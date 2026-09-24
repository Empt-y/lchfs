//! The control channel of a running mount: a Unix socket at
//! `<primary root>/control.sock`, one newline-delimited JSON request per
//! connection, one JSON reply. It lives here and not in `lchfs-store`
//! because the store is transport-free by design (ARCHITECTURE.md §5a);
//! every command is one call on `Pool`'s public API. §14.3 declined ioctl
//! for the same reasons this is a socket: nothing about it belongs in the
//! filesystem's data path.

use lchfs_store::{Pool, VdevHealth};
use serde_json::{Value, json};
use lchfs_crypto::locked::LockedBytes;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub const SOCKET_NAME: &str = "control.sock";

/// The reply code for a key the pool did not accept.
pub const KEY_REFUSED: &str = "key-refused";

/// Where a mounted pool's socket is: in its primary's root.
pub fn socket_path(pool: &Pool) -> PathBuf {
    let primary = pool.primary_vdev();
    let root = pool
        .vdev_status()
        .into_iter()
        .find(|s| s.id == primary)
        .and_then(|s| s.root)
        .expect("the primary is online and has a root");
    root.join(SOCKET_NAME)
}

/// A running control listener. Dropping it stops the thread and removes
/// the socket.
pub struct ControlServer {
    stop: Arc<AtomicBool>,
    path: PathBuf,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ControlServer {
    /// Binds the socket and serves requests against `pool` until dropped.
    /// A socket file left by a mount that died is replaced, once a
    /// connection to it has been refused -- a live mount's socket is not.
    pub fn start(pool: Arc<Pool>, path: PathBuf) -> anyhow::Result<Self> {
        if path.exists() {
            if UnixStream::connect(&path).is_ok() {
                anyhow::bail!("{} is in use: is the pool already mounted?", path.display());
            }
            std::fs::remove_file(&path)?;
        }
        let listener = UnixListener::bind(&path)?;
        // Owner only. The peer check in `serve_one` is what enforces it --
        // this just keeps the socket from being offered to anyone else.
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("lchfs-control".into())
            .spawn(move || {
                while !thread_stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            if let Err(e) = serve_one(&pool, stream) {
                                tracing::warn!("control: {e}");
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(50));
                        }
                        Err(e) => {
                            tracing::warn!("control: accept failed: {e}");
                            std::thread::sleep(Duration::from_millis(200));
                        }
                    }
                }
            })?;
        Ok(Self {
            stop,
            path,
            thread: Some(thread),
        })
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Only the mount's own user, or root, may drive it: a detach or an
/// offline is destructive, and a key change grants access.
fn peer_allowed(stream: &UnixStream) -> anyhow::Result<bool> {
    let cred = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)?;
    Ok(cred.uid() == 0 || cred.uid() == nix::unistd::geteuid().as_raw())
}

fn serve_one(pool: &Pool, mut stream: UnixStream) -> anyhow::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    if !peer_allowed(&stream)? {
        writeln!(stream, "{}", json!({ "ok": false, "error": "permission denied: not the mount's user" }))?;
        return Ok(());
    }
    // The request may carry a passphrase or an identity: it is read into
    // locked memory, and every string parsed out of it is zeroed after.
    let line = read_line_locked(&stream)?;
    if line.is_empty() {
        // A connection closed without a request: `is_live` probing.
        return Ok(());
    }
    let reply = match serde_json::from_slice::<Value>(&line).map(SecretJson) {
        Ok(request) => match handle(pool, &request) {
            Ok(result) => json!({ "ok": true, "result": result }),
            Err(e) => {
                // A refused key is its own code, so a client can ask again
                // rather than give up.
                let refused = e.downcast_ref::<lchfs_store::PoolError>().is_some_and(crate::unlock::refused);
                if refused {
                    json!({ "ok": false, "error": e.to_string(), "code": KEY_REFUSED })
                } else {
                    json!({ "ok": false, "error": e.to_string() })
                }
            }
        },
        Err(e) => json!({ "ok": false, "error": format!("bad request: {e}") }),
    };
    // A scrub or resilver can run for a long time; the client waits.
    stream.set_write_timeout(None)?;
    writeln!(stream, "{reply}")?;
    Ok(())
}

fn arg<'a>(request: &'a Value, name: &str) -> anyhow::Result<&'a Value> {
    request
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("missing argument {name:?}"))
}

fn health_name(h: VdevHealth) -> &'static str {
    match h {
        VdevHealth::Online => "online",
        VdevHealth::CatchingUp => "catching-up",
        VdevHealth::Faulted => "FAULTED",
        VdevHealth::Absent => "absent",
    }
}

fn stripe_policy_json(pool: &Pool) -> Value {
    let p = pool.stripe_policy();
    json!({
        "k": p.k,
        "m": p.m,
        "min_age_segments": p.min_age_segments,
        "enabled": p.enabled(),
    })
}

/// What a mount can say about its encryption without disclosing a key.
fn encryption_json(pool: &Pool) -> Value {
    let conversion = pool.conversion_status();
    match pool.keyring_config() {
        None => json!({ "encrypted": false }),
        Some(config) => json!({
            "progress": conversion.progress,
            "encrypted": true,
            "keyring_generation": pool.keyring_generation(),
            "padding": format!("{:?}", config.padding),
            "current_epoch": config.current_epoch,
            "min_epoch": config.min_epoch,
            "conversion": config.conversion.map(|c| json!({
                "target_epoch": c.target_epoch,
                "phase": format!("{:?}", c.phase),
            })),
            "slots": pool.keyring_slots(),
        }),
    }
}

fn resilver_json(r: &lchfs_store::ResilverReport) -> Value {
    json!({
        "examined": r.examined,
        "missing": r.missing,
        "healed": r.healed,
        "unrecoverable": r.unrecoverable.len(),
        "shards_rebuilt": r.shards_rebuilt,
    })
}

/// Every command, and what it maps to on `Pool`.
pub fn handle(pool: &Pool, request: &Value) -> anyhow::Result<Value> {
    let cmd = arg(request, "cmd")?
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("cmd must be a string"))?;
    match cmd {
        "status" => {
            let primary = pool.primary_vdev();
            let stats = pool.repair_stats();
            let vdevs: Vec<Value> = pool
                .vdev_status()
                .iter()
                .map(|s| {
                    json!({
                        "id": s.id,
                        "health": health_name(s.health),
                        "root": s.root.as_ref().map(|r| r.display().to_string()),
                        "primary": s.id == primary,
                    })
                })
                .collect();
            // A faulted primary is promoted away within a second; a remount
            // is only required if there is nothing left to promote.
            let remount_required = pool.primary_faulted() && pool.vdev_status().iter().all(|s| s.health != VdevHealth::Online);
            Ok(json!({
                "pool_uuid": lchfs_format::pool_uuid_hex(&pool.pool_uuid()),
                "primary": primary,
                "degraded": pool.is_degraded(),
                "primary_faulted": pool.primary_faulted(),
                "remount_required": remount_required,
                "vdevs": vdevs,
                "missing": pool.missing_vdevs(),
                "faulted": pool.faulted_vdevs(),
                "repair": {
                    "failovers": stats.failovers,
                    "heals": stats.heals,
                    "heal_failures": stats.heal_failures,
                    "promotions": stats.promotions,
                    "corruption_events": pool.corruption_events().len(),
                },
                "encryption": encryption_json(pool),
                "mount_resilver": pool
                    .mount_resilver()
                    .iter()
                    .map(|(id, r)| json!({ "vdev": id, "report": resilver_json(r) }))
                    .collect::<Vec<_>>(),
            }))
        }
        "scrub" => {
            let reports = pool.scrub()?;
            Ok(json!(reports
                .iter()
                .map(|r| json!({
                    "vdev": r.vdev_id,
                    "verified": r.verified,
                    "corrupt": r.corrupt,
                    "healed": r.healed,
                    "unrecoverable": r.unrecoverable.len(),
                    "shards_verified": r.shards_verified,
                    "shards_corrupt": r.shards_corrupt,
                    "shards_rebuilt": r.shards_rebuilt,
                }))
                .collect::<Vec<_>>()))
        }
        "resilver" => {
            let id = arg(request, "vdev")?
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("vdev must be a number"))? as u16;
            Ok(resilver_json(&pool.resilver(id)?))
        }
        "attach" => {
            let path = path_arg(request)?;
            let (id, report) = pool.attach_vdev_live(&path)?;
            Ok(json!({ "vdev": id, "report": resilver_json(&report) }))
        }
        "online" => {
            let path = path_arg(request)?;
            let (id, report) = pool.online_vdev(&path)?;
            Ok(json!({ "vdev": id, "report": resilver_json(&report) }))
        }
        "offline" => {
            let id = arg(request, "vdev")?
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("vdev must be a number"))? as u16;
            pool.offline_vdev(id)?;
            Ok(json!({ "vdev": id, "health": "FAULTED" }))
        }
        "corruption" => {
            let events = pool.corruption_events();
            let clear = request.get("clear").and_then(Value::as_bool).unwrap_or(false);
            if clear {
                pool.clear_corruption_events();
            }
            Ok(json!(events
                .iter()
                .map(|e| json!({
                    "at": e.at.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
                    "vdev": e.vdev_id,
                    "stream": format!("{:?}", e.stream).to_lowercase(),
                    "hash": format!("{:?}", e.hash),
                    "segment": e.location.map(|l| l.segment_id),
                    "offset": e.location.map(|l| l.offset),
                    "ino": e.ino,
                    "detail": e.detail,
                    "healed": e.healed,
                }))
                .collect::<Vec<_>>()))
        }
        "promote" => Ok(json!({ "primary": pool.promote_primary()? })),
        "detach" => Ok(json!({ "detached": pool.detach_vdev_live()? })),
        "set-stripe" => {
            let small = |name: &str| -> anyhow::Result<u8> {
                let v = arg(request, name)?
                    .as_u64()
                    .ok_or_else(|| anyhow::anyhow!("{name} must be a number"))?;
                u8::try_from(v).map_err(|_| anyhow::anyhow!("{name} must be at most 255"))
            };
            let (k, m) = (small("k")?, small("m")?);
            let min_age = match request.get("min_age_segments") {
                None | Some(Value::Null) => None,
                Some(v) => Some(
                    v.as_u64()
                        .and_then(|a| u32::try_from(a).ok())
                        .ok_or_else(|| anyhow::anyhow!("min_age_segments must be a number"))?,
                ),
            };
            pool.set_stripe_policy(k, m, min_age)?;
            Ok(stripe_policy_json(pool))
        }
        "stripe-status" => {
            let s = pool.stripe_status();
            Ok(json!({
                "policy": stripe_policy_json(pool),
                "online_vdevs": s.online_vdevs,
                "enough_devices": s.k as u16 + s.m as u16 <= s.online_vdevs,
                "striped_segments": s.striped_segments,
                "segments_missing_shards": s.segments_missing_shards,
                "unreadable_segments": s.unreadable_segments,
                "logical_bytes": s.logical_bytes,
                "shard_bytes": s.shard_bytes,
                "shard_bytes_by_vdev": s.shard_bytes_by_vdev
                    .iter()
                    .map(|(id, b)| json!({ "vdev": id, "bytes": b }))
                    .collect::<Vec<_>>(),
                "mirrored_cost_bytes": s.mirrored_cost_bytes,
                "saved_bytes": s.mirrored_cost_bytes.saturating_sub(s.shard_bytes),
            }))
        }
        "encryption-status" => Ok(encryption_json(pool)),
        "start-encrypt" => {
            let specs = arg(request, "slots")?
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("slots must be an array"))?
                .iter()
                .map(crate::keyops::NewSlotSpec::from_json)
                .collect::<anyhow::Result<Vec<_>>>()?;
            let padding = if request.get("no_padding").and_then(Value::as_bool) == Some(true) {
                lchfs_crypto::keyring::Padding::None
            } else {
                lchfs_crypto::keyring::Padding::Padme
            };
            pool.start_encrypt(lchfs_store::EncryptionSetup {
                padding,
                slots: specs.iter().map(|s| s.as_new_slot()).collect(),
            })?;
            Ok(encryption_json(pool))
        }
        "start-rekey" => {
            let proof = crate::unlock::Credential::from_json(arg(request, "proof")?)?;
            pool.verify_key(&proof.as_unlock())?;
            let epoch = pool.start_rekey()?;
            Ok(json!({ "target_epoch": epoch }))
        }
        "set-conversion-rate" => {
            pool.set_conversion_rate(request.get("bytes_per_sec").and_then(Value::as_u64));
            Ok(json!({}))
        }
        "key-list" => Ok(json!({
            "generation": pool.keyring_generation(),
            "slots": pool.keyring_slots(),
        })),
        "key-op" => {
            let proof = crate::unlock::Credential::from_json(arg(request, "proof")?)?;
            let op = crate::keyops::KeyOp::from_json(arg(request, "op")?)?;
            let (result, unwritten) = pool.update_keyring(&proof.as_unlock(), |ring| op.apply(ring))?;
            Ok(json!({
                "result": result,
                "generation": pool.keyring_generation(),
                "unwritten": unwritten
                    .iter()
                    .map(|(root, e)| json!({ "root": root.display().to_string(), "error": e.to_string() }))
                    .collect::<Vec<_>>(),
            }))
        }
        other => anyhow::bail!("unknown command {other:?}"),
    }
}

fn path_arg(request: &Value) -> anyhow::Result<PathBuf> {
    let path = arg(request, "path")?
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("path must be a string"))?;
    // The mount's working directory is not the caller's; only an absolute
    // path means the same thing on both sides.
    let path = Path::new(path);
    if !path.is_absolute() {
        anyhow::bail!("path must be absolute");
    }
    Ok(path.to_path_buf())
}

/// A JSON value that may carry secrets -- hex passphrases and PINs, an
/// identity's text. JSON strings cannot live in locked memory, so this is
/// the next best thing: every string in the tree is zeroed when it drops.
pub struct SecretJson(pub Value);

impl std::ops::Deref for SecretJson {
    type Target = Value;
    fn deref(&self) -> &Value {
        &self.0
    }
}

impl serde::Serialize for SecretJson {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}

impl Drop for SecretJson {
    fn drop(&mut self) {
        scrub(&mut self.0);
    }
}

/// Zeroes every string (and object key) in `v`.
pub fn scrub(v: &mut Value) {
    use zeroize::Zeroize;
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(scrub),
        Value::Object(map) => {
            for (_, item) in map.iter_mut() {
                scrub(item);
            }
            // Keys are names, never secrets; values are what matter.
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Reads one `\n`-terminated line byte by byte into locked memory -- no
/// `BufReader` holding a copy in its own buffer, no `String` reallocating.
fn read_line_locked(mut stream: &UnixStream) -> anyhow::Result<LockedBytes> {
    use std::io::Read;
    let mut line = LockedBytes::with_capacity(LockedBytes::MAX);
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => line.push(byte[0]).map_err(|e| anyhow::anyhow!("request: {e}"))?,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    zeroize::Zeroize::zeroize(&mut byte);
    Ok(line)
}

/// `io::Write` into a `LockedBytes`, for serializing a request that may
/// carry secrets without passing it through a growing `String`.
struct LockedWriter(LockedBytes);

impl Write for LockedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.try_extend_from_slice(buf).map_err(std::io::Error::other)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Sends one request and returns the whole reply, `ok` or not.
pub fn request_raw(socket: &Path, request: &Value) -> anyhow::Result<Value> {
    let mut stream = UnixStream::connect(socket)
        .map_err(|e| anyhow::anyhow!("cannot reach {} ({e}); is the pool mounted?", socket.display()))?;
    let mut out = LockedWriter(LockedBytes::with_capacity(LockedBytes::MAX));
    serde_json::to_writer(&mut out, request)?;
    out.write_all(b"\n")?;
    stream.write_all(&out.0)?;
    let mut line = String::new();
    BufReader::new(&stream).read_line(&mut line)?;
    Ok(serde_json::from_str(&line)?)
}

/// True when a mount is serving `socket` right now.
pub fn is_live(socket: &Path) -> bool {
    UnixStream::connect(socket).is_ok()
}

/// Sends one request to the socket at `socket` and returns the reply's
/// `result`, or the error the mount reported.
pub fn request(socket: &Path, request: &Value) -> anyhow::Result<Value> {
    let reply = request_raw(socket, request)?;
    if reply.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(reply.get("result").cloned().unwrap_or(Value::Null))
    } else {
        anyhow::bail!(
            "{}",
            reply.get("error").and_then(Value::as_str).unwrap_or("unknown error")
        )
    }
}
