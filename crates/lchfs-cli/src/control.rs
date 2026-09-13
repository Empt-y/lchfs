//! The control channel of a running mount: a Unix socket at
//! `<primary root>/control.sock`, one newline-delimited JSON request per
//! connection, one JSON reply. It lives here and not in `lchfs-store`
//! because the store is transport-free by design (ARCHITECTURE.md §5a);
//! every command is one call on `Pool`'s public API. §14.3 declined ioctl
//! for the same reasons this is a socket: nothing about it belongs in the
//! filesystem's data path.

use lchfs_store::{Pool, VdevHealth};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub const SOCKET_NAME: &str = "control.sock";

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

fn serve_one(pool: &Pool, mut stream: UnixStream) -> anyhow::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut line = String::new();
    BufReader::new(&stream).read_line(&mut line)?;
    let reply = match serde_json::from_str::<Value>(&line) {
        Ok(request) => match handle(pool, &request) {
            Ok(result) => json!({ "ok": true, "result": result }),
            Err(e) => json!({ "ok": false, "error": e.to_string() }),
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

fn resilver_json(r: &lchfs_store::ResilverReport) -> Value {
    json!({
        "examined": r.examined,
        "missing": r.missing,
        "healed": r.healed,
        "unrecoverable": r.unrecoverable.len(),
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
            let primary_faulted = pool.faulted_vdevs().contains(&primary);
            Ok(json!({
                "pool_uuid": lchfs_format::pool_uuid_hex(&pool.pool_uuid()),
                "primary": primary,
                "degraded": pool.is_degraded(),
                "remount_required": primary_faulted,
                "vdevs": vdevs,
                "missing": pool.missing_vdevs(),
                "faulted": pool.faulted_vdevs(),
                "repair": {
                    "failovers": stats.failovers,
                    "heals": stats.heals,
                    "heal_failures": stats.heal_failures,
                },
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

/// Sends one request to the socket at `socket` and returns the reply's
/// `result`, or the error the mount reported.
pub fn request(socket: &Path, request: &Value) -> anyhow::Result<Value> {
    let mut stream = UnixStream::connect(socket)
        .map_err(|e| anyhow::anyhow!("cannot reach {} ({e}); is the pool mounted?", socket.display()))?;
    writeln!(stream, "{request}")?;
    let mut line = String::new();
    BufReader::new(&stream).read_line(&mut line)?;
    let reply: Value = serde_json::from_str(&line)?;
    if reply.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(reply.get("result").cloned().unwrap_or(Value::Null))
    } else {
        anyhow::bail!(
            "{}",
            reply.get("error").and_then(Value::as_str).unwrap_or("unknown error")
        )
    }
}
