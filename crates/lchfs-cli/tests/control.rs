//! The control channel end to end: a pool opened in-process, the listener
//! started on it, and every command driven over the socket the way the
//! CLI does.

use lchfs_cli::control::{ControlServer, request, socket_path};
use lchfs_format::PoolParams;
use lchfs_store::Pool;
use serde_json::json;
use std::sync::Arc;

fn small_params() -> PoolParams {
    PoolParams {
        data_segment_cap_bytes: 64 * 1024,
        meta_segment_cap_bytes: 64 * 1024,
        chunk_avg_size: 1024,
        chunk_min_size: 256,
        chunk_max_size: 4096,
        inline_threshold: 64,
        logical_shard_count: 1,
        stripe_k: 0,
        stripe_m: 0,
        stripe_min_age_segments: 8,
    }
}

#[test]
fn every_command_round_trips_over_the_socket() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let pool = Arc::new(Pool::create(a.path(), small_params()).unwrap());
    let ino = pool.create_file(1, "f", 0o644).unwrap();
    pool.write(ino, 0, &vec![7u8; 20_000]).unwrap();
    pool.checkpoint().unwrap();

    let sock = socket_path(&pool);
    assert_eq!(sock, lchfs_cli::control::socket_for_device(a.path()).unwrap());
    assert!(sock.to_string_lossy().ends_with(&format!("{}.sock", lchfs_format::pool_uuid_hex(&pool.pool_uuid()))));
    let server = ControlServer::start(Arc::clone(&pool), sock.clone()).unwrap();
    assert!(sock.exists());

    let status = request(&sock, &json!({ "cmd": "status" })).unwrap();
    assert_eq!(status["primary"], 0);
    assert_eq!(status["degraded"], false);
    assert_eq!(status["vdevs"].as_array().unwrap().len(), 1);
    assert_eq!(status["vdevs"][0]["health"], "online");

    // Attach a device live, over the socket.
    let attached = request(&sock, &json!({ "cmd": "attach", "path": b.path() })).unwrap();
    assert_eq!(attached["vdev"], 1);
    assert!(attached["report"]["healed"].as_u64().unwrap() > 0);
    let status = request(&sock, &json!({ "cmd": "status" })).unwrap();
    assert_eq!(status["vdevs"].as_array().unwrap().len(), 2);

    // Scrub and resilver report.
    let scrub = request(&sock, &json!({ "cmd": "scrub" })).unwrap();
    assert_eq!(scrub.as_array().unwrap().len(), 2);
    assert_eq!(scrub[1]["corrupt"], 0);
    let resilver = request(&sock, &json!({ "cmd": "resilver", "vdev": 1 })).unwrap();
    assert_eq!(resilver["missing"], 0);

    // Offline, then back online.
    request(&sock, &json!({ "cmd": "offline", "vdev": 1 })).unwrap();
    let status = request(&sock, &json!({ "cmd": "status" })).unwrap();
    assert_eq!(status["vdevs"][1]["health"], "FAULTED");
    assert_eq!(status["degraded"], true);
    let err = request(&sock, &json!({ "cmd": "offline", "vdev": 0 })).unwrap_err().to_string();
    assert!(err.contains("primary"), "{err}");
    let online = request(&sock, &json!({ "cmd": "online", "path": b.path() })).unwrap();
    assert_eq!(online["vdev"], 1);
    let status = request(&sock, &json!({ "cmd": "status" })).unwrap();
    assert_eq!(status["vdevs"][1]["health"], "online");

    let corruption = request(&sock, &json!({ "cmd": "corruption" })).unwrap();
    assert_eq!(corruption.as_array().unwrap().len(), 0);
    assert_eq!(status["repair"]["corruption_events"], 0);

    // Bad requests are errors, not disconnects.
    let err = request(&sock, &json!({ "cmd": "dance" })).unwrap_err().to_string();
    assert!(err.contains("unknown command"), "{err}");
    let err = request(&sock, &json!({ "cmd": "attach", "path": "relative" })).unwrap_err().to_string();
    assert!(err.contains("absolute"), "{err}");

    drop(server);
    assert!(!sock.exists(), "the socket should be removed on shutdown");
    assert!(request(&sock, &json!({ "cmd": "status" })).is_err());
}

/// A socket left behind by a mount that died is replaced; one that a
/// live mount answers on is not.
#[test]
fn the_stripe_policy_is_set_and_reported_over_the_socket() {
    let a = tempfile::tempdir().unwrap();
    let pool = Arc::new(Pool::create(a.path(), small_params()).unwrap());
    let sock = socket_path(&pool);
    let _server = ControlServer::start(Arc::clone(&pool), sock.clone()).unwrap();

    let status = request(&sock, &json!({ "cmd": "stripe-status" })).unwrap();
    assert_eq!(status["policy"]["enabled"], false);
    assert_eq!(status["striped_segments"], 0);
    assert_eq!(status["online_vdevs"], 1);

    let err = request(&sock, &json!({ "cmd": "set-stripe", "k": 1, "m": 1 })).unwrap_err().to_string();
    assert!(err.contains("stripe policy"), "{err}");
    let set = request(&sock, &json!({ "cmd": "set-stripe", "k": 2, "m": 1, "min_age_segments": 3 })).unwrap();
    assert_eq!(set["k"], 2);
    assert_eq!(set["m"], 1);
    assert_eq!(set["min_age_segments"], 3);
    assert_eq!(set["enabled"], true);
    let status = request(&sock, &json!({ "cmd": "stripe-status" })).unwrap();
    assert_eq!(status["policy"]["k"], 2);
    assert_eq!(status["enough_devices"], false, "one device cannot hold a 2+1 stripe");
    assert_eq!(pool.stripe_policy().k, 2);
}

#[test]
fn a_stale_socket_is_replaced_but_a_live_one_is_not() {
    let a = tempfile::tempdir().unwrap();
    let pool = Arc::new(Pool::create(a.path(), small_params()).unwrap());
    let sock = socket_path(&pool);
    std::fs::create_dir_all(sock.parent().unwrap()).unwrap();
    std::fs::write(&sock, b"stale").unwrap();
    let server = ControlServer::start(Arc::clone(&pool), sock.clone()).unwrap();
    assert!(request(&sock, &json!({ "cmd": "status" })).is_ok());
    let err = match ControlServer::start(Arc::clone(&pool), sock.clone()) {
        Ok(_) => panic!("a second listener must not replace a live socket"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("in use"), "{err}");
    drop(server);
}
