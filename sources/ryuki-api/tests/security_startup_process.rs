use std::io::Write;
use std::net::TcpListener;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

const BINARY: &str = env!("CARGO_BIN_EXE_ryuki-api");
const CHILD_TIMEOUT: Duration = Duration::from_secs(10);

fn wait_with_output_bounded(mut child: Child, context: &str) -> Output {
    let deadline = Instant::now() + CHILD_TIMEOUT;

    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                return child
                    .wait_with_output()
                    .unwrap_or_else(|error| panic!("failed to collect {context} output: {error}"));
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let kill_error = child.kill().err();
                let output = child.wait_with_output().unwrap_or_else(|error| {
                    panic!("failed to reap timed-out {context} child: {error}")
                });
                panic!(
                    "{context} exceeded {CHILD_TIMEOUT:?}; kill error: {kill_error:?}; stderr: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("failed to poll {context} child: {error}");
            }
        }
    }
}

fn run_bounded(command: &mut Command, context: &str) -> Output {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let child = command
        .spawn()
        .unwrap_or_else(|error| panic!("failed to spawn {context}: {error}"));
    wait_with_output_bounded(child, context)
}

#[test]
fn security_admission_precedes_apply_only_database_configuration() {
    let database_observer = TcpListener::bind("127.0.0.1:0").expect("database observer");
    database_observer
        .set_nonblocking(true)
        .expect("nonblocking database observer");
    let database_address = database_observer.local_addr().expect("observer address");

    let output = run_bounded(
        Command::new(BINARY)
            .env_clear()
            .env("RYUKI_MIGRATION_MODE", "apply-only")
            .env(
                "RYUKI_MIGRATION_DATABASE_URL",
                format!("postgresql://migrator:unused@{database_address}/ryuki"),
            ),
        "apply-only security admission",
    );

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("stderr must be UTF-8");
    assert!(
        stderr.contains("RYUKI_SECURITY_CONTRACT_ROOT"),
        "security admission must fail first: {stderr}"
    );
    assert!(!stderr.contains("migration apply-only process failed"));
    assert!(!stderr.contains("embedded migrations applied"));
    match database_observer.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok((_, peer)) => panic!("security failure still opened a database connection from {peer}"),
        Err(error) => panic!("failed to inspect database observer: {error}"),
    }
}

#[test]
fn security_admission_precedes_key_workers_router_and_listener() {
    let temp = TempDir::new().expect("temporary directory");
    let key_path = temp.path().join("must-not-be-created.key");

    let output = run_bounded(
        Command::new(BINARY)
            .env_clear()
            .env("RYUKI_MIGRATION_MODE", "local-auto")
            .env("RYUKI_CP_SIGNING_KEY_PATH", &key_path),
        "normal startup security admission",
    );

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("stderr must be UTF-8");
    assert!(stderr.contains("RYUKI_SECURITY_CONTRACT_ROOT"));
    assert!(
        !key_path.exists(),
        "preflight failure created a signing key"
    );
    for forbidden in [
        "sweep started",
        "scheduler started",
        "router",
        "failed to bind",
        "ryuki-api listening",
    ] {
        assert!(
            !stderr.contains(forbidden),
            "preflight failure reached a later startup phase ({forbidden}): {stderr}"
        );
    }
}

#[test]
fn route_metadata_maintenance_mode_remains_configuration_free() {
    let mut child = Command::new(BINARY)
        .arg("--dump-route-meta")
        .env_clear()
        .env("RYUKI_SERVER__BIND_ADDRESS", "not-a-socket-address")
        .env("RYUKI_DATABASE__REQUIRED", "not-a-boolean")
        .env("RYUKI_MIGRATION_MODE", "not-a-migration-mode")
        .env("RYUKI_SECURITY_CONTRACT_ROOT", "relative/root")
        .env(
            "RYUKI_DEPLOYMENT_SECURITY_PROFILE_PATH",
            "../outside-root.json",
        )
        .env(
            "RYUKI_DEPLOYMENT_SECURITY_PROFILE_DIGEST",
            "not-a-sha256-digest",
        )
        .env("RYUKI_EXPECTED_DEPLOYMENT_ID", "NOT_CANONICAL")
        .env("RYUKI_SECURITY_PROFILE", "not-a-security-profile")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("ryuki-api should execute");
    child
        .stdin
        .take()
        .expect("stdin pipe")
        .write_all(b"[]")
        .expect("write route inventory");

    let output = wait_with_output_bounded(child, "route metadata maintenance mode");
    assert!(
        output.status.success(),
        "maintenance mode failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("route metadata JSON");
    assert_eq!(value["meta"], serde_json::json!([]));
    assert!(value["openapi"].is_object());
}
