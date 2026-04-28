//! Python sidecar lifecycle management.
//!
//! The sidecar is bundled as an external binary
//! (`guardiabox-sidecar-<triple>[.exe]`) declared in
//! `tauri.conf.json > bundle.externalBin`. Tauri copies it next to
//! the shell at packaging time; at runtime we spawn it, read the
//! first stdout line for the handshake (`GUARDIABOX_SIDECAR=<port>
//! <token>`), stash `(port, token)` in a shared state, and expose
//! a `get_sidecar_connection` Tauri command so the React frontend
//! can fetch them.
//!
//! Anti-oracle preservation (ADR-0016 sec C): the parser refuses
//! handshake lines that do not match the strict prefix + format.
//! Subsequent stdout lines (structlog JSON records) are forwarded
//! to the tracing layer so the shell window keeps a debug trail
//! without the renderer ever seeing them.

use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Manager, State};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tracing::{error, info};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

/// Windows CreateProcess flag: do not open a console window for the
/// child. Required because the sidecar binary is built as a "Console
/// Subsystem" PE -- without --noconsole at PyInstaller time we keep
/// stdout/stderr pipes alive (needed for the handshake) but Windows
/// would otherwise pop a stray cmd window every launch.
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

const HANDSHAKE_PREFIX: &str = "GUARDIABOX_SIDECAR=";
const SIDECAR_BIN_PREFIX: &str = "binaries/guardiabox-sidecar";
const HANDSHAKE_TIMEOUT_SECS: u64 = 10;

/// Per-launch sidecar identity bytes -- forwarded to the React frontend
/// via the `get_sidecar_connection` Tauri command.
#[derive(Clone, Debug, Serialize)]
pub struct SidecarConnection {
    pub port: u16,
    pub token: String,
}

/// Shared state slot. `None` until the spawn handshake completes.
#[derive(Default)]
pub struct SidecarState(pub Arc<Mutex<Option<SidecarConnection>>>);

/// Spawn the sidecar binary, parse its handshake, attach the result
/// to the Tauri app state.
pub async fn start(app: AppHandle) -> Result<()> {
    let bin_path = resolve_binary_path(&app)?;
    info!(path = %bin_path.display(), "spawning sidecar");

    let mut cmd = Command::new(&bin_path);
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);

    #[cfg(target_os = "windows")]
    {
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child: Child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn {}", bin_path.display()))?;

    // Drain stderr immediately. If we leave it piped without reading,
    // uvicorn's stderr buffer fills up after ~64 KiB and the worker
    // thread blocks on write -- the sidecar then never emits its
    // handshake on stdout, and we time out. Forwarding to our tracing
    // layer also surfaces Python tracebacks during dev.
    if let Some(stderr) = child.stderr.take() {
        let mut err_reader = BufReader::new(stderr).lines();
        tokio::spawn(async move {
            while let Ok(Some(line)) = err_reader.next_line().await {
                info!(target: "sidecar.stderr", "{}", line);
            }
        });
    }

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("sidecar stdout pipe missing"))?;
    let mut reader = BufReader::new(stdout).lines();

    let first_line = tokio::time::timeout(
        std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
        reader.next_line(),
    )
    .await
    .map_err(|_| anyhow!("sidecar handshake timeout"))?
    .context("error reading sidecar stdout")?
    .ok_or_else(|| anyhow!("sidecar exited before sending handshake"))?;

    let conn = parse_handshake(&first_line)
        .with_context(|| format!("bad sidecar handshake: {first_line:?}"))?;
    info!(port = conn.port, "sidecar handshake parsed");

    // Persist the connection in app state so the renderer can fetch it.
    app.manage(SidecarState(Arc::new(Mutex::new(Some(conn.clone())))));

    // Drain remaining stdout to the shell tracing layer.
    tokio::spawn(async move {
        while let Ok(Some(line)) = reader.next_line().await {
            info!(target: "sidecar.stdout", "{}", line);
        }
        // When the sidecar's stdout closes, log it loudly -- the shell
        // can decide whether to surface a "sidecar lost" toast.
        error!("sidecar stdout closed");
    });
    Ok(())
}

fn resolve_binary_path(app: &AppHandle) -> Result<std::path::PathBuf> {
    let triple = current_target_triple();
    let ext = if cfg!(target_os = "windows") {
        ".exe"
    } else {
        ""
    };
    // SIDECAR_BIN_PREFIX includes the `binaries/` prefix needed by the
    // tauri.conf.json `externalBin` declaration, but at runtime we
    // resolve plain filenames (no leading dir) because Tauri places
    // the sidecar next to the .exe in both `cargo build --release`
    // and the bundled installer.
    let bin_name = std::path::Path::new(SIDECAR_BIN_PREFIX)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("guardiabox-sidecar");
    // Tauri 2 *strips* the platform-triple from `externalBin` entries
    // when bundling -- the binary that lives next to the .exe at
    // runtime is `guardiabox-sidecar.exe`, not the original
    // `guardiabox-sidecar-x86_64-pc-windows-msvc.exe`. Search both
    // forms so the same code works in dev, in `cargo build --release`
    // (no bundling), and in the bundled installer.
    let stripped = format!("{bin_name}{ext}");
    let with_triple = format!("{bin_name}-{triple}{ext}");

    let resource_dir = app
        .path()
        .resource_dir()
        .context("resource_dir unavailable")?;
    for candidate in [
        resource_dir.join(&stripped),
        resource_dir.join(&with_triple),
    ] {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    // Tauri also exposes the executable's parent dir; useful when
    // resource_dir() points to the install dir but the sidecar was
    // copied next to the .exe by `cargo build` (non-bundled release).
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            for candidate in [exe_dir.join(&stripped), exe_dir.join(&with_triple)] {
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }
        }
    }
    // Dev fallback: `cargo tauri dev` runs from src-tauri/.
    let dev = std::env::current_dir()
        .context("no current dir")?
        .join("binaries")
        .join(&with_triple);
    if dev.is_file() {
        return Ok(dev);
    }
    Err(anyhow!(
        "sidecar binary {stripped} (or {with_triple}) not found near the executable, in resource dir, or in dev fallback"
    ))
}

fn current_target_triple() -> &'static str {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        "x86_64-pc-windows-msvc"
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        "aarch64-apple-darwin"
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        "x86_64-apple-darwin"
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        "x86_64-unknown-linux-gnu"
    }
}

/// Parse a single handshake line of the form
/// `GUARDIABOX_SIDECAR=<port> <token>`. Token must be non-empty;
/// port must fit in u16.
pub fn parse_handshake(line: &str) -> Result<SidecarConnection> {
    let rest = line
        .strip_prefix(HANDSHAKE_PREFIX)
        .ok_or_else(|| anyhow!("missing handshake prefix"))?;
    let (port_str, token) = rest
        .split_once(' ')
        .ok_or_else(|| anyhow!("missing handshake separator"))?;
    let port: u16 = port_str
        .parse()
        .with_context(|| format!("port not a u16: {port_str:?}"))?;
    if port == 0 {
        return Err(anyhow!("port must be non-zero"));
    }
    if token.is_empty() {
        return Err(anyhow!("token must be non-empty"));
    }
    Ok(SidecarConnection {
        port,
        token: token.to_string(),
    })
}

/// Tauri command exposed to the React frontend. Returns `None` if
/// the spawn handshake has not yet completed (renderer should retry
/// after `/healthz` succeeds).
#[tauri::command]
pub fn get_sidecar_connection(state: State<'_, SidecarState>) -> Option<SidecarConnection> {
    state.0.lock().ok().and_then(|guard| guard.clone())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::parse_handshake;

    #[test]
    fn parse_handshake_valid() {
        let conn = parse_handshake("GUARDIABOX_SIDECAR=51234 abc-token-43-chars-long").unwrap();
        assert_eq!(conn.port, 51234);
        assert_eq!(conn.token, "abc-token-43-chars-long");
    }

    #[test]
    fn parse_handshake_rejects_wrong_prefix() {
        assert!(parse_handshake("GUARDIABOX_TOKEN=51234 abc").is_err());
    }

    #[test]
    fn parse_handshake_rejects_zero_port() {
        assert!(parse_handshake("GUARDIABOX_SIDECAR=0 abc").is_err());
    }

    #[test]
    fn parse_handshake_rejects_empty_token() {
        assert!(parse_handshake("GUARDIABOX_SIDECAR=51234 ").is_err());
    }

    #[test]
    fn parse_handshake_rejects_non_u16_port() {
        assert!(parse_handshake("GUARDIABOX_SIDECAR=99999999 abc").is_err());
    }

    #[test]
    fn parse_handshake_rejects_missing_separator() {
        assert!(parse_handshake("GUARDIABOX_SIDECAR=51234").is_err());
    }
}
