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

    let mut child: Child = Command::new(&bin_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("failed to spawn {}", bin_path.display()))?;

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

    let conn = parse_handshake(&first_line).with_context(|| {
        format!("bad sidecar handshake: {first_line:?}")
    })?;
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
    let ext = if cfg!(target_os = "windows") { ".exe" } else { "" };
    let filename = format!("{SIDECAR_BIN_PREFIX}-{triple}{ext}");

    // Tauri places externalBin entries next to the shell at runtime;
    // resource_dir() returns that path on bundled builds. In dev mode
    // we fall back to the in-tree binaries/ directory.
    let resource = app
        .path()
        .resource_dir()
        .context("resource_dir unavailable")?
        .join(&filename);
    if resource.is_file() {
        return Ok(resource);
    }
    // Dev fallback: `cargo tauri dev` runs from src-tauri/.
    let dev = std::env::current_dir()
        .context("no current dir")?
        .join("binaries")
        .join(&filename);
    if dev.is_file() {
        return Ok(dev);
    }
    Err(anyhow!(
        "sidecar binary {filename} not found in resource dir or dev fallback"
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
