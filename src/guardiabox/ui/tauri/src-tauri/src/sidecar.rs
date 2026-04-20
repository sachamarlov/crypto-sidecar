//! Python sidecar lifecycle management.
//!
//! The sidecar is bundled as an external binary (`guardiabox-sidecar[.exe]`)
//! via `tauri.conf.json > bundle.externalBin`. We spawn it, read the first
//! stdout line to grab the per-launch session token, and stash it in the
//! global state so Tauri commands can forward it to the React frontend.
//!
//! Implementation stubbed — to be fleshed out by spec 000-tauri-sidecar.

use anyhow::{anyhow, Result};
use tauri::AppHandle;

pub async fn start(_app: AppHandle) -> Result<()> {
    Err(anyhow!(
        "sidecar::start is not implemented yet; see docs/specs/000-tauri-sidecar/plan.md"
    ))
}
