//! GuardiaBox Tauri shell.
//!
//! Responsibilities:
//!   1. Spawn the Python sidecar (bundled as an external binary).
//!   2. Parse the first stdout line to retrieve the session token + bound port.
//!   3. Expose a handful of Tauri commands to the React frontend, all
//!      allowlisted in `capabilities/default.json`.
//!   4. Host the WebView2 window with frameless + transparent chrome.

use tracing::info;

mod sidecar;

#[tauri::command]
fn app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .compact()
        .init();

    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_store::Builder::default().build())
        .plugin(tauri_plugin_window_state::Builder::default().build())
        .setup(|app| {
            info!(
                version = env!("CARGO_PKG_VERSION"),
                "GuardiaBox shell starting"
            );
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                if let Err(error) = sidecar::start(handle).await {
                    tracing::error!(?error, "failed to spawn Python sidecar");
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![app_version])
        .run(tauri::generate_context!())
        .expect("error while running GuardiaBox");
}
