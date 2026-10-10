pub mod auth;
pub mod scanner;
pub mod state;
pub mod watchdog;

use auth::BiometricStatus;
use scanner::ScannedApp;
use state::{AppGuardConfig, AppRule, SecurityManager};
use std::sync::Arc;
use tauri::State;

// ----------------- IPC Tauri Commands -----------------

#[tauri::command]
fn check_biometrics() -> BiometricStatus {
    auth::check_biometrics()
}

#[tauri::command]
fn authenticate_biometrics(reason: String) -> Result<bool, String> {
    auth::authenticate(&reason)
}

#[tauri::command]
fn is_pin_configured(security: State<'_, Arc<SecurityManager>>) -> bool {
    security.is_pin_configured()
}

#[tauri::command]
fn set_master_pin(pin: String, security: State<'_, Arc<SecurityManager>>) -> Result<bool, String> {
    security.set_master_pin(&pin).map(|_| true)
}

#[tauri::command]
fn verify_pin(pin: String, security: State<'_, Arc<SecurityManager>>) -> bool {
    security.verify_master_pin(&pin)
}

#[tauri::command]
fn get_config(security: State<'_, Arc<SecurityManager>>) -> AppGuardConfig {
    security.config.read().clone()
}

#[tauri::command]
fn toggle_lock_app(
    app: AppRule,
    security: State<'_, Arc<SecurityManager>>,
) -> Result<bool, String> {
    security.toggle_app_lock(app).map(|_| true)
}

#[tauri::command]
fn unlock_app_session(
    bundle_id: String,
    security: State<'_, Arc<SecurityManager>>,
) -> Result<bool, String> {
    security.mark_app_unlocked(&bundle_id);
    Ok(true)
}

#[tauri::command]
fn lock_all_sessions(security: State<'_, Arc<SecurityManager>>) -> bool {
    security.lock_all();
    true
}

#[tauri::command]
fn get_installed_apps() -> Vec<ScannedApp> {
    scanner::scan_installed_applications()
}

// ----------------- App Initialization -----------------

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let security_manager = Arc::new(SecurityManager::new());
    let watchdog_security = security_manager.clone();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(security_manager)
        .setup(move |app| {
            let handle = app.handle().clone();
            // Start the background frontmost application watchdog
            watchdog::start_focus_watchdog(handle, watchdog_security);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            check_biometrics,
            authenticate_biometrics,
            is_pin_configured,
            set_master_pin,
            verify_pin,
            get_config,
            toggle_lock_app,
            unlock_app_session,
            lock_all_sessions,
            get_installed_apps,
        ])
        .run(tauri::generate_context!())
        .expect("error while running AppGuard application");
}
