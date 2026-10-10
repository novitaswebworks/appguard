pub mod auth;
pub mod scanner;
pub mod state;
pub mod vault;
pub mod watchdog;

use auth::BiometricStatus;
use scanner::ScannedApp;
use state::{AppGuardConfig, AppRule, SecurityManager};
use std::sync::Arc;
use tauri::{Manager, State};
use vault::VaultItem;

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

#[tauri::command]
fn inspect_folder_vaults(security: State<'_, Arc<SecurityManager>>) -> Vec<VaultItem> {
    let folders = security.config.read().locked_folders.clone();
    let mut items = Vec::new();
    for folder in folders {
        if let Some(item) = vault::inspect_vault(&folder) {
            items.push(item);
        }
    }
    items
}

#[tauri::command]
fn add_folder_to_vault(
    folder_path: String,
    security: State<'_, Arc<SecurityManager>>,
) -> Result<VaultItem, String> {
    security.add_vault_folder(folder_path.clone())?;
    vault::inspect_vault(&folder_path).ok_or_else(|| "Failed to inspect added folder".into())
}

#[tauri::command]
fn remove_folder_from_vault(
    folder_path: String,
    security: State<'_, Arc<SecurityManager>>,
) -> Result<bool, String> {
    security.remove_vault_folder(&folder_path)?;
    Ok(true)
}

#[tauri::command]
fn encrypt_vault_folder(
    folder_path: String,
    pin: String,
    security: State<'_, Arc<SecurityManager>>,
) -> Result<bool, String> {
    if !security.verify_master_pin(&pin) {
        return Err("Invalid Master PIN".into());
    }
    vault::lock_folder(&folder_path, &pin)
}

#[tauri::command]
fn decrypt_vault_folder(
    folder_path: String,
    pin: String,
    security: State<'_, Arc<SecurityManager>>,
) -> Result<bool, String> {
    if !security.verify_master_pin(&pin) {
        return Err("Invalid Master PIN".into());
    }
    vault::unlock_folder(&folder_path, &pin)
}

use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;

// ----------------- App Initialization -----------------

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let security_manager = Arc::new(SecurityManager::new());
    let watchdog_security = security_manager.clone();
    let tray_security = security_manager.clone();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--minimized"]),
        ))
        .manage(security_manager)
        .setup(move |app| {
            let handle = app.handle().clone();

            // Build enhanced system tray menu
            let count = tray_security.config.read().locked_apps.values().filter(|a| a.is_locked).count();
            let shield_text = format!("🛡️ Shield Active ({count} apps locked)");
            let status_i = MenuItem::with_id(app, "status", shield_text, false, None::<&str>)?;
            let show_i = MenuItem::with_id(app, "show", "Open AppGuard", true, None::<&str>)?;
            let lock_i = MenuItem::with_id(app, "lock_all", "🔒 Lock All Now (⌘⇧L)", true, None::<&str>)?;
            let prefs_i = MenuItem::with_id(app, "prefs", "⚙️ Preferences & Palettes", true, None::<&str>)?;
            let quit_i = MenuItem::with_id(app, "quit", "❌ Quit AppGuard", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&status_i, &show_i, &lock_i, &prefs_i, &quit_i])?;

            let tray_handle = handle.clone();
            let _tray = TrayIconBuilder::new()
                .menu(&menu)
                .tooltip("AppGuard — Biometric Privacy Shield")
                .on_menu_event(move |_app, event| {
                    match event.id.as_ref() {
                        "show" | "prefs" => {
                            if let Some(w) = tray_handle.get_webview_window("main") {
                                let _ = w.show();
                                let _ = w.unminimize();
                                let _ = w.set_focus();
                            }
                        }
                        "lock_all" => {
                            tray_security.lock_all();
                        }
                        "quit" => {
                            std::process::exit(0);
                        }
                        _ => {}
                    }
                })
                .build(app)?;

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
            inspect_folder_vaults,
            add_folder_to_vault,
            remove_folder_from_vault,
            encrypt_vault_folder,
            decrypt_vault_folder,
        ])
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                // Prevent application exit on window close, minimize to tray
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running AppGuard application");
}
