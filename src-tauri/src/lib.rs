pub mod auth;
pub mod platform;
pub mod scanner;
pub mod state;
pub mod vault;
pub mod watchdog;

use auth::BiometricStatus;
use scanner::ScannedApp;
use state::{AppGuardConfig, AppRule, SecurityManager};
use std::sync::Arc;
use tauri::{Emitter, Manager, State};
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
    let valid = security.verify_master_pin(&pin);
    if valid {
        security.set_app_authenticated(true);
    }
    valid
}

#[tauri::command]
fn is_app_authenticated(security: State<'_, Arc<SecurityManager>>) -> bool {
    security.is_app_authenticated()
}

#[tauri::command]
fn unlock_appguard(security: State<'_, Arc<SecurityManager>>) -> bool {
    security.set_app_authenticated(true);
    true
}

#[tauri::command]
fn lock_appguard(security: State<'_, Arc<SecurityManager>>) -> bool {
    security.set_app_authenticated(false);
    true
}

#[tauri::command]
fn update_preferences(
    grace_period_seconds: u64,
    app_self_locked: bool,
    lock_on_sleep: bool,
    lock_on_screensaver: bool,
    instant_lock_mode: bool,
    stealth_mode: bool,
    security: State<'_, Arc<SecurityManager>>,
) -> Result<bool, String> {
    security
        .update_preferences(
            grace_period_seconds,
            app_self_locked,
            lock_on_sleep,
            lock_on_screensaver,
            instant_lock_mode,
            stealth_mode,
        )
        .map(|_| true)
}

#[tauri::command]
fn change_master_pin(
    old_pin: String,
    new_pin: String,
    security: State<'_, Arc<SecurityManager>>,
) -> Result<bool, String> {
    if !security.verify_master_pin(&old_pin) {
        return Err("Current PIN is incorrect".into());
    }
    security.set_master_pin(&new_pin).map(|_| true)
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
    app_handle: tauri::AppHandle,
    security: State<'_, Arc<SecurityManager>>,
) -> Result<bool, String> {
    security.mark_app_unlocked(&bundle_id);

    #[cfg(target_os = "macos")]
    {
        use objc2::msg_send;
        use objc2::runtime::AnyClass;
        use objc2_foundation::NSString;
        unsafe {
            if let Some(ns_workspace_cls) = AnyClass::get(c"NSWorkspace") {
                let shared_workspace: *mut objc2::runtime::AnyObject =
                    msg_send![ns_workspace_cls, sharedWorkspace];
                if !shared_workspace.is_null() {
                    let running_apps: *mut objc2_foundation::NSArray<objc2::runtime::AnyObject> =
                        msg_send![shared_workspace, runningApplications];
                    if !running_apps.is_null() {
                        let count: usize = msg_send![running_apps, count];
                        for i in 0..count {
                            let app: *mut objc2::runtime::AnyObject =
                                msg_send![running_apps, objectAtIndex: i];
                            let bid: *mut NSString = msg_send![app, bundleIdentifier];
                            if !bid.is_null() && (*bid).to_string() == bundle_id {
                                let _: () = msg_send![app, unhide];
                                let _: () = msg_send![app, activateWithOptions: 1usize << 1]; // NSApplicationActivateIgnoringOtherApps
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    // Release always-on-top and hide AppGuard window so focus returns to the unlocked app
    if let Some(window) = app_handle.get_webview_window("main") {
        let _ = window.set_always_on_top(false);
        let _ = window.hide();
    }
    Ok(true)
}

pub fn enforce_lock_all(security: &SecurityManager) {
    security.lock_all();

    #[cfg(target_os = "macos")]
    {
        use objc2::msg_send;
        use objc2::runtime::AnyClass;
        use objc2_foundation::NSString;
        unsafe {
            if let Some(ns_workspace_cls) = AnyClass::get(c"NSWorkspace") {
                let shared_workspace: *mut objc2::runtime::AnyObject =
                    msg_send![ns_workspace_cls, sharedWorkspace];
                if !shared_workspace.is_null() {
                    let running_apps: *mut objc2_foundation::NSArray<objc2::runtime::AnyObject> =
                        msg_send![shared_workspace, runningApplications];
                    if !running_apps.is_null() {
                        let count: usize = msg_send![running_apps, count];
                        for i in 0..count {
                            let app: *mut objc2::runtime::AnyObject =
                                msg_send![running_apps, objectAtIndex: i];
                            let bid: *mut NSString = msg_send![app, bundleIdentifier];
                            if !bid.is_null() {
                                let b_str = (*bid).to_string();
                                if security.is_app_locked(&b_str) {
                                    let _: () = msg_send![app, hide];
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[tauri::command]
fn lock_all_sessions(
    app_handle: tauri::AppHandle,
    security: State<'_, Arc<SecurityManager>>,
) -> bool {
    enforce_lock_all(&security);
    let _ = app_handle.emit("sessions-locked", ());
    true
}

#[tauri::command]
fn close_locked_application(bundle_id: String) -> Result<bool, String> {
    #[cfg(target_os = "macos")]
    {
        use objc2::msg_send;
        use objc2::runtime::AnyClass;
        use objc2_foundation::NSString;
        unsafe {
            if let Some(ns_workspace_cls) = AnyClass::get(c"NSWorkspace") {
                let shared_workspace: *mut objc2::runtime::AnyObject =
                    msg_send![ns_workspace_cls, sharedWorkspace];
                if !shared_workspace.is_null() {
                    let running_apps: *mut objc2_foundation::NSArray<objc2::runtime::AnyObject> =
                        msg_send![shared_workspace, runningApplications];
                    if !running_apps.is_null() {
                        let count: usize = msg_send![running_apps, count];
                        for i in 0..count {
                            let app: *mut objc2::runtime::AnyObject =
                                msg_send![running_apps, objectAtIndex: i];
                            let bid: *mut NSString = msg_send![app, bundleIdentifier];
                            if !bid.is_null() && (*bid).to_string() == bundle_id {
                                // Force hide and terminate the unauthorized app
                                let _: () = msg_send![app, hide];
                                let _: bool = msg_send![app, terminate];
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(true)
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
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .manage(security_manager)
        .setup(move |app| {
            let handle = app.handle().clone();

            // Register global hotkey Command+Shift+L to lock all sessions
            use tauri_plugin_global_shortcut::{GlobalShortcutExt, Shortcut};
            if let Ok(shortcut) = "CommandOrControl+Shift+L".parse::<Shortcut>() {
                let shortcut_security = tray_security.clone();
                let _ = app.global_shortcut().on_shortcut(shortcut, move |_app, _sc, _ev| {
                    shortcut_security.lock_all();
                });
            }

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
            let mut tray_builder = TrayIconBuilder::new()
                .menu(&menu)
                .tooltip("AppGuard — Biometric Privacy Shield");

            // Explicitly load macOS template icon (vector lock shield) for the menu bar
            let icon_bytes = include_bytes!("../icons/tray-template.png");
            if let Ok(img) = image::load_from_memory(icon_bytes) {
                let rgba = img.to_rgba8();
                let (width, height) = rgba.dimensions();
                let icon = tauri::image::Image::new_owned(rgba.into_raw(), width, height);
                tray_builder = tray_builder.icon(icon).icon_as_template(true);
            }

            let _tray = tray_builder
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
                            enforce_lock_all(&tray_security);
                        }
                        "quit" => {
                            // Security Gate: Ensure unauthorized individuals cannot terminate AppGuard
                            std::thread::spawn(|| {
                                if let Ok(success) = auth::authenticate("Authenticate to Quit AppGuard") {
                                    if success {
                                        std::process::exit(0);
                                    }
                                }
                            });
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
            is_app_authenticated,
            unlock_appguard,
            lock_appguard,
            update_preferences,
            change_master_pin,
            get_config,
            toggle_lock_app,
            unlock_app_session,
            lock_all_sessions,
            get_installed_apps,
            close_locked_application,
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
