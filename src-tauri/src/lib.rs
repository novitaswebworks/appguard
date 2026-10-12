pub mod auth;
pub mod platform;
pub mod scanner;
mod session;
pub mod state;
mod storage;
pub mod vault;
pub mod watchdog;

use auth::BiometricStatus;
use scanner::ScannedApp;
use state::{AppRule, SecurityManager};
use std::sync::Arc;
use tauri::{Emitter, Manager, State};
use vault::VaultItem;

#[derive(Debug, Clone, serde::Serialize)]
struct PublicAppGuardConfig {
    locked_apps: std::collections::HashMap<String, AppRule>,
    locked_folders: Vec<String>,
    grace_period_seconds: u64,
    stealth_mode: bool,
    app_self_locked: bool,
    lock_on_sleep: bool,
    lock_on_screensaver: bool,
    instant_lock_mode: bool,
    tamper_protection_enabled: bool,
    activity_log: Vec<state::AuditEvent>,
    pin_configured: bool,
    recovery_key_configured: bool,
}

fn main_window(window: &tauri::WebviewWindow) -> Result<(), String> {
    if window.label() == "main" {
        Ok(())
    } else {
        Err("This command is restricted to the dashboard".into())
    }
}
fn dashboard(window: &tauri::WebviewWindow, security: &SecurityManager) -> Result<(), String> {
    main_window(window)?;
    security.require_authenticated()
}
fn auth_window(window: &tauri::WebviewWindow) -> Result<(), String> {
    if window.label() == "auth" {
        Ok(())
    } else {
        Err("Use the application authentication window".into())
    }
}

#[tauri::command]
fn quit_app(
    app_handle: tauri::AppHandle,
    window: tauri::WebviewWindow,
    security: State<'_, Arc<SecurityManager>>,
) -> Result<(), String> {
    main_window(&window)?;
    let _operation = security.operation_lock.lock();
    security.ensure_ready()?;
    if security.is_pin_configured() {
        security.require_authenticated()?;
    }
    if security.config.read().tamper_protection_enabled {
        platform::get_platform().disable_tamper_protection()?;
        security.config.write().tamper_protection_enabled = false;
        security.save()?;
    }
    app_handle.exit(0);
    Ok(())
}

#[tauri::command]
fn security_status(security: State<'_, Arc<SecurityManager>>) -> serde_json::Value {
    serde_json::json!({"error": security.ensure_ready().err(), "authenticated": security.is_app_authenticated(), "pin_configured": security.is_pin_configured(), "platform": std::env::consts::OS, "arch": std::env::consts::ARCH, "protection": watchdog::capability()})
}

// ----------------- IPC Tauri Commands -----------------

#[tauri::command]
fn check_biometrics() -> BiometricStatus {
    auth::check_biometrics()
}

#[tauri::command]
fn authenticate_biometrics(
    reason: String,
    window: tauri::WebviewWindow,
    security: State<'_, Arc<SecurityManager>>,
) -> Result<bool, String> {
    main_window(&window)?;
    security.ensure_ready()?;
    let generation = security.auth_generation();
    let success = auth::authenticate(&reason)?;
    if success {
        security.authenticate_dashboard(generation)?;
    }
    Ok(success)
}

#[tauri::command]
fn is_pin_configured(security: State<'_, Arc<SecurityManager>>) -> bool {
    security.is_pin_configured()
}

#[tauri::command]
fn set_master_pin(
    pin: String,
    window: tauri::WebviewWindow,
    security: State<'_, Arc<SecurityManager>>,
) -> Result<bool, String> {
    main_window(&window)?;
    let _operation = security.operation_lock.lock();
    security.ensure_ready()?;
    if security.is_pin_configured() {
        return Err("A Master PIN already exists; use the authenticated PIN change flow".into());
    }
    security.set_master_pin(&pin)?;
    security.set_app_authenticated(true);
    Ok(true)
}

#[tauri::command]
fn verify_pin(
    pin: String,
    window: tauri::WebviewWindow,
    security: State<'_, Arc<SecurityManager>>,
) -> Result<bool, String> {
    main_window(&window)?;
    let _operation = security.operation_lock.lock();
    let generation = security.auth_generation();
    let valid = security.verify_master_pin(&pin)?;
    if valid {
        security.authenticate_dashboard(generation)?;
    }
    Ok(valid)
}

#[tauri::command]
fn generate_recovery_key(
    pin: String,
    window: tauri::WebviewWindow,
    security: State<'_, Arc<SecurityManager>>,
) -> Result<String, String> {
    let _operation = security.operation_lock.lock();
    dashboard(&window, &security)?;
    security.generate_recovery_key(&pin)
}

#[tauri::command]
fn is_recovery_configured(security: State<'_, Arc<SecurityManager>>) -> bool {
    security.is_recovery_configured()
}

#[tauri::command]
fn verify_recovery_key(
    key: String,
    new_pin: String,
    window: tauri::WebviewWindow,
    security: State<'_, Arc<SecurityManager>>,
) -> Result<bool, String> {
    main_window(&window)?;
    let _operation = security.operation_lock.lock();
    security.verify_recovery_key(&key, &new_pin)
}

#[tauri::command]
fn get_activity_log(
    window: tauri::WebviewWindow,
    security: State<'_, Arc<SecurityManager>>,
) -> Result<Vec<state::AuditEvent>, String> {
    dashboard(&window, &security)?;
    Ok(security.get_activity_log())
}

#[tauri::command]
fn get_locked_app_target(security: State<'_, Arc<SecurityManager>>) -> Option<session::Target> {
    security.challenge.lock().get()
}

#[tauri::command]
fn authenticate_target(
    bundle_id: String,
    request_id: u64,
    pin: Option<String>,
    window: tauri::WebviewWindow,
    security: State<'_, Arc<SecurityManager>>,
) -> Result<bool, String> {
    auth_window(&window)?;
    security.ensure_ready()?;
    let target = security.challenge.lock().validate(&bundle_id, request_id)?;
    let valid = if let Some(pin) = pin {
        let _operation = security.operation_lock.lock();
        security.verify_master_pin(&pin)?
    } else {
        auth::authenticate(&format!("Unlock {}", target.name))?
    };
    if valid {
        security.challenge.lock().authorize(&target)?;
    }
    Ok(valid)
}

#[tauri::command]
fn is_app_authenticated(security: State<'_, Arc<SecurityManager>>) -> bool {
    security.is_app_authenticated()
}

#[tauri::command]
fn unlock_appguard(
    reason: Option<String>,
    window: tauri::WebviewWindow,
    security: State<'_, Arc<SecurityManager>>,
) -> Result<bool, String> {
    main_window(&window)?;
    security.ensure_ready()?;
    let generation = security.auth_generation();
    // Rust-enforced authentication gate: require valid OS biometric or passcode
    let auth_reason = reason.unwrap_or_else(|| "Authenticate to access AppGuard".into());
    let success = auth::authenticate(&auth_reason)?;
    if success {
        security.authenticate_dashboard(generation)?;
        Ok(true)
    } else {
        Err("Authentication failed".into())
    }
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
    tamper_protection_enabled: bool,
    window: tauri::WebviewWindow,
    security: State<'_, Arc<SecurityManager>>,
) -> Result<bool, String> {
    let _operation = security.operation_lock.lock();
    dashboard(&window, &security)?;
    security
        .update_preferences(
            grace_period_seconds,
            app_self_locked,
            lock_on_sleep,
            lock_on_screensaver,
            instant_lock_mode,
            stealth_mode,
            tamper_protection_enabled,
        )
        .map(|_| true)
}

#[tauri::command]
fn set_tamper_protection(
    enabled: bool,
    window: tauri::WebviewWindow,
    security: State<'_, Arc<SecurityManager>>,
) -> Result<bool, String> {
    let _operation = security.operation_lock.lock();
    dashboard(&window, &security)?;
    let platform = platform::get_platform();
    if enabled {
        let exe_path = std::env::current_exe()
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .to_string();
        platform.enable_tamper_protection(&exe_path)?;
    } else {
        platform.disable_tamper_protection()?;
    }

    let mut cfg = security.config.write();
    cfg.tamper_protection_enabled = enabled;
    drop(cfg);
    security.save()?;
    Ok(true)
}

#[tauri::command]
fn change_master_pin(
    old_pin: String,
    new_pin: String,
    window: tauri::WebviewWindow,
    security: State<'_, Arc<SecurityManager>>,
) -> Result<bool, String> {
    let _operation = security.operation_lock.lock();
    dashboard(&window, &security)?;
    security.change_pin(&old_pin, &new_pin).map(|_| true)
}

#[tauri::command]
fn get_config(
    window: tauri::WebviewWindow,
    security: State<'_, Arc<SecurityManager>>,
) -> Result<PublicAppGuardConfig, String> {
    dashboard(&window, &security)?;
    let cfg = security.config.read();
    Ok(PublicAppGuardConfig {
        locked_apps: cfg.locked_apps.clone(),
        locked_folders: cfg.locked_folders.clone(),
        grace_period_seconds: cfg.grace_period_seconds,
        stealth_mode: false,
        app_self_locked: true,
        lock_on_sleep: false,
        lock_on_screensaver: false,
        instant_lock_mode: cfg.instant_lock_mode,
        tamper_protection_enabled: cfg.tamper_protection_enabled,
        activity_log: cfg.activity_log.clone(),
        pin_configured: cfg.master_pin_hash.is_some(),
        recovery_key_configured: cfg.recovery_key_hash.is_some(),
    })
}

#[tauri::command]
fn toggle_lock_app(
    app: AppRule,
    window: tauri::WebviewWindow,
    security: State<'_, Arc<SecurityManager>>,
) -> Result<bool, String> {
    let _operation = security.operation_lock.lock();
    dashboard(&window, &security)?;
    if app.is_locked && !watchdog::capability().available {
        return Err(watchdog::capability().message);
    }
    security.toggle_app_lock(app).map(|_| true)
}

#[tauri::command]
fn unlock_app_session(
    bundle_id: String,
    request_id: u64,
    duration_secs: Option<u64>,
    app_handle: tauri::AppHandle,
    window: tauri::WebviewWindow,
    security: State<'_, Arc<SecurityManager>>,
) -> Result<bool, String> {
    auth_window(&window)?;
    security.ensure_ready()?;
    if duration_secs.is_some_and(|seconds| seconds == 0 || seconds > 3600) {
        return Err("Invalid unlock duration".into());
    }
    let _windows = security.window_lock.lock();
    let target = security.challenge.lock().consume(&bundle_id, request_id)?;
    let _pending_platform_window = target.window;
    security.mark_app_unlocked(&bundle_id, duration_secs);

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

    #[cfg(target_os = "linux")]
    {
        // Restore the exact window that triggered authentication. Window
        // titles are not stable application identifiers and often do not
        // contain the desktop-file ID.
        if let Some(window_id) = _pending_platform_window {
            let _ = std::process::Command::new("xdotool")
                .args(["windowmap", &window_id])
                .status();
            let _ = std::process::Command::new("xdotool")
                .args(["windowactivate", &window_id])
                .status();
        }
    }

    #[cfg(target_os = "windows")]
    if let Some(window_handle) = _pending_platform_window {
        watchdog::windows_show_window(&window_handle, true);
    }

    // Release always-on-top and hide both auth and main windows so focus returns to the unlocked app
    if let Some(auth_win) = app_handle.get_webview_window("auth") {
        let _ = auth_win.set_always_on_top(false);
        let _ = auth_win.hide();
    }
    if let Some(main_win) = app_handle.get_webview_window("main") {
        let _ = main_win.set_always_on_top(false);
        let _ = main_win.hide();
    }
    Ok(true)
}

pub fn enforce_lock_all(app: &tauri::AppHandle, security: &SecurityManager) {
    let _operation = security.operation_lock.lock();
    security.lock_all();
    let _windows = security.window_lock.lock();
    let _ = app.emit("sessions-locked", ());
    if let Some(auth) = app.get_webview_window("auth") {
        let _ = auth.hide();
    }

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

    #[cfg(target_os = "linux")]
    {
        watchdog::enforce_linux_lock_all(app, security);
    }
    #[cfg(target_os = "windows")]
    watchdog::enforce_windows_lock_all(app, security);
}

#[tauri::command]
fn lock_all_sessions(
    app_handle: tauri::AppHandle,
    security: State<'_, Arc<SecurityManager>>,
) -> bool {
    enforce_lock_all(&app_handle, &security);
    true
}

#[tauri::command]
fn close_locked_application(
    bundle_id: String,
    request_id: u64,
    app_handle: tauri::AppHandle,
    window: tauri::WebviewWindow,
    security: State<'_, Arc<SecurityManager>>,
) -> Result<bool, String> {
    auth_window(&window)?;
    let _windows = security.window_lock.lock();
    let target = security.challenge.lock().cancel(&bundle_id, request_id)?;
    let _pending_platform_window = target.window;
    if let Some(auth_win) = app_handle.get_webview_window("auth") {
        let _ = auth_win.set_always_on_top(false);
        let _ = auth_win.hide();
    }

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

    #[cfg(target_os = "linux")]
    {
        if let Some(window_id) = _pending_platform_window {
            let _ = std::process::Command::new("xdotool")
                .args(["windowclose", &window_id])
                .status();
        }
    }
    #[cfg(target_os = "windows")]
    if let Some(window_handle) = _pending_platform_window {
        watchdog::windows_show_window(&window_handle, false);
    }
    Ok(true)
}

#[tauri::command]
fn hide_auth_window(
    app_handle: tauri::AppHandle,
    security: State<'_, Arc<SecurityManager>>,
) -> bool {
    if security.challenge.lock().get().is_some() {
        return false;
    }
    if let Some(auth_win) = app_handle.get_webview_window("auth") {
        let _ = auth_win.set_always_on_top(false);
        let _ = auth_win.hide();
    }
    true
}

#[tauri::command]
fn get_installed_apps(
    window: tauri::WebviewWindow,
    security: State<'_, Arc<SecurityManager>>,
) -> Result<Vec<ScannedApp>, String> {
    main_window(&window)?;
    security.ensure_ready()?;
    if security.is_pin_configured() {
        security.require_authenticated()?;
    }
    let mut apps = scanner::scan_installed_applications();
    let known_ids: std::collections::HashSet<String> =
        apps.iter().map(|app| app.bundle_id.clone()).collect();

    // Keep manually registered binaries visible after a restart or rescan.
    // They are not required to have a .desktop launcher.
    for rule in security.config.read().locked_apps.values() {
        if !known_ids.contains(&rule.bundle_id) {
            apps.push(ScannedApp {
                name: rule.name.clone(),
                bundle_id: rule.bundle_id.clone(),
                path: rule.path.clone(),
                icon_path: None,
                icon_base64: rule.icon_base64.clone(),
                exec_path: rule.exec_path.clone(),
                startup_wm_class: rule.startup_wm_class.clone(),
            });
        }
    }

    apps.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Ok(apps)
}

#[tauri::command]
fn register_application(
    path: String,
    window: tauri::WebviewWindow,
    security: State<'_, Arc<SecurityManager>>,
) -> Result<ScannedApp, String> {
    let _operation = security.operation_lock.lock();
    dashboard(&window, &security)?;
    let capability = watchdog::capability();
    if !capability.available {
        return Err(capability.message);
    }
    let app = scanner::inspect_application(&path)?;
    security.toggle_app_lock(AppRule {
        bundle_id: app.bundle_id.clone(),
        name: app.name.clone(),
        path: app.path.clone(),
        is_locked: true,
        icon_base64: app.icon_base64.clone(),
        exec_path: app.exec_path.clone(),
        startup_wm_class: app.startup_wm_class.clone(),
    })?;
    Ok(app)
}

#[tauri::command]
fn inspect_folder_vaults(
    window: tauri::WebviewWindow,
    security: State<'_, Arc<SecurityManager>>,
) -> Result<Vec<VaultItem>, String> {
    dashboard(&window, &security)?;
    let folders = security.config.read().locked_folders.clone();
    let mut items = Vec::new();
    for folder in folders {
        if let Some(item) = vault::inspect_vault(&folder) {
            items.push(item);
        }
    }
    Ok(items)
}

#[tauri::command]
fn add_folder_to_vault(
    folder_path: String,
    window: tauri::WebviewWindow,
    security: State<'_, Arc<SecurityManager>>,
) -> Result<VaultItem, String> {
    let _operation = security.operation_lock.lock();
    dashboard(&window, &security)?;
    security.add_vault_folder(folder_path.clone())?;
    let canonical_path = std::fs::canonicalize(&folder_path)
        .map_err(|e| format!("Failed to resolve vault folder: {e}"))?;
    let canonical_path = canonical_path.to_string_lossy().to_string();
    vault::inspect_vault(&canonical_path).ok_or_else(|| "Failed to inspect added folder".into())
}

#[tauri::command]
fn remove_folder_from_vault(
    folder_path: String,
    window: tauri::WebviewWindow,
    security: State<'_, Arc<SecurityManager>>,
) -> Result<bool, String> {
    let _operation = security.operation_lock.lock();
    dashboard(&window, &security)?;
    if vault::inspect_vault(&folder_path).is_some_and(|item| item.is_locked) {
        return Err("Decrypt this vault before removing it".into());
    }
    security.remove_vault_folder(&folder_path)?;
    Ok(true)
}

#[tauri::command]
fn encrypt_vault_folder(
    folder_path: String,
    pin: String,
    window: tauri::WebviewWindow,
    security: State<'_, Arc<SecurityManager>>,
) -> Result<bool, String> {
    let _operation = security.operation_lock.lock();
    dashboard(&window, &security)?;
    security.require_vault(&folder_path)?;
    if !security.verify_master_pin(&pin)? {
        return Err("Invalid Master PIN".into());
    }
    let result = vault::lock_folder(&folder_path, &pin)?;
    security.log_event(
        "vault_encrypted",
        &format!("Folder successfully encrypted: {folder_path}"),
        "info",
    );
    Ok(result)
}

#[tauri::command]
fn decrypt_vault_folder(
    folder_path: String,
    pin: String,
    window: tauri::WebviewWindow,
    security: State<'_, Arc<SecurityManager>>,
) -> Result<bool, String> {
    let _operation = security.operation_lock.lock();
    dashboard(&window, &security)?;
    security.require_vault(&folder_path)?;
    if !security.verify_master_pin(&pin)? {
        return Err("Invalid Master PIN".into());
    }
    let result = vault::unlock_folder(&folder_path, &pin)?;
    security.log_event(
        "vault_decrypted",
        &format!("Folder decrypted: {folder_path}"),
        "info",
    );
    Ok(result)
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
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            let is_minimized = args.iter().any(|arg| arg == "--minimized");
            if !is_minimized {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.unminimize();
                    let _ = w.set_focus();
                }
            }
        }))
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

            // Ensure main window is shown and focused unless launched with --minimized
            let is_minimized_launch = std::env::args().any(|arg| arg == "--minimized");
            if !is_minimized_launch {
                if let Some(w) = handle.get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.unminimize();
                    let _ = w.set_focus();
                }
            }

            // Register global hotkey Command+Shift+L to lock all sessions
            use tauri_plugin_global_shortcut::{GlobalShortcutExt, Shortcut};
            if let Ok(shortcut) = "CommandOrControl+Shift+L".parse::<Shortcut>() {
                let shortcut_security = tray_security.clone();
                let _ = app
                    .global_shortcut()
                    .on_shortcut(shortcut, move |app, _sc, event| {
                        if event.state == tauri_plugin_global_shortcut::ShortcutState::Pressed {
                            enforce_lock_all(app, &shortcut_security);
                        }
                    });
            }

            // Build enhanced system tray menu
            let count = tray_security
                .config
                .read()
                .locked_apps
                .values()
                .filter(|a| a.is_locked)
                .count();
            let shield_text = if watchdog::capability().available {
                format!("Window shield ({count} rules)")
            } else {
                "Window shielding unavailable".into()
            };
            let status_i = MenuItem::with_id(app, "status", shield_text, false, None::<&str>)?;
            let show_i = MenuItem::with_id(app, "show", "Open AppGuard", true, None::<&str>)?;
            let lock_i =
                MenuItem::with_id(app, "lock_all", "🔒 Lock All Now (⌘⇧L)", true, None::<&str>)?;
            let prefs_i = MenuItem::with_id(
                app,
                "prefs",
                "⚙️ Preferences & Palettes",
                true,
                None::<&str>,
            )?;
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
                            enforce_lock_all(&tray_handle, &tray_security);
                        }
                        "quit" => {
                            // Use the authenticated dashboard, including its
                            // PIN flow on platforms without OS authentication.
                            if let Some(w) = tray_handle.get_webview_window("main") {
                                let _ = w.show();
                                let _ = w.unminimize();
                                let _ = w.set_focus();
                                let _ = w.emit("quit-requested", ());
                            }
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
            security_status,
            quit_app,
            authenticate_target,
            check_biometrics,
            authenticate_biometrics,
            is_pin_configured,
            set_master_pin,
            verify_pin,
            is_app_authenticated,
            unlock_appguard,
            lock_appguard,
            update_preferences,
            set_tamper_protection,
            change_master_pin,
            get_config,
            toggle_lock_app,
            unlock_app_session,
            lock_all_sessions,
            get_installed_apps,
            register_application,
            close_locked_application,
            inspect_folder_vaults,
            add_folder_to_vault,
            remove_folder_from_vault,
            encrypt_vault_folder,
            decrypt_vault_folder,
            generate_recovery_key,
            is_recovery_configured,
            verify_recovery_key,
            get_activity_log,
            hide_auth_window,
            get_locked_app_target,
        ])
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                // Prevent application exit on window close, minimize to tray
                api.prevent_close();
                let security = window.state::<Arc<SecurityManager>>();
                if window.label() == "auth" && security.challenge.lock().get().is_some() {
                    // Cancel through the target-bound IPC so a window close
                    // cannot silently leave an invisible live challenge.
                    return;
                }
                if window.label() == "main" {
                    security.set_app_authenticated(false);
                    let _ = window.emit("sessions-locked", ());
                }
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running AppGuard application");
}
