use crate::state::SecurityManager;
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};

#[cfg(target_os = "macos")]
pub fn start_focus_watchdog(app_handle: AppHandle, security: Arc<SecurityManager>) {
    use objc2::msg_send;
    use objc2::runtime::AnyClass;
    use objc2_foundation::NSString;

    std::thread::spawn(move || {
        let mut last_bundle = String::new();

        loop {
            std::thread::sleep(Duration::from_millis(150));

            unsafe {
                let ns_workspace_cls = match AnyClass::get(c"NSWorkspace") {
                    Some(cls) => cls,
                    None => continue,
                };

                let shared_workspace: *mut objc2::runtime::AnyObject =
                    msg_send![ns_workspace_cls, sharedWorkspace];
                if shared_workspace.is_null() {
                    continue;
                }

                let frontmost_app: *mut objc2::runtime::AnyObject =
                    msg_send![shared_workspace, frontmostApplication];
                if frontmost_app.is_null() {
                    continue;
                }

                let bundle_id_ns: *mut NSString = msg_send![frontmost_app, bundleIdentifier];
                if bundle_id_ns.is_null() {
                    continue;
                }

                let current_bundle = (*bundle_id_ns).to_string();

                // When AppGuard is frontmost, record it in last_bundle and continue
                if current_bundle == "com.appguard.desktop" || current_bundle.is_empty() {
                    last_bundle = current_bundle;
                    continue;
                }

                if current_bundle != last_bundle {
                    last_bundle = current_bundle.clone();

                    if security.is_app_locked(&current_bundle) {
                        let name_ns: *mut NSString =
                            msg_send![frontmost_app, localizedName];
                        let app_name = if !name_ns.is_null() {
                            (*name_ns).to_string()
                        } else {
                            current_bundle.clone()
                        };

                        // Immediately hide the unauthorized locked application from screen!
                        let _: () = msg_send![frontmost_app, hide];

                        // Emit locked app event to frontend & bring AppGuard lock window to focus
                        let _ = app_handle.emit(
                            "app-locked-triggered",
                            serde_json::json!({
                                "bundle_id": current_bundle,
                                "name": app_name,
                            }),
                        );

                        // Prefer showing compact 'auth' floating window (Option A); fallback to 'main' only if needed
                        let target_window = app_handle
                            .get_webview_window("auth")
                            .or_else(|| app_handle.get_webview_window("main"));

                        if let Some(window) = target_window {
                            let _ = window.show();
                            let _ = window.unminimize();
                            let _ = window.set_always_on_top(true);
                            let _ = window.set_focus();

                            // Force macOS App Activation to steal focus over the locked app
                            if let Some(ns_app_cls) = AnyClass::get(c"NSApplication") {
                                let shared_app: *mut objc2::runtime::AnyObject =
                                    msg_send![ns_app_cls, sharedApplication];
                                if !shared_app.is_null() {
                                    let _: () = msg_send![shared_app, activateIgnoringOtherApps: true];
                                }
                            }
                        }
                    }
                }
            }
        }
    });
}

#[cfg(target_os = "linux")]
pub fn start_focus_watchdog(app_handle: AppHandle, security: Arc<SecurityManager>) {
    use std::process::Command;

    std::thread::spawn(move || {
        let mut last_app = String::new();

        loop {
            std::thread::sleep(Duration::from_millis(250));

            // Probe active window title/class via xdotool
            let output = Command::new("xdotool")
                .args(["getwindowfocus", "getwindowname"])
                .output();

            if let Ok(out) = output {
                if out.status.success() {
                    let current_name = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if current_name.is_empty() || current_name.to_lowercase().contains("appguard") {
                        continue;
                    }

                    if current_name != last_app {
                        last_app = current_name.clone();

                        // Check if any locked app rule matches this title or binary
                        let is_locked = {
                            let cfg = security.config.read();
                            cfg.locked_apps.values().any(|r| {
                                r.is_locked
                                    && (current_name.contains(&r.name)
                                        || current_name.contains(&r.bundle_id))
                            })
                        };

                        if is_locked {
                            // Minimize unauthorized window
                            let _ = Command::new("xdotool")
                                .args(["getwindowfocus", "windowminimize"])
                                .status();

                            let _ = app_handle.emit(
                                "app-locked-triggered",
                                serde_json::json!({
                                    "bundle_id": current_name,
                                    "name": current_name,
                                }),
                            );

                            let target_window = app_handle
                                .get_webview_window("auth")
                                .or_else(|| app_handle.get_webview_window("main"));

                            if let Some(window) = target_window {
                                let _ = window.show();
                                let _ = window.unminimize();
                                let _ = window.set_always_on_top(true);
                                let _ = window.set_focus();
                            }
                        }
                    }
                }
            }
        }
    });
}

#[cfg(target_os = "windows")]
pub fn start_focus_watchdog(app_handle: AppHandle, security: Arc<SecurityManager>) {
    // Windows focus loop querying active foreground window
    std::thread::spawn(move || {
        let mut last_title = String::new();

        loop {
            std::thread::sleep(Duration::from_millis(250));

            // On Windows, users can query active foreground window via powershell / tasklist
            // or native Windows hook when winapi/windows crate is linked
            let output = std::process::Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    "(Get-Process | Where-Object { $_.MainWindowHandle -eq (Add-Type '[DllImport(\"user32.dll\")] public static extern IntPtr GetForegroundWindow();' -Name W -PassThru)::GetForegroundWindow() }).ProcessName",
                ])
                .output();

            if let Ok(out) = output {
                if out.status.success() {
                    let proc_name = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    let exe_bundle = format!("{}.exe", proc_name.to_lowercase());

                    if proc_name.is_empty() || proc_name.to_lowercase().contains("appguard") {
                        continue;
                    }

                    if exe_bundle != last_title {
                        last_title = exe_bundle.clone();

                        if security.is_app_locked(&exe_bundle) {
                            let _ = app_handle.emit(
                                "app-locked-triggered",
                                serde_json::json!({
                                    "bundle_id": exe_bundle,
                                    "name": proc_name,
                                }),
                            );

                            let target_window = app_handle
                                .get_webview_window("auth")
                                .or_else(|| app_handle.get_webview_window("main"));

                            if let Some(window) = target_window {
                                let _ = window.show();
                                let _ = window.unminimize();
                                let _ = window.set_always_on_top(true);
                                let _ = window.set_focus();
                            }
                        }
                    }
                }
            }
        }
    });
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn start_focus_watchdog(_app_handle: AppHandle, _security: Arc<SecurityManager>) {
    // Unsupported platform stub
}
