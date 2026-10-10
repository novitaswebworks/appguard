use crate::state::SecurityManager;
use std::sync::Arc;
use tauri::AppHandle;
#[cfg(target_os = "macos")]
use std::time::Duration;
#[cfg(target_os = "macos")]
use tauri::{Emitter, Manager};

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

                // Skip AppGuard itself from triggering its own lock overlay
                if current_bundle == "com.appguard.desktop" || current_bundle.is_empty() {
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

                        if let Some(window) = app_handle.get_webview_window("main") {
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
                } else if security.is_app_locked(&current_bundle) {
                    // Even if last_bundle matches (e.g. user dismissed or tried to re-focus), enforce lock!
                    let name_ns: *mut NSString = msg_send![frontmost_app, localizedName];
                    let app_name = if !name_ns.is_null() {
                        (*name_ns).to_string()
                    } else {
                        current_bundle.clone()
                    };

                    let _: () = msg_send![frontmost_app, hide];
                    let _ = app_handle.emit(
                        "app-locked-triggered",
                        serde_json::json!({
                            "bundle_id": current_bundle,
                            "name": app_name,
                        }),
                    );
                    if let Some(window) = app_handle.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.unminimize();
                        let _ = window.set_always_on_top(true);
                        let _ = window.set_focus();

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
    });
}

#[cfg(not(target_os = "macos"))]
pub fn start_focus_watchdog(_app_handle: AppHandle, _security: Arc<SecurityManager>) {
    // Windows/Linux focus hook
}
