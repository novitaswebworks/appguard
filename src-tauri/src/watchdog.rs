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
                            let _ = window.set_focus();
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
