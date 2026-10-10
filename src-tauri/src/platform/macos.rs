use super::{FrontmostAppInfo, PlatformBiometricStatus, PlatformOps};
use block2::RcBlock;
use objc2::msg_send;
use objc2::runtime::{AnyClass, Bool};
use objc2_foundation::NSString;
use std::process::Command;
use std::sync::mpsc::channel;

pub struct MacPlatformOps;

impl MacPlatformOps {
    pub fn new() -> Self {
        Self
    }
}

impl PlatformOps for MacPlatformOps {
    fn check_biometrics(&self) -> PlatformBiometricStatus {
        unsafe {
            let la_context_class = match AnyClass::get(c"LAContext") {
                Some(cls) => cls,
                None => {
                    return PlatformBiometricStatus {
                        is_available: false,
                        biometric_type: "None".into(),
                        has_system_passcode: false,
                        error_message: Some("LocalAuthentication framework not found".into()),
                    };
                }
            };

            let context: *mut objc2::runtime::AnyObject = msg_send![la_context_class, new];
            if context.is_null() {
                return PlatformBiometricStatus {
                    is_available: false,
                    biometric_type: "None".into(),
                    has_system_passcode: false,
                    error_message: Some("Failed to allocate LAContext".into()),
                };
            }

            // LAPolicyDeviceOwnerAuthenticationWithBiometrics = 1
            // LAPolicyDeviceOwnerAuthentication (Biometrics + Mac Password fallback) = 2
            let mut bio_error: *mut objc2::runtime::AnyObject = std::ptr::null_mut();
            let can_evaluate_bio: Bool =
                msg_send![context, canEvaluatePolicy: 1isize, error: &mut bio_error];

            let mut pass_error: *mut objc2::runtime::AnyObject = std::ptr::null_mut();
            let can_evaluate_passcode: Bool =
                msg_send![context, canEvaluatePolicy: 2isize, error: &mut pass_error];
            let has_system_passcode = can_evaluate_passcode.as_bool();

            if can_evaluate_bio.as_bool() {
                let biometry_type: isize = msg_send![context, biometryType];
                let b_type = match biometry_type {
                    1 => "TouchID",
                    2 => "FaceID",
                    _ => "TouchID",
                };
                PlatformBiometricStatus {
                    is_available: true,
                    biometric_type: b_type.into(),
                    has_system_passcode,
                    error_message: None,
                }
            } else if has_system_passcode {
                PlatformBiometricStatus {
                    is_available: true,
                    biometric_type: "SystemPassword".into(),
                    has_system_passcode: true,
                    error_message: None,
                }
            } else {
                PlatformBiometricStatus {
                    is_available: false,
                    biometric_type: "PIN".into(),
                    has_system_passcode: false,
                    error_message: Some(
                        "No biometric hardware or system passcode enrolled. Master PIN will be used."
                            .into(),
                    ),
                }
            }
        }
    }

    fn authenticate_biometrics(&self, reason: &str) -> Result<bool, String> {
        unsafe {
            let la_context_class = AnyClass::get(c"LAContext")
                .ok_or_else(|| "LocalAuthentication not available".to_string())?;

            let context: *mut objc2::runtime::AnyObject = msg_send![la_context_class, new];
            if context.is_null() {
                return Err("Failed to create LAContext".into());
            }

            let reason_ns = NSString::from_str(reason);
            let (tx, rx) = channel::<Result<bool, String>>();

            let reply_block = RcBlock::new(
                move |success: Bool, error: *mut objc2::runtime::AnyObject| {
                    if success.as_bool() {
                        let _ = tx.send(Ok(true));
                    } else if !error.is_null() {
                        let desc: *mut NSString = msg_send![error, localizedDescription];
                        let desc_str = if !desc.is_null() {
                            (*desc).to_string()
                        } else {
                            "Authentication failed".to_string()
                        };
                        let _ = tx.send(Err(desc_str));
                    } else {
                        let _ = tx.send(Err("User cancelled authentication".to_string()));
                    }
                },
            );

            let _: () = msg_send![
                context,
                evaluatePolicy: 2isize,
                localizedReason: &*reason_ns,
                reply: &*reply_block
            ];

            rx.recv().unwrap_or(Err("Authentication channel dropped".into()))
        }
    }

    fn get_frontmost_app(&self) -> Option<FrontmostAppInfo> {
        unsafe {
            let ns_workspace_cls = AnyClass::get(c"NSWorkspace")?;
            let shared_workspace: *mut objc2::runtime::AnyObject =
                msg_send![ns_workspace_cls, sharedWorkspace];
            if shared_workspace.is_null() {
                return None;
            }

            let frontmost_app: *mut objc2::runtime::AnyObject =
                msg_send![shared_workspace, frontmostApplication];
            if frontmost_app.is_null() {
                return None;
            }

            let bundle_id_ns: *mut NSString = msg_send![frontmost_app, bundleIdentifier];
            if bundle_id_ns.is_null() {
                return None;
            }
            let bundle_id = (*bundle_id_ns).to_string();

            let name_ns: *mut NSString = msg_send![frontmost_app, localizedName];
            let name = if !name_ns.is_null() {
                (*name_ns).to_string()
            } else {
                bundle_id.clone()
            };

            Some(FrontmostAppInfo {
                id: bundle_id,
                name,
            })
        }
    }

    fn hide_application(&self, _app_id: &str) {
        unsafe {
            if let Some(ns_workspace_cls) = AnyClass::get(c"NSWorkspace") {
                let shared_workspace: *mut objc2::runtime::AnyObject =
                    msg_send![ns_workspace_cls, sharedWorkspace];
                if !shared_workspace.is_null() {
                    let frontmost_app: *mut objc2::runtime::AnyObject =
                        msg_send![shared_workspace, frontmostApplication];
                    if !frontmost_app.is_null() {
                        let _: () = msg_send![frontmost_app, hide];
                    }
                }
            }
        }
    }

    fn focus_appguard(&self) {
        unsafe {
            if let Some(ns_app_cls) = AnyClass::get(c"NSApplication") {
                let shared_app: *mut objc2::runtime::AnyObject =
                    msg_send![ns_app_cls, sharedApplication];
                if !shared_app.is_null() {
                    let _: () = msg_send![shared_app, activateIgnoringOtherApps: true];
                }
            }
        }
    }

    fn get_keychain_secret(&self, service: &str, account: &str) -> Option<String> {
        let output = Command::new("security")
            .args(["find-generic-password", "-a", account, "-s", service, "-w"])
            .output()
            .ok()?;
        if output.status.success() {
            let secret = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !secret.is_empty() {
                return Some(secret);
            }
        }
        None
    }

    fn store_keychain_secret(&self, service: &str, account: &str, secret: &str) -> Result<(), String> {
        let res = Command::new("security")
            .args(["add-generic-password", "-a", account, "-s", service, "-w", secret, "-U"])
            .output()
            .map_err(|e| e.to_string())?;
        if res.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&res.stderr).to_string())
        }
    }

    fn shield_folder(&self, folder_path: &str) -> Result<(), String> {
        let _ = Command::new("chflags").arg("hidden").arg(folder_path).status();
        let status = Command::new("chmod").arg("000").arg(folder_path).status()
            .map_err(|e| e.to_string())?;
        if status.success() {
            Ok(())
        } else {
            Err("Failed to set chmod 000".into())
        }
    }

    fn unshield_folder(&self, folder_path: &str) -> Result<(), String> {
        let _ = Command::new("chmod").arg("755").arg(folder_path).status();
        let _ = Command::new("chflags").arg("nohidden").arg(folder_path).status();
        Ok(())
    }

    fn enable_tamper_protection(&self, app_path: &str) -> Result<(), String> {
        // Registers a launchd User Agent (~/Library/LaunchAgents/com.appguard.watchdog.plist) with KeepAlive = true
        let home = std::env::var("HOME").map_err(|e| e.to_string())?;
        let launch_agents_dir = std::path::PathBuf::from(home).join("Library").join("LaunchAgents");
        let _ = std::fs::create_dir_all(&launch_agents_dir);
        let plist_path = launch_agents_dir.join("com.appguard.watchdog.plist");

        // Binary inside app bundle or standalone executable
        let exec_path = if app_path.ends_with(".app") {
            format!("{app_path}/Contents/MacOS/appguard")
        } else if app_path.contains("/Contents/MacOS/") {
            app_path.to_string()
        } else if std::path::Path::new("/Applications/AppGuard.app/Contents/MacOS/appguard").exists() {
            "/Applications/AppGuard.app/Contents/MacOS/appguard".to_string()
        } else {
            app_path.to_string()
        };

        let plist_content = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.appguard.watchdog</string>
    <key>AssociatedBundleIdentifiers</key>
    <array>
        <string>com.appguard.desktop</string>
    </array>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>--minimized</string>
    </array>
    <key>KeepAlive</key>
    <true/>
    <key>RunAtLoad</key>
    <false/>
    <key>ProcessType</key>
    <string>Interactive</string>
</dict>
</plist>"#,
            exec_path
        );

        std::fs::write(&plist_path, plist_content).map_err(|e| e.to_string())?;

        // Unload first if previously loaded, then load
        let _ = Command::new("launchctl")
            .args(["unload", &plist_path.to_string_lossy()])
            .status();

        let status = Command::new("launchctl")
            .args(["load", "-w", &plist_path.to_string_lossy()])
            .status()
            .map_err(|e| e.to_string())?;

        if status.success() {
            Ok(())
        } else {
            Err("Failed to register launchd watchdog agent".into())
        }
    }

    fn disable_tamper_protection(&self) -> Result<(), String> {
        let home = std::env::var("HOME").map_err(|e| e.to_string())?;
        let plist_path = std::path::PathBuf::from(home)
            .join("Library")
            .join("LaunchAgents")
            .join("com.appguard.watchdog.plist");

        if plist_path.exists() {
            let _ = Command::new("launchctl")
                .args(["unload", "-w", &plist_path.to_string_lossy()])
                .status();
            let _ = std::fs::remove_file(plist_path);
        }
        Ok(())
    }
}
