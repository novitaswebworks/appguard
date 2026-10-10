use super::{FrontmostAppInfo, PlatformBiometricStatus, PlatformOps};
use std::process::Command;

/// Linux implementation supporting PAM (password/fprintd), X11/Wayland windowing, and Secret Service
pub struct LinuxPlatformOps;

impl LinuxPlatformOps {
    pub fn new() -> Self {
        Self
    }
}

impl PlatformOps for LinuxPlatformOps {
    fn check_biometrics(&self) -> PlatformBiometricStatus {
        // Check for libfprint / fprintd biometric daemon or PAM presence
        let has_fprintd = Command::new("which")
            .arg("fprintd-verify")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        PlatformBiometricStatus {
            is_available: true,
            biometric_type: if has_fprintd { "PAM/Fingerprint".into() } else { "SystemPassword".into() },
            has_system_passcode: true,
            error_message: None,
        }
    }

    fn authenticate_biometrics(&self, reason: &str) -> Result<bool, String> {
        // Authenticate via pkexec / sudo / PAM helper or fprintd:
        // Try polkit / pkexec verification
        let status = Command::new("pkexec")
            .args(["echo", reason])
            .status();

        match status {
            Ok(s) if s.success() => Ok(true),
            _ => Err("PAM authentication failed or cancelled".into()),
        }
    }

    fn get_frontmost_app(&self) -> Option<FrontmostAppInfo> {
        // X11 detection via xdotool or xprop:
        // xdotool getactivewindow getwindowpid
        // Wayland detection via org.gnome.Shell or KWin D-Bus interface
        if let Ok(output) = Command::new("xdotool").args(["getwindowfocus", "getwindowname"]).output() {
            if output.status.success() {
                let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !name.is_empty() {
                    return Some(FrontmostAppInfo {
                        id: name.clone(),
                        name,
                    });
                }
            }
        }
        None
    }

    fn hide_application(&self, _app_id: &str) {
        // X11: xdotool getactivewindow windowminimize
        let _ = Command::new("xdotool")
            .args(["getwindowfocus", "windowminimize"])
            .status();
    }

    fn focus_appguard(&self) {
        // Bring AppGuard window forward:
        // wmctrl -x -a appguard
        let _ = Command::new("wmctrl")
            .args(["-x", "-a", "appguard"])
            .status();
    }

    fn get_keychain_secret(&self, service: &str, account: &str) -> Option<String> {
        // Secret Service API via secret-tool (libsecret):
        // secret-tool lookup service <service> account <account>
        let output = Command::new("secret-tool")
            .args(["lookup", "service", service, "account", account])
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
        // secret-tool store --label="AppGuard Secret" service <service> account <account>
        use std::io::Write;
        let mut child = Command::new("secret-tool")
            .args(["store", "--label=AppGuard Secret", "service", service, "account", account])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())?;

        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(secret.as_bytes());
        }
        let status = child.wait().map_err(|e| e.to_string())?;
        if status.success() {
            Ok(())
        } else {
            Err("Failed to save secret to Secret Service".into())
        }
    }

    fn shield_folder(&self, folder_path: &str) -> Result<(), String> {
        // On Linux: chmod 000 blocks directory listing and access
        let status = Command::new("chmod")
            .arg("000")
            .arg(folder_path)
            .status()
            .map_err(|e| e.to_string())?;
        if status.success() {
            Ok(())
        } else {
            Err("chmod 000 failed".into())
        }
    }

    fn unshield_folder(&self, folder_path: &str) -> Result<(), String> {
        let _ = Command::new("chmod")
            .arg("755")
            .arg(folder_path)
            .status();
        Ok(())
    }
}
