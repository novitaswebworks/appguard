use super::{FrontmostAppInfo, PlatformBiometricStatus, PlatformOps};
use std::process::Command;

/// Linux integration with PIN-only authentication, X11 tooling, and Secret Service.
/// Native Wayland window control requires compositor-specific integrations.
pub struct LinuxPlatformOps;

impl LinuxPlatformOps {
    pub fn new() -> Self {
        Self
    }
}

impl PlatformOps for LinuxPlatformOps {
    fn check_biometrics(&self) -> PlatformBiometricStatus {
        PlatformBiometricStatus {
            is_available: false,
            biometric_type: "MasterPIN".into(),
            has_system_passcode: false,
            error_message: Some(
                "Native Linux PAM/fingerprint authentication is not enabled in this build".into(),
            ),
        }
    }

    fn authenticate_biometrics(&self, _reason: &str) -> Result<bool, String> {
        Err("Native Linux biometric authentication is not enabled in this build".into())
    }

    fn get_frontmost_app(&self) -> Option<FrontmostAppInfo> {
        // X11 detection via xdotool. Native Wayland does not provide a
        // compositor-independent equivalent for arbitrary application windows.
        if let Ok(output) = Command::new("xdotool")
            .args(["getwindowfocus", "getwindowname"])
            .output()
        {
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

    fn store_keychain_secret(
        &self,
        service: &str,
        account: &str,
        secret: &str,
    ) -> Result<(), String> {
        // secret-tool store --label="AppGuard Secret" service <service> account <account>
        use std::io::Write;
        let mut child = Command::new("secret-tool")
            .args([
                "store",
                "--label=AppGuard Secret",
                "service",
                service,
                "account",
                account,
            ])
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
        let _ = Command::new("chmod").arg("755").arg(folder_path).status();
        Ok(())
    }

    fn enable_tamper_protection(&self, app_path: &str) -> Result<(), String> {
        // Creates a systemd user service (~/.config/systemd/user/appguard.service) with Restart=always
        let home = std::env::var("HOME").map_err(|e| e.to_string())?;
        let user_service_dir = std::path::PathBuf::from(home)
            .join(".config")
            .join("systemd")
            .join("user");
        crate::storage::reject_symlinks(&user_service_dir)?;
        std::fs::create_dir_all(&user_service_dir).map_err(|e| e.to_string())?;
        let service_path = user_service_dir.join("appguard.service");

        let service_content = format!(
            r#"[Unit]
Description=AppGuard Window Shield Restart Service
After=graphical-session.target

[Service]
Type=simple
ExecStart={} --minimized
Restart=always
RestartSec=1
KillMode=process

[Install]
WantedBy=default.target
"#,
            super::service_config::systemd_executable(app_path)?
        );

        crate::storage::atomic_write(&service_path, service_content.as_bytes())?;

        // Reload systemd user daemon and enable + start the service
        let reload = Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status()
            .map_err(|e| e.to_string())?;
        if !reload.success() {
            return Err("systemd user daemon reload failed".into());
        }

        let status = Command::new("systemctl")
            .args(["--user", "enable", "--now", "appguard.service"])
            .status()
            .map_err(|e| e.to_string())?;

        if status.success() {
            Ok(())
        } else {
            Err("Failed to activate systemd watchdog service".into())
        }
    }

    fn disable_tamper_protection(&self) -> Result<(), String> {
        let _ = Command::new("systemctl")
            .args(["--user", "disable", "--now", "appguard.service"])
            .status();

        let home = std::env::var("HOME").map_err(|e| e.to_string())?;
        let service_path = std::path::PathBuf::from(home)
            .join(".config")
            .join("systemd")
            .join("user")
            .join("appguard.service");

        if service_path.exists() {
            let _ = std::fs::remove_file(service_path);
            let _ = Command::new("systemctl")
                .args(["--user", "daemon-reload"])
                .status();
        }
        Ok(())
    }
}
