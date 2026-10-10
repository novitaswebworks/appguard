#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "windows")]
pub mod windows;

use std::sync::Arc;

#[cfg(target_os = "linux")]
pub use linux::LinuxPlatformOps;
#[cfg(target_os = "macos")]
pub use macos::MacPlatformOps;
#[cfg(target_os = "windows")]
pub use windows::WindowsPlatformOps;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformBiometricStatus {
    pub is_available: bool,
    pub biometric_type: String, // "TouchID", "FaceID", "WindowsHello", "PAM", "SystemPassword", or "PIN"
    pub has_system_passcode: bool,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrontmostAppInfo {
    pub id: String, // bundle_id on macOS, exe name / window title on Windows, wm_class on Linux
    pub name: String,
}

/// Abstract hardware, windowing, and keychain capabilities across macOS, Windows, and Linux
pub trait PlatformOps: Send + Sync {
    /// Detects availability of biometric sensors or OS authentication
    fn check_biometrics(&self) -> PlatformBiometricStatus;

    /// Invokes native OS biometric or credentials verification prompt
    fn authenticate_biometrics(&self, reason: &str) -> Result<bool, String>;

    /// Queries the currently active foreground application window
    fn get_frontmost_app(&self) -> Option<FrontmostAppInfo>;

    /// Hides or minimizes the targeted unauthorized application window
    fn hide_application(&self, app_id: &str);

    /// Activates and pulls AppGuard window to the top
    fn focus_appguard(&self);

    /// Securely retrieves a salt or master secret from OS credential store
    fn get_keychain_secret(&self, service: &str, account: &str) -> Option<String>;

    /// Stores a secret into the OS credential store (Keychain / Credential Manager / Secret Service)
    fn store_keychain_secret(&self, service: &str, account: &str, secret: &str) -> Result<(), String>;

    /// Applies OS-level folder shield (hidden attribute, access permissions)
    fn shield_folder(&self, folder_path: &str) -> Result<(), String>;

    /// Unshields the protected folder, restoring normal explorer access
    fn unshield_folder(&self, folder_path: &str) -> Result<(), String>;

    /// Registers background watchdog daemon with OS (launchd KeepAlive / Windows AutoRestart Service / systemd Restart=always)
    fn enable_tamper_protection(&self, app_path: &str) -> Result<(), String>;

    /// Disables background watchdog daemon with authorization
    fn disable_tamper_protection(&self) -> Result<(), String>;
}

/// Returns the singleton PlatformOps provider for the current operating system
pub fn get_platform() -> Arc<dyn PlatformOps> {
    #[cfg(target_os = "macos")]
    {
        Arc::new(MacPlatformOps::new())
    }

    #[cfg(target_os = "windows")]
    {
        Arc::new(WindowsPlatformOps::new())
    }

    #[cfg(target_os = "linux")]
    {
        Arc::new(LinuxPlatformOps::new())
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        Arc::new(MacPlatformOps::new())
    }
}
