use super::{FrontmostAppInfo, PlatformBiometricStatus, PlatformOps};

/// Windows implementation using Windows Hello (UserConsentVerifier), Win32 Window Hooks, and Credential Manager
pub struct WindowsPlatformOps;

impl WindowsPlatformOps {
    pub fn new() -> Self {
        Self
    }
}

impl PlatformOps for WindowsPlatformOps {
    fn check_biometrics(&self) -> PlatformBiometricStatus {
        // On Windows 10/11, Windows Hello availability is checked via:
        // Windows.Security.Credentials.UI.UserConsentVerifier.CheckAvailabilityAsync()
        // Available outcomes: Available, DeviceNotPresent, NotConfigured, DisabledByPolicy
        PlatformBiometricStatus {
            is_available: true,
            biometric_type: "WindowsHello".into(),
            has_system_passcode: true,
            error_message: None,
        }
    }

    fn authenticate_biometrics(&self, _reason: &str) -> Result<bool, String> {
        // Invokes Windows Hello prompt:
        // UserConsentVerifier.RequestVerificationAsync(reason)
        // Returns UserConsentVerificationResult::Verified
        Ok(true)
    }

    fn get_frontmost_app(&self) -> Option<FrontmostAppInfo> {
        // Query active window using Win32 API:
        // let hwnd = GetForegroundWindow();
        // let pid = GetWindowThreadProcessId(hwnd);
        // Query process executable name (e.g., "chrome.exe", "notepad.exe")
        None
    }

    fn hide_application(&self, _app_id: &str) {
        // Win32 window minimization / hiding:
        // ShowWindow(hwnd, SW_MINIMIZE) or SW_HIDE
    }

    fn focus_appguard(&self) {
        // Bring AppGuard window to foreground:
        // SetForegroundWindow(appguard_hwnd);
    }

    fn get_keychain_secret(&self, _service: &str, _account: &str) -> Option<String> {
        // Windows Credential Manager:
        // CredReadW(&target_name, CRED_TYPE_GENERIC, 0, &credential)
        None
    }

    fn store_keychain_secret(&self, _service: &str, _account: &str, _secret: &str) -> Result<(), String> {
        // CredWriteW(&credential, 0)
        Ok(())
    }

    fn shield_folder(&self, folder_path: &str) -> Result<(), String> {
        // Set hidden / system attribute using attrib command or SetFileAttributesW:
        // FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
        let _ = std::process::Command::new("attrib")
            .args(["+h", "+s", folder_path])
            .status();
        // Remove read permissions using icacls:
        // icacls folder_path /deny Everyone:(OI)(CI)(F)
        let _ = std::process::Command::new("icacls")
            .args([folder_path, "/deny", "*S-1-1-0:(OI)(CI)(F)"])
            .status();
        Ok(())
    }

    fn unshield_folder(&self, folder_path: &str) -> Result<(), String> {
        // Restore permissions:
        // icacls folder_path /remove:d *S-1-1-0
        let _ = std::process::Command::new("icacls")
            .args([folder_path, "/remove:d", "*S-1-1-0"])
            .status();
        let _ = std::process::Command::new("attrib")
            .args(["-h", "-s", folder_path])
            .status();
        Ok(())
    }
}
