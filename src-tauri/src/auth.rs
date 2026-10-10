use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiometricStatus {
    pub is_available: bool,
    pub biometric_type: String, // "TouchID", "FaceID", "SystemPasscode", "WindowsHello", or "PIN"
    pub has_system_passcode: bool,
    pub error_message: Option<String>,
}

#[cfg(target_os = "macos")]
mod macos {
    use super::BiometricStatus;
    use block2::RcBlock;
    use objc2::msg_send;
    use objc2::runtime::{AnyClass, Bool};
    use objc2_foundation::NSString;
    use std::sync::mpsc::channel;

    pub fn check_biometrics() -> BiometricStatus {
        unsafe {
            let la_context_class = match AnyClass::get(c"LAContext") {
                Some(cls) => cls,
                None => {
                    return BiometricStatus {
                        is_available: false,
                        biometric_type: "None".into(),
                        has_system_passcode: false,
                        error_message: Some("LocalAuthentication framework not found".into()),
                    };
                }
            };

            let context: *mut objc2::runtime::AnyObject = msg_send![la_context_class, new];
            if context.is_null() {
                return BiometricStatus {
                    is_available: false,
                    biometric_type: "None".into(),
                    has_system_passcode: false,
                    error_message: Some("Failed to allocate LAContext".into()),
                };
            }

            // LAPolicyDeviceOwnerAuthenticationWithBiometrics = 1
            // LAPolicyDeviceOwnerAuthentication (Biometrics + Mac Password fallback) = 2
            let mut bio_error: *mut objc2::runtime::AnyObject = std::ptr::null_mut();
            let can_evaluate_bio: Bool = msg_send![context, canEvaluatePolicy: 1isize, error: &mut bio_error];

            let mut pass_error: *mut objc2::runtime::AnyObject = std::ptr::null_mut();
            let can_evaluate_passcode: Bool = msg_send![context, canEvaluatePolicy: 2isize, error: &mut pass_error];
            let has_system_passcode = can_evaluate_passcode.as_bool();

            if can_evaluate_bio.as_bool() {
                // LABiometryType: 0=None, 1=TouchID, 2=FaceID, 3=OpticID
                let biometry_type: isize = msg_send![context, biometryType];
                let b_type = match biometry_type {
                    1 => "TouchID",
                    2 => "FaceID",
                    _ => "TouchID",
                };
                BiometricStatus {
                    is_available: true,
                    biometric_type: b_type.into(),
                    has_system_passcode,
                    error_message: None,
                }
            } else if has_system_passcode {
                // Mac without Touch ID hardware, but has system login password enrolled
                BiometricStatus {
                    is_available: true,
                    biometric_type: "SystemPassword".into(),
                    has_system_passcode: true,
                    error_message: None,
                }
            } else {
                BiometricStatus {
                    is_available: false,
                    biometric_type: "PIN".into(),
                    has_system_passcode: false,
                    error_message: Some("No biometric hardware or system passcode enrolled. Master PIN will be used.".into()),
                }
            }
        }
    }

    pub fn authenticate(reason: &str) -> Result<bool, String> {
        unsafe {
            let la_context_class = AnyClass::get(c"LAContext")
                .ok_or_else(|| "LocalAuthentication not available".to_string())?;

            let context: *mut objc2::runtime::AnyObject = msg_send![la_context_class, new];
            if context.is_null() {
                return Err("Failed to create LAContext".into());
            }

            let reason_ns = NSString::from_str(reason);
            let (tx, rx) = channel::<Result<bool, String>>();

            // LAPolicyDeviceOwnerAuthentication (allows Touch ID or device password fallback) = 2
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
}

#[cfg(not(target_os = "macos"))]
mod fallback {
    use super::BiometricStatus;

    pub fn check_biometrics() -> BiometricStatus {
        BiometricStatus {
            is_available: false,
            biometric_type: "MasterPIN".into(),
            has_system_passcode: false,
            error_message: Some("Native biometrics fallback to Master PIN on this platform".into()),
        }
    }

    pub fn authenticate(_reason: &str) -> Result<bool, String> {
        // Fallback platform returns true if delegating to master PIN verification in app
        Ok(true)
    }
}

pub fn check_biometrics() -> BiometricStatus {
    #[cfg(target_os = "macos")]
    {
        macos::check_biometrics()
    }
    #[cfg(not(target_os = "macos"))]
    {
        fallback::check_biometrics()
    }
}

pub fn authenticate(reason: &str) -> Result<bool, String> {
    #[cfg(target_os = "macos")]
    {
        macos::authenticate(reason)
    }
    #[cfg(not(target_os = "macos"))]
    {
        fallback::authenticate(reason)
    }
}
