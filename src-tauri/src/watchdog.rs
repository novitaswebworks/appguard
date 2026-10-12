use crate::state::SecurityManager;
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};

#[derive(Clone, serde::Serialize)]
pub struct Capability {
    pub available: bool,
    pub message: String,
}

pub fn capability() -> Capability {
    #[cfg(target_os = "linux")]
    {
        if std::env::var("XDG_SESSION_TYPE").is_ok_and(|value| value == "wayland")
            || std::env::var_os("WAYLAND_DISPLAY").is_some()
        {
            return Capability { available: false, message: "Native Wayland window shielding needs a compositor integration. Application discovery and vaults remain available.".into() };
        }
        if std::env::var_os("DISPLAY").is_none() || linux_command(&["getmouselocation"]).is_none() {
            return Capability { available: false, message: "X11 shielding is unavailable. Install xdotool and run AppGuard in an X11 desktop session.".into() };
        }
        if !std::process::Command::new("xprop")
            .args(["-root", "WM_CLASS"])
            .output()
            .is_ok_and(|output| output.status.success())
        {
            return Capability { available: false, message: "X11 identity detection needs xprop (provided by your distribution's X11 utilities package).".into() };
        }
    }
    Capability { available: true, message: "Best-effort window shielding. Applications may render before polling detects them; this does not prevent process execution.".into() }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn show_challenge(app: &AppHandle, target: &crate::session::Target) {
    if let Some(main) = app.get_webview_window("main") {
        let _ = main.hide();
    }
    if let Some(auth) = app.get_webview_window("auth") {
        let _ = auth.show();
        let _ = auth.unminimize();
        let _ = auth.set_always_on_top(true);
        let _ = auth.set_focus();
    }
    let _ = app.emit("app-locked-triggered", target);
}

#[cfg(target_os = "macos")]
pub fn start_focus_watchdog(app_handle: AppHandle, security: Arc<SecurityManager>) {
    use objc2::msg_send;
    use objc2::runtime::AnyClass;
    use objc2_foundation::NSString;

    std::thread::spawn(move || {
        let mut last_bundle = String::new();

        let my_pid = std::process::id() as i32;

        loop {
            std::thread::sleep(Duration::from_millis(150));
            if security.ensure_ready().is_err() {
                continue;
            }
            let _windows = security.window_lock.lock();

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

                let proc_pid: i32 = msg_send![frontmost_app, processIdentifier];
                if proc_pid == my_pid {
                    if security.challenge.lock().get().is_none() && !last_bundle.is_empty() {
                        security.relock_on_focus_loss(&last_bundle);
                        last_bundle.clear();
                    }
                    continue;
                }

                let bundle_id_ns: *mut NSString = msg_send![frontmost_app, bundleIdentifier];
                let current_bundle = if !bundle_id_ns.is_null() {
                    (*bundle_id_ns).to_string()
                } else {
                    String::new()
                };

                // When AppGuard bundle or empty, skip
                if current_bundle == "com.appguard.desktop" || current_bundle.is_empty() {
                    last_bundle = current_bundle;
                    continue;
                }

                if current_bundle != last_bundle && !last_bundle.is_empty() {
                    security.relock_on_focus_loss(&last_bundle);
                }
                last_bundle = current_bundle.clone();

                if security.is_app_locked(&current_bundle) {
                    let name_ns: *mut NSString = msg_send![frontmost_app, localizedName];
                    let app_name = if !name_ns.is_null() {
                        (*name_ns).to_string()
                    } else {
                        current_bundle.clone()
                    };

                    // Immediately hide the unauthorized locked application from screen!
                    let _: () = msg_send![frontmost_app, hide];

                    // Record pending locked target in SecurityManager so CompactAuthPanel can query it synchronously
                    let target = security.challenge.lock().set(
                        current_bundle.clone(),
                        app_name.clone(),
                        None,
                    );

                    // Explicitly hide the main dashboard window so it never interrupts the user
                    if let Some(main_win) = app_handle.get_webview_window("main") {
                        let _ = main_win.set_always_on_top(false);
                        let _ = main_win.hide();
                    }

                    // Show and bring only the compact 'auth' floating window to top
                    if let Some(auth_win) = app_handle.get_webview_window("auth") {
                        let _ = auth_win.show();
                        let _ = auth_win.unminimize();
                        let _ = auth_win.set_always_on_top(true);
                        let _ = auth_win.set_focus();

                        // Force macOS App Activation to steal focus over the locked app
                        if let Some(ns_app_cls) = AnyClass::get(c"NSApplication") {
                            let shared_app: *mut objc2::runtime::AnyObject =
                                msg_send![ns_app_cls, sharedApplication];
                            if !shared_app.is_null() {
                                let _: () = msg_send![shared_app, activateIgnoringOtherApps: true];
                            }
                        }
                    }

                    // Emit locked app event to frontend
                    let _ = app_handle.emit("app-locked-triggered", target);
                }
            }
        }
    });
}

#[cfg(target_os = "linux")]
pub fn start_focus_watchdog(app_handle: AppHandle, security: Arc<SecurityManager>) {
    use std::process::Command;

    if !capability().available {
        return;
    }
    std::thread::spawn(move || {
        let mut last_window = String::new();
        let mut last_bundle = String::new();

        loop {
            std::thread::sleep(Duration::from_millis(250));
            if security.ensure_ready().is_err() {
                continue;
            }
            let _windows = security.window_lock.lock();

            let Some(window) = linux_active_window() else {
                continue;
            };
            if window.id.is_empty() || window.is_appguard() {
                if security.challenge.lock().get().is_none() && !last_bundle.is_empty() {
                    security.relock_on_focus_loss(&last_bundle);
                    last_bundle.clear();
                }
                continue;
            }

            if window.id != last_window {
                if !last_bundle.is_empty() {
                    security.relock_on_focus_loss(&last_bundle);
                }
                last_window = window.id.clone();
            }

            let locked_match = {
                let cfg = security.config.read();
                cfg.locked_apps.values().find_map(|rule| {
                    if rule.is_locked && linux_window_matches_rule(&window, rule) {
                        Some((rule.bundle_id.clone(), rule.name.clone()))
                    } else {
                        None
                    }
                })
            };

            if let Some((target_bundle, target_name)) = locked_match {
                last_bundle = target_bundle.clone();
                if security.is_app_locked(&target_bundle) {
                    // Minimize the exact unauthorized window, not whichever
                    // window happens to be focused after the auth panel opens.
                    let _ = Command::new("xdotool")
                        .args(["windowminimize", &window.id])
                        .status();

                    let target = security.challenge.lock().set(
                        target_bundle.clone(),
                        target_name.clone(),
                        Some(window.id.clone()),
                    );

                    let _ = app_handle.emit("app-locked-triggered", target);

                    if let Some(main_win) = app_handle.get_webview_window("main") {
                        let _ = main_win.set_always_on_top(false);
                        let _ = main_win.hide();
                    }

                    if let Some(auth_win) = app_handle.get_webview_window("auth") {
                        let _ = auth_win.show();
                        let _ = auth_win.unminimize();
                        let _ = auth_win.set_always_on_top(true);
                        let _ = auth_win.set_focus();
                    }
                }
            } else {
                last_bundle.clear();
            }
        }
    });
}

#[cfg(target_os = "linux")]
pub fn enforce_linux_lock_all(app: &AppHandle, security: &SecurityManager) {
    let Some(window) = linux_active_window() else {
        return;
    };
    let target = {
        let cfg = security.config.read();
        cfg.locked_apps.values().find_map(|rule| {
            if rule.is_locked && linux_window_matches_rule(&window, rule) {
                Some((rule.bundle_id.clone(), rule.name.clone()))
            } else {
                None
            }
        })
    };
    if let Some((bundle_id, name)) = target {
        let _ = std::process::Command::new("xdotool")
            .args(["windowminimize", &window.id])
            .status();
        let target = security
            .challenge
            .lock()
            .set(bundle_id, name, Some(window.id));
        show_challenge(app, &target);
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct LinuxWindow {
    id: String,
    wm_classes: Vec<String>,
    executable: Option<String>,
    pid: Option<u32>,
}

#[cfg(target_os = "linux")]
impl LinuxWindow {
    fn is_appguard(&self) -> bool {
        self.pid == Some(std::process::id())
    }
}

#[cfg(target_os = "linux")]
fn linux_command(args: &[&str]) -> Option<String> {
    let output = std::process::Command::new("xdotool")
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!value.is_empty()).then_some(value)
}

#[cfg(target_os = "linux")]
fn linux_active_window() -> Option<LinuxWindow> {
    let id = linux_command(&["getactivewindow"])?;
    // xdotool has no getwindowclassname command. Read both WM_CLASS values
    // with xprop; neither the window title nor its contents are identities.
    let wm_classes = std::process::Command::new("xprop")
        .args(["-id", &id, "WM_CLASS"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| {
            String::from_utf8_lossy(&output.stdout)
                .split('"')
                .skip(1)
                .step_by(2)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let pid = linux_command(&["getwindowpid", &id]);
    let executable = pid.as_deref().and_then(|pid| {
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|path| path.to_string_lossy().to_string())
    });

    Some(LinuxWindow {
        id,
        wm_classes,
        executable,
        pid: pid.and_then(|value| value.parse().ok()),
    })
}

#[cfg(target_os = "linux")]
fn linux_window_matches_rule(window: &LinuxWindow, rule: &crate::state::AppRule) -> bool {
    let id = rule
        .bundle_id
        .strip_suffix(".desktop")
        .unwrap_or(&rule.bundle_id);
    let class_match = window.wm_classes.iter().any(|class| {
        !class.is_empty()
            && (class.eq_ignore_ascii_case(id)
                || rule
                    .startup_wm_class
                    .as_ref()
                    .is_some_and(|expected| class.eq_ignore_ascii_case(expected)))
    });
    if class_match {
        return true;
    }
    let Some(expected) = rule.exec_path.as_deref() else {
        return false;
    };
    let name = std::path::Path::new(expected)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if matches!(
        name,
        "flatpak" | "snap" | "env" | "sh" | "bash" | "python" | "python3" | "java"
    ) {
        return false;
    }
    window.executable.as_ref().is_some_and(|actual| {
        if std::path::Path::new(expected).is_absolute() {
            std::fs::canonicalize(expected).is_ok_and(|path| path == std::path::Path::new(actual))
        } else {
            std::path::Path::new(actual)
                .file_name()
                .is_some_and(|actual| actual == expected)
        }
    })
}

#[cfg(target_os = "windows")]
pub fn start_focus_watchdog(app_handle: AppHandle, security: Arc<SecurityManager>) {
    std::thread::spawn(move || {
        let mut last_process = String::new();

        loop {
            std::thread::sleep(Duration::from_millis(250));
            if security.ensure_ready().is_err() {
                continue;
            }
            let _windows = security.window_lock.lock();
            let Some((proc_name, window_handle, pid)) = windows_active_process() else {
                continue;
            };
            let exe_bundle = format!("{}.exe", proc_name.to_lowercase());
            if proc_name.is_empty() || pid == std::process::id() {
                if security.challenge.lock().get().is_none() && !last_process.is_empty() {
                    security.relock_on_focus_loss(&last_process);
                    last_process.clear();
                }
                continue;
            }

            if exe_bundle != last_process {
                if !last_process.is_empty() {
                    security.relock_on_focus_loss(&last_process);
                }
                last_process = exe_bundle.clone();
            }

            if security.is_app_locked(&exe_bundle) {
                let target = security.challenge.lock().set(
                    exe_bundle.clone(),
                    proc_name.clone(),
                    Some(window_handle.clone()),
                );
                windows_show_window(&window_handle, false);
                let _ = app_handle.emit("app-locked-triggered", target);

                if let Some(main_win) = app_handle.get_webview_window("main") {
                    let _ = main_win.set_always_on_top(false);
                    let _ = main_win.hide();
                }

                if let Some(auth_win) = app_handle.get_webview_window("auth") {
                    let _ = auth_win.show();
                    let _ = auth_win.unminimize();
                    let _ = auth_win.set_always_on_top(true);
                    let _ = auth_win.set_focus();
                }
            }
        }
    });
}

#[cfg(target_os = "windows")]
fn windows_active_process() -> Option<(String, String, u32)> {
    let script = r#"$sig='[DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);';Add-Type -MemberDefinition $sig -Name AppGuardWindow -Namespace AppGuard; $hwnd=[AppGuard.AppGuardWindow]::GetForegroundWindow(); [uint32]$processId=0;[void][AppGuard.AppGuardWindow]::GetWindowThreadProcessId($hwnd,[ref]$processId);$p=Get-Process -Id $processId -ErrorAction SilentlyContinue;if($p){"$($p.ProcessName)|$hwnd|$processId"}"#;
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let mut parts = value.split('|');
    Some((
        parts.next()?.to_string(),
        parts.next()?.to_string(),
        parts.next()?.parse().ok()?,
    ))
}

#[cfg(target_os = "windows")]
pub fn enforce_windows_lock_all(app: &AppHandle, security: &SecurityManager) {
    let Some((name, window, pid)) = windows_active_process() else {
        return;
    };
    if pid == std::process::id() {
        return;
    }
    let id = format!("{}.exe", name.to_lowercase());
    if security.is_app_locked(&id) {
        windows_show_window(&window, false);
        let target = security.challenge.lock().set(id, name, Some(window));
        show_challenge(app, &target);
    }
}

#[cfg(target_os = "windows")]
pub fn windows_show_window(handle: &str, restore: bool) {
    let command = r#"$sig='[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);[DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);';Add-Type -MemberDefinition $sig -Name AppGuardControl -Namespace AppGuard; $h=[IntPtr]::new([Int64]$env:APPGUARD_HWND);[AppGuard.AppGuardControl]::ShowWindow($h,[Int32]$env:APPGUARD_SHOW);if([Int32]$env:APPGUARD_SHOW -eq 9){[AppGuard.AppGuardControl]::SetForegroundWindow($h)}"#;
    let _ = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", command])
        .env("APPGUARD_HWND", handle)
        .env("APPGUARD_SHOW", if restore { "9" } else { "6" })
        .status();
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn start_focus_watchdog(_app_handle: AppHandle, _security: Arc<SecurityManager>) {
    // Unsupported platform stub
}
