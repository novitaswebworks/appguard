use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use std::collections::HashSet;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannedApp {
    pub name: String,
    pub bundle_id: String,
    pub path: String,
    pub icon_path: Option<String>,
    pub icon_base64: Option<String>,
    #[serde(default)]
    pub exec_path: Option<String>,
    #[serde(default)]
    pub startup_wm_class: Option<String>,
}

pub fn scan_installed_applications() -> Vec<ScannedApp> {
    let mut apps = Vec::new();

    #[cfg(target_os = "macos")]
    {
        let mut app_dirs = vec![
            std::path::PathBuf::from("/Applications"),
            std::path::PathBuf::from("/System/Applications"),
            std::path::PathBuf::from("/System/Applications/Utilities"),
        ];
        if let Ok(home) = std::env::var("HOME") {
            app_dirs.push(std::path::PathBuf::from(home).join("Applications"));
        }

        for dir in &app_dirs {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) == Some("app") {
                        if let Some(app) = parse_macos_app(&path) {
                            apps.push(app);
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        scan_linux_applications(&mut apps);
    }

    #[cfg(target_os = "windows")]
    {
        let mut win_dirs = Vec::new();

        if let Ok(progdata) = std::env::var("ProgramData") {
            win_dirs.push(
                std::path::PathBuf::from(progdata)
                    .join("Microsoft")
                    .join("Windows")
                    .join("Start Menu")
                    .join("Programs"),
            );
        }
        if let Ok(appdata) = std::env::var("APPDATA") {
            win_dirs.push(
                std::path::PathBuf::from(appdata)
                    .join("Microsoft")
                    .join("Windows")
                    .join("Start Menu")
                    .join("Programs"),
            );
        }

        for dir in win_dirs {
            scan_windows_start_menu_recursive(&dir, &mut apps);
        }
    }

    apps.sort_by(|a: &ScannedApp, b: &ScannedApp| {
        a.name.to_lowercase().cmp(&b.name.to_lowercase())
    });
    let mut seen = std::collections::HashSet::new();
    apps.retain(|app| seen.insert(app.bundle_id.clone()));
    apps
}

/// Resolve identity from native metadata, rather than guessing it in React.
pub fn inspect_application(path: &str) -> Result<ScannedApp, String> {
    let path = fs::canonicalize(path).map_err(|e| format!("Cannot resolve application: {e}"))?;
    #[cfg(target_os = "macos")]
    {
        let app = parse_macos_app(&path).ok_or("Select an application bundle (.app); standalone commands have no macOS window identity")?;
        if app.bundle_id == "com.appguard.desktop" {
            return Err("AppGuard cannot shield itself".into());
        }
        Ok(app)
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        if std::env::current_exe()
            .ok()
            .and_then(|p| fs::canonicalize(p).ok())
            .as_ref()
            == Some(&path)
        {
            return Err("AppGuard cannot shield itself".into());
        }
        if let Some(app) = scan_installed_applications()
            .into_iter()
            .find(|app| fs::canonicalize(&app.path).is_ok_and(|p| p == path))
        {
            return Ok(app);
        }
        if path.extension().is_some_and(|ext| ext == "desktop") {
            let mut app =
                parse_linux_desktop_file(&path).ok_or("Invalid or disabled desktop entry")?;
            use sha2::{Digest, Sha256};
            app.bundle_id = format!("manual:{:x}", Sha256::digest(app.path.as_bytes()));
            return Ok(app);
        }
        let metadata = fs::metadata(&path).map_err(|e| e.to_string())?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
            return Err("Select an executable file or desktop entry".into());
        }
        use sha2::{Digest, Sha256};
        let path = path
            .to_str()
            .ok_or("Application path is not valid Unicode")?
            .to_string();
        Ok(ScannedApp {
            name: Path::new(&path)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into(),
            bundle_id: format!("manual:{:x}", Sha256::digest(path.as_bytes())),
            exec_path: Some(path.clone()),
            path,
            icon_path: None,
            icon_base64: None,
            startup_wm_class: None,
        })
    }
    #[cfg(target_os = "windows")]
    {
        let target = if path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("lnk"))
        {
            resolve_windows_shortcut_target(&path).ok_or("Cannot resolve shortcut target")?
        } else {
            path.to_string_lossy().into_owned()
        };
        let executable = Path::new(&target);
        if !executable.is_file()
            || !executable
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
        {
            return Err("Select an executable or a shortcut to an executable".into());
        }
        let bundle_id = executable
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();
        if bundle_id == "appguard.exe" {
            return Err("AppGuard cannot shield itself".into());
        }
        Ok(ScannedApp {
            name: path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .into(),
            bundle_id,
            path: path.to_string_lossy().into(),
            exec_path: Some(target),
            icon_path: None,
            icon_base64: None,
            startup_wm_class: None,
        })
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    Err("Application discovery is unavailable on this platform".into())
}

#[cfg(target_os = "macos")]
fn parse_macos_app(path: &Path) -> Option<ScannedApp> {
    let info_plist = path.join("Contents").join("Info.plist");
    if !info_plist.exists() {
        return None;
    }

    let plist = plist::Value::from_file(&info_plist).ok()?;
    let dictionary = plist.as_dictionary()?;
    let plist_string = |key: &str| {
        dictionary
            .get(key)
            .and_then(|value| value.as_string())
            .map(str::to_string)
    };

    let bundle_id = plist_string("CFBundleIdentifier")?;
    let name = plist_string("CFBundleDisplayName")
        .or_else(|| plist_string("CFBundleName"))
        .unwrap_or_else(|| {
            path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("Unknown")
                .to_string()
        });

    let icon_file = plist_string("CFBundleIconFile");
    let icon_path = icon_file.and_then(|file_name| {
        let name_with_ext = if file_name.ends_with(".icns") {
            file_name
        } else {
            format!("{file_name}.icns")
        };
        let resources_path = path.join("Contents").join("Resources").join(name_with_ext);
        if resources_path.exists() {
            Some(resources_path.to_string_lossy().to_string())
        } else {
            None
        }
    });

    let icon_base64 = icon_path
        .as_ref()
        .and_then(|p| get_icon_png_base64(&bundle_id, p));

    Some(ScannedApp {
        name,
        bundle_id,
        path: path.to_string_lossy().to_string(),
        icon_path,
        icon_base64,
        exec_path: None,
        startup_wm_class: None,
    })
}

#[cfg(target_os = "macos")]
fn get_icon_png_base64(bundle_id: &str, icns_path: &str) -> Option<String> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use std::path::PathBuf;
    use std::process::Command;

    let home = std::env::var("HOME")
        .ok()
        .or_else(|| std::env::var("USERPROFILE").ok())?;
    let cache_dir = PathBuf::from(home)
        .join(".cache")
        .join("appguard")
        .join("icons");
    let _ = fs::create_dir_all(&cache_dir);
    let safe_id = bundle_id.replace(|c: char| !c.is_alphanumeric() && c != '.', "_");
    let cached_png = cache_dir.join(format!("{safe_id}.png"));

    if cached_png.exists() {
        if let Ok(bytes) = fs::read(&cached_png) {
            return Some(format!("data:image/png;base64,{}", BASE64.encode(&bytes)));
        }
    }

    let output = Command::new("/usr/bin/sips")
        .args(["-s", "format", "png", "-z", "64", "64", icns_path, "--out"])
        .arg(&cached_png)
        .output();

    if let Ok(res) = output {
        if res.status.success() && cached_png.exists() {
            if let Ok(bytes) = fs::read(&cached_png) {
                return Some(format!("data:image/png;base64,{}", BASE64.encode(&bytes)));
            }
        }
    }

    None
}

#[cfg(target_os = "linux")]
fn scan_linux_applications(apps: &mut Vec<ScannedApp>) {
    let mut seen_desktop_ids = HashSet::new();
    let mut visited_directories = HashSet::new();

    for dir in linux_application_dirs() {
        scan_linux_dir_recursive(
            &dir,
            &dir,
            apps,
            &mut seen_desktop_ids,
            &mut visited_directories,
        );
    }
}

#[cfg(target_os = "linux")]
fn linux_application_dirs() -> Vec<std::path::PathBuf> {
    let mut dirs = Vec::new();
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let data_home = std::env::var_os("XDG_DATA_HOME")
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| home.clone().map(|path| path.join(".local").join("share")));

    if let Some(data_home) = &data_home {
        dirs.push(data_home.join("applications"));
        dirs.push(
            data_home
                .join("flatpak")
                .join("exports")
                .join("share")
                .join("applications"),
        );
    }

    let data_dirs = std::env::var("XDG_DATA_DIRS")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "/usr/local/share:/usr/share".to_string());
    for base in data_dirs
        .split(':')
        .filter(|base| Path::new(base).is_absolute())
    {
        dirs.push(std::path::PathBuf::from(base).join("applications"));
    }

    // Package managers export launchers in these locations. They supplement
    // XDG_DATA_DIRS for sessions that do not expose the export directory.
    dirs.push(std::path::PathBuf::from(
        "/var/lib/flatpak/exports/share/applications",
    ));
    dirs.push(std::path::PathBuf::from(
        "/var/lib/snapd/desktop/applications",
    ));
    dirs.push(std::path::PathBuf::from(
        "/usr/share/kali-menu/applications",
    ));

    let mut unique = HashSet::new();
    dirs.retain(|dir| unique.insert(dir.clone()));
    dirs
}

#[cfg(target_os = "linux")]
fn scan_linux_dir_recursive(
    root: &Path,
    dir: &Path,
    apps: &mut Vec<ScannedApp>,
    seen_desktop_ids: &mut HashSet<String>,
    visited_directories: &mut HashSet<std::path::PathBuf>,
) {
    let canonical_dir = match fs::canonicalize(dir) {
        Ok(path) => path,
        Err(_) => return,
    };
    if !visited_directories.insert(canonical_dir) {
        return;
    }

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                scan_linux_dir_recursive(root, &path, apps, seen_desktop_ids, visited_directories);
            } else if path.extension().and_then(|s| s.to_str()) == Some("desktop") {
                let desktop_id = path
                    .strip_prefix(root)
                    .ok()
                    .map(|relative| {
                        relative
                            .components()
                            .map(|component| component.as_os_str().to_string_lossy())
                            .collect::<Vec<_>>()
                            .join("-")
                    })
                    .unwrap_or_else(|| path.to_string_lossy().to_string());

                if seen_desktop_ids.insert(desktop_id.clone()) {
                    if let Some(mut app) = parse_linux_desktop_file(&path) {
                        app.bundle_id = desktop_id.trim_end_matches(".desktop").to_string();
                        apps.push(app);
                    }
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn parse_linux_desktop_file(path: &Path) -> Option<ScannedApp> {
    let content = fs::read_to_string(path).ok()?;
    let mut name = None;
    let mut exec = None;
    let mut try_exec = None;
    let mut icon = None;
    let mut hidden = false;
    let mut dbus_activatable = false;
    let mut startup_wm_class = None;
    let mut entry_type = None;
    let mut in_desktop_entry = false;

    for line in content.lines() {
        let line = line.trim();
        if line == "[Desktop Entry]" {
            in_desktop_entry = true;
            continue;
        } else if line.starts_with('[') && line.ends_with(']') {
            in_desktop_entry = false;
            continue;
        }

        if !in_desktop_entry || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();

        match key {
            "Name" => {
                if name.is_none() {
                    name = Some(value.to_string());
                }
            }
            "Exec" => exec = Some(value.to_string()),
            "TryExec" => try_exec = Some(value.to_string()),
            "Icon" => icon = Some(value.to_string()),
            "Hidden" => hidden = value.eq_ignore_ascii_case("true"),
            "DBusActivatable" => dbus_activatable = value.eq_ignore_ascii_case("true"),
            "StartupWMClass" => startup_wm_class = Some(value.to_string()),
            "Type" => entry_type = Some(value),
            _ => {}
        }
    }

    if entry_type != Some("Application") || hidden {
        return None;
    }

    // NoDisplay only controls menu visibility. A valid hidden-from-menu
    // launcher can still be protected by AppGuard. DBus-only launchers are
    // retained because their window class can identify the running app.
    let raw_exec = exec.or(try_exec);
    if raw_exec.is_none() && !dbus_activatable {
        return None;
    }

    let name = name.or_else(|| {
        path.file_stem()
            .and_then(|stem| stem.to_str())
            .map(str::to_string)
    })?;
    let path_str = path.to_string_lossy().to_string();
    let bundle_id = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(&name)
        .to_string();

    Some(ScannedApp {
        name,
        bundle_id,
        path: path_str,
        icon_path: icon,
        icon_base64: None,
        exec_path: raw_exec.and_then(|value| parse_desktop_exec_binary(&value)),
        startup_wm_class,
    })
}

#[cfg(target_os = "linux")]
fn parse_desktop_exec_binary(raw_exec: &str) -> Option<String> {
    let tokens = tokenize_desktop_exec(raw_exec);
    let mut index = 0;

    if tokens.first().map(String::as_str) == Some("env") {
        index = 1;
        while index < tokens.len() && tokens[index].contains('=') {
            index += 1;
        }
    }

    let command = tokens.get(index)?;
    if command.starts_with('/') {
        return Some(command.clone());
    }

    if let Some(path_var) = std::env::var_os("PATH") {
        for directory in std::env::split_paths(&path_var) {
            let candidate = directory.join(command);
            if candidate.is_file() {
                return Some(candidate.to_string_lossy().to_string());
            }
        }
    }

    Some(command.clone())
}

#[cfg(target_os = "linux")]
fn tokenize_desktop_exec(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;

    for character in input.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }

        match (quote, character) {
            (_, '\\') => escaped = true,
            (Some(active_quote), value) if value == active_quote => quote = None,
            (None, '\'' | '"') => quote = Some(character),
            (None, value) if value.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            (_, value) => current.push(value),
        }
    }

    if escaped {
        current.push('\\');
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

#[cfg(target_os = "windows")]
fn scan_windows_start_menu_recursive(dir: &Path, apps: &mut Vec<ScannedApp>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                scan_windows_start_menu_recursive(&path, apps);
            } else if path.extension().and_then(|s| s.to_str()) == Some("lnk") {
                let name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("Unknown")
                    .to_string();
                let path_str = path.to_string_lossy().to_string();
                let target = resolve_windows_shortcut_target(&path);
                let bundle_id = target
                    .as_ref()
                    .and_then(|target| {
                        Path::new(target)
                            .file_name()
                            .and_then(|name| name.to_str())
                            .map(|name| name.to_lowercase())
                    })
                    .unwrap_or_else(|| format!("{}.exe", name.to_lowercase().replace(' ', "")));

                apps.push(ScannedApp {
                    name,
                    bundle_id,
                    path: path_str,
                    icon_path: None,
                    icon_base64: None,
                    exec_path: target,
                    startup_wm_class: None,
                });
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn resolve_windows_shortcut_target(path: &Path) -> Option<String> {
    let script =
        "$s=(New-Object -ComObject WScript.Shell).CreateShortcut($env:APPGUARD_LINK);$s.TargetPath";
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("APPGUARD_LINK", path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let target = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!target.is_empty()).then_some(target)
}
