use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannedApp {
    pub name: String,
    pub bundle_id: String,
    pub path: String,
    pub icon_path: Option<String>,
    pub icon_base64: Option<String>,
}

pub fn scan_installed_applications() -> Vec<ScannedApp> {
    let mut apps = Vec::new();

    #[cfg(target_os = "macos")]
    {
        let app_dirs = [
            "/Applications",
            "/System/Applications",
            "/System/Applications/Utilities",
        ];

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
        let mut linux_dirs = vec![
            std::path::PathBuf::from("/usr/share/applications"),
            std::path::PathBuf::from("/usr/local/share/applications"),
        ];

        if let Ok(home) = std::env::var("HOME") {
            linux_dirs.push(
                std::path::PathBuf::from(home)
                    .join(".local")
                    .join("share")
                    .join("applications"),
            );
        }

        for dir in linux_dirs {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) == Some("desktop") {
                        if let Some(app) = parse_linux_desktop_file(&path) {
                            apps.push(app);
                        }
                    }
                }
            }
        }
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

    apps.sort_by(|a: &ScannedApp, b: &ScannedApp| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    apps.dedup_by(|a, b| a.bundle_id == b.bundle_id);
    apps
}

#[cfg(target_os = "macos")]
fn parse_macos_app(path: &Path) -> Option<ScannedApp> {
    let info_plist = path.join("Contents").join("Info.plist");
    if !info_plist.exists() {
        return None;
    }

    let plist_str = fs::read_to_string(&info_plist).ok()?;

    let bundle_id = extract_plist_tag(&plist_str, "CFBundleIdentifier")?;
    let name = extract_plist_tag(&plist_str, "CFBundleDisplayName")
        .or_else(|| extract_plist_tag(&plist_str, "CFBundleName"))
        .unwrap_or_else(|| {
            path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("Unknown")
                .to_string()
        });

    let icon_file = extract_plist_tag(&plist_str, "CFBundleIconFile");
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

    let icon_base64 = icon_path.as_ref().and_then(|p| get_icon_png_base64(&bundle_id, p));

    Some(ScannedApp {
        name,
        bundle_id,
        path: path.to_string_lossy().to_string(),
        icon_path,
        icon_base64,
    })
}

#[cfg(target_os = "macos")]
fn get_icon_png_base64(bundle_id: &str, icns_path: &str) -> Option<String> {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use std::path::PathBuf;
    use std::process::Command;

    let home = std::env::var("HOME").ok().or_else(|| std::env::var("USERPROFILE").ok())?;
    let cache_dir = PathBuf::from(home).join(".cache").join("appguard").join("icons");
    let _ = fs::create_dir_all(&cache_dir);
    let safe_id = bundle_id.replace(|c: char| !c.is_alphanumeric() && c != '.', "_");
    let cached_png = cache_dir.join(format!("{safe_id}.png"));

    if cached_png.exists() {
        if let Ok(bytes) = fs::read(&cached_png) {
            return Some(format!("data:image/png;base64,{}", BASE64.encode(&bytes)));
        }
    }

    let output = Command::new("/usr/bin/sips")
        .args([
            "-s", "format", "png",
            "-z", "64", "64",
            icns_path,
            "--out",
        ])
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

#[cfg(target_os = "macos")]
fn extract_plist_tag(plist: &str, tag: &str) -> Option<String> {
    let search = format!("<key>{}</key>", tag);
    let key_pos = plist.find(&search)?;
    let after_key = &plist[key_pos + search.len()..];

    let string_tag = "<string>";
    let str_pos = after_key.find(string_tag)?;
    let after_str = &after_key[str_pos + string_tag.len()..];

    let end_pos = after_str.find("</string>")?;
    Some(after_str[..end_pos].trim().to_string())
}

#[cfg(target_os = "linux")]
fn parse_linux_desktop_file(path: &Path) -> Option<ScannedApp> {
    let content = fs::read_to_string(path).ok()?;
    let mut name = None;
    let mut exec = None;
    let mut icon = None;
    let mut no_display = false;
    let mut is_application = false;

    for line in content.lines() {
        let line = line.trim();
        if line == "[Desktop Entry]" {
            is_application = true;
        } else if line.starts_with('[') && line.ends_with(']') {
            // Reached another group (e.g. [Desktop Action])
            break;
        }

        if let Some(stripped) = line.strip_prefix("Name=") {
            if name.is_none() {
                name = Some(stripped.trim().to_string());
            }
        } else if let Some(stripped) = line.strip_prefix("Exec=") {
            if exec.is_none() {
                // Strip parameter placeholders like %u, %F, %U
                let raw_exec = stripped.trim();
                let clean_exec = raw_exec
                    .split_whitespace()
                    .next()
                    .unwrap_or(raw_exec)
                    .to_string();
                exec = Some(clean_exec);
            }
        } else if let Some(stripped) = line.strip_prefix("Icon=") {
            if icon.is_none() {
                icon = Some(stripped.trim().to_string());
            }
        } else if let Some(stripped) = line.strip_prefix("NoDisplay=") {
            if stripped.trim().eq_ignore_ascii_case("true") {
                no_display = true;
            }
        } else if let Some(stripped) = line.strip_prefix("Type=") {
            if stripped.trim() != "Application" {
                return None;
            }
        }
    }

    if !is_application || no_display {
        return None;
    }

    let name = name?;
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
    })
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
                let bundle_id = format!("{}.exe", name.to_lowercase().replace(' ', ""));

                apps.push(ScannedApp {
                    name,
                    bundle_id,
                    path: path_str,
                    icon_path: None,
                    icon_base64: None,
                });
            }
        }
    }
}
