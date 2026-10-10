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
