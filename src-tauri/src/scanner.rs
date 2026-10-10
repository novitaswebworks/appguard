use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannedApp {
    pub name: String,
    pub bundle_id: String,
    pub path: String,
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

    apps.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
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

    Some(ScannedApp {
        name,
        bundle_id,
        path: path.to_string_lossy().to_string(),
    })
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
