use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRule {
    pub bundle_id: String,
    pub name: String,
    pub path: String,
    pub is_locked: bool,
    pub icon_base64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppGuardConfig {
    pub master_pin_hash: Option<String>,
    pub locked_apps: HashMap<String, AppRule>, // Key: bundle_id (or exe name)
    pub locked_folders: Vec<String>,
    pub grace_period_seconds: u64, // Default 60 seconds before re-locking
    pub stealth_mode: bool,
}

impl Default for AppGuardConfig {
    fn default() -> Self {
        Self {
            master_pin_hash: None,
            locked_apps: HashMap::new(),
            locked_folders: Vec::new(),
            grace_period_seconds: 60,
            stealth_mode: false,
        }
    }
}

pub struct SecurityManager {
    config_path: PathBuf,
    pub config: RwLock<AppGuardConfig>,
    // Tracks when an app was last unlocked to respect grace periods
    unlocked_at: RwLock<HashMap<String, Instant>>,
    // Set of currently unlocked session tokens
    active_unlocked: RwLock<HashSet<String>>,
}

impl SecurityManager {
    pub fn new() -> Self {
        let config_dir = dirs_config_dir().unwrap_or_else(|| PathBuf::from("."));
        let _ = fs::create_dir_all(&config_dir);
        let config_path = config_dir.join("appguard_config.json");

        let config = if config_path.exists() {
            fs::read_to_string(&config_path)
                .ok()
                .and_then(|data| serde_json::from_str(&data).ok())
                .unwrap_or_default()
        } else {
            AppGuardConfig::default()
        };

        Self {
            config_path,
            config: RwLock::new(config),
            unlocked_at: RwLock::new(HashMap::new()),
            active_unlocked: RwLock::new(HashSet::new()),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let serialized = serde_json::to_string_pretty(&*self.config.read())
            .map_err(|e| e.to_string())?;
        fs::write(&self.config_path, serialized).map_err(|e| e.to_string())
    }

    pub fn set_master_pin(&self, pin: &str) -> Result<(), String> {
        if pin.len() < 4 {
            return Err("PIN must be at least 4 digits".into());
        }
        let mut hasher = Sha256::new();
        hasher.update(pin.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        self.config.write().master_pin_hash = Some(hash);
        self.save()
    }

    pub fn verify_master_pin(&self, pin: &str) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(pin.as_bytes());
        let input_hash = format!("{:x}", hasher.finalize());

        self.config.read().master_pin_hash.as_ref() == Some(&input_hash)
    }

    pub fn is_pin_configured(&self) -> bool {
        self.config.read().master_pin_hash.is_some()
    }

    pub fn toggle_app_lock(&self, app: AppRule) -> Result<(), String> {
        let mut cfg = self.config.write();
        let bundle_id = app.bundle_id.clone();
        if let Some(existing) = cfg.locked_apps.get_mut(&bundle_id) {
            existing.is_locked = !existing.is_locked;
        } else {
            cfg.locked_apps.insert(bundle_id, app);
        }
        drop(cfg);
        self.save()
    }

    pub fn is_app_locked(&self, bundle_id: &str) -> bool {
        let cfg = self.config.read();
        let rule = match cfg.locked_apps.get(bundle_id) {
            Some(r) => r,
            None => return false,
        };
        if !rule.is_locked {
            return false;
        }

        // Check if unlocked within grace period
        let grace = Duration::from_secs(cfg.grace_period_seconds);
        let unlocked = self.unlocked_at.read();
        if let Some(last_unlocked) = unlocked.get(bundle_id) {
            if last_unlocked.elapsed() < grace {
                return false; // Still within grace period
            }
        }

        // Check if explicitly unlocked
        !self.active_unlocked.read().contains(bundle_id)
    }

    pub fn mark_app_unlocked(&self, bundle_id: &str) {
        self.unlocked_at.write().insert(bundle_id.to_string(), Instant::now());
        self.active_unlocked.write().insert(bundle_id.to_string());
    }

    pub fn add_vault_folder(&self, path: String) -> Result<(), String> {
        let mut cfg = self.config.write();
        if !cfg.locked_folders.contains(&path) {
            cfg.locked_folders.push(path);
        }
        drop(cfg);
        self.save()
    }

    pub fn remove_vault_folder(&self, path: &str) -> Result<(), String> {
        let mut cfg = self.config.write();
        cfg.locked_folders.retain(|f| f != path);
        drop(cfg);
        self.save()
    }

    pub fn lock_all(&self) {
        self.unlocked_at.write().clear();
        self.active_unlocked.write().clear();
    }
}

fn dirs_config_dir() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok().or_else(|| std::env::var("USERPROFILE").ok())?;
    Some(PathBuf::from(home).join(".config").join("appguard"))
}
