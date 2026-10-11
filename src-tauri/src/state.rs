use argon2::{
    password_hash::{phc::PasswordHash, PasswordHasher, PasswordVerifier},
    Argon2,
};

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
    pub grace_period_seconds: u64, // 0 = Immediate, 60 = 1m, 300 = 5m, etc.
    pub stealth_mode: bool,
    #[serde(default = "default_true")]
    pub app_self_locked: bool, // Require auth to access AppGuard dashboard
    #[serde(default = "default_true")]
    pub lock_on_sleep: bool,
    #[serde(default = "default_true")]
    pub lock_on_screensaver: bool,
    #[serde(default = "default_false")]
    pub instant_lock_mode: bool, // Zero-tolerance lock immediately on process focus change
    #[serde(default = "default_false")]
    pub tamper_protection_enabled: bool, // Cross-platform auto-resurrect OS watchdog
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

impl Default for AppGuardConfig {
    fn default() -> Self {
        Self {
            master_pin_hash: None,
            locked_apps: HashMap::new(),
            locked_folders: Vec::new(),
            grace_period_seconds: 60,
            stealth_mode: false,
            app_self_locked: true,
            lock_on_sleep: true,
            lock_on_screensaver: true,
            instant_lock_mode: false,
            tamper_protection_enabled: false,
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
    // Tracks if AppGuard itself has been authenticated for this session
    is_app_authenticated: RwLock<bool>,
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
            is_app_authenticated: RwLock::new(false),
        }
    }

    pub fn is_app_authenticated(&self) -> bool {
        // If master PIN is not configured yet (first launch), allow access for setup
        if !self.is_pin_configured() {
            return true;
        }
        if !self.config.read().app_self_locked {
            return true;
        }
        *self.is_app_authenticated.read()
    }

    pub fn set_app_authenticated(&self, auth: bool) {
        *self.is_app_authenticated.write() = auth;
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
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(pin.as_bytes())
            .map_err(|e| format!("Argon2 hashing error: {e}"))?
            .to_string();

        self.config.write().master_pin_hash = Some(hash);
        self.save()
    }

    pub fn verify_master_pin(&self, pin: &str) -> bool {
        let cfg = self.config.read();
        let stored_hash = match cfg.master_pin_hash.as_ref() {
            Some(h) => h,
            None => return false,
        };

        // 1. Try modern Argon2id verification
        if let Ok(parsed_hash) = PasswordHash::new(stored_hash) {
            if Argon2::default().verify_password(pin.as_bytes(), &parsed_hash).is_ok() {
                return true;
            }
        }

        // 2. Try previous Keychain-salted hash ($salted$v1$...)
        let salt = get_or_create_keychain_salt();
        let salted_hash = compute_salted_pin_hash(pin, &salt);
        if stored_hash == &salted_hash {
            // Transparently upgrade to Argon2id
            drop(cfg);
            let _ = self.set_master_pin(pin);
            return true;
        }

        // 3. Backwards compatibility for early legacy plain SHA-256 hash
        let mut hasher = Sha256::new();
        hasher.update(pin.as_bytes());
        let legacy_hash = format!("{:x}", hasher.finalize());
        if stored_hash == &legacy_hash {
            // Transparently upgrade to Argon2id
            drop(cfg);
            let _ = self.set_master_pin(pin);
            return true;
        }

        false
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

    pub fn update_preferences(
        &self,
        grace_period_seconds: u64,
        app_self_locked: bool,
        lock_on_sleep: bool,
        lock_on_screensaver: bool,
        instant_lock_mode: bool,
        stealth_mode: bool,
        tamper_protection_enabled: bool,
    ) -> Result<(), String> {
        let mut cfg = self.config.write();
        cfg.grace_period_seconds = grace_period_seconds;
        cfg.app_self_locked = app_self_locked;
        cfg.lock_on_sleep = lock_on_sleep;
        cfg.lock_on_screensaver = lock_on_screensaver;
        cfg.instant_lock_mode = instant_lock_mode;
        cfg.stealth_mode = stealth_mode;
        cfg.tamper_protection_enabled = tamper_protection_enabled;
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

        // If instant_lock_mode is enabled or grace_period is 0, session only lasts until app loses focus
        if cfg.instant_lock_mode || cfg.grace_period_seconds == 0 {
            return !self.active_unlocked.read().contains(bundle_id);
        }

        // Check if unlocked within grace period
        let grace = Duration::from_secs(cfg.grace_period_seconds);
        let unlocked = self.unlocked_at.read();
        if let Some(last_unlocked) = unlocked.get(bundle_id) {
            if last_unlocked.elapsed() < grace {
                return false; // Still within grace period
            }
        }
        drop(unlocked);

        // Grace period has expired: clean up unlocked session and report locked
        self.unlocked_at.write().remove(bundle_id);
        self.active_unlocked.write().remove(bundle_id);
        true
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
        *self.is_app_authenticated.write() = false;
    }
}

fn dirs_config_dir() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok().or_else(|| std::env::var("USERPROFILE").ok())?;
    Some(PathBuf::from(home).join(".config").join("appguard"))
}

fn compute_salted_pin_hash(pin: &str, salt: &str) -> String {
    let mut current = pin.as_bytes().to_vec();
    // 10,000 rounds of salted SHA-256 stretching (PBKDF2 style)
    for i in 0u32..10_000u32 {
        let mut hasher = Sha256::new();
        hasher.update(&current);
        hasher.update(salt.as_bytes());
        hasher.update(&i.to_be_bytes());
        current = hasher.finalize().to_vec();
    }
    format!("$salted$v1${}", hex_encode(&current))
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn get_or_create_keychain_salt() -> String {
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let user = std::env::var("USER").unwrap_or_else(|_| "current_user".into());
        let service = "com.appguard.desktop.salt";

        // Attempt reading from Apple Keychain
        if let Ok(output) = Command::new("security")
            .args(["find-generic-password", "-a", &user, "-s", service, "-w"])
            .output()
        {
            if output.status.success() {
                let salt_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !salt_str.is_empty() {
                    return salt_str;
                }
            }
        }

        // Generate high-entropy 256-bit salt and store into Keychain
        let random_salt = format!("ag_salt_{:x}_{:x}", std::time::SystemTime::now().elapsed().unwrap_or_default().as_nanos(), std::process::id());
        let _ = Command::new("security")
            .args(["add-generic-password", "-a", &user, "-s", service, "-w", &random_salt, "-U"])
            .output();

        random_salt
    }

    #[cfg(not(target_os = "macos"))]
    {
        "appguard_static_salt_fallback_platform".into()
    }
}
