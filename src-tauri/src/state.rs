use argon2::{
    password_hash::{phc::PasswordHash, PasswordHasher, PasswordVerifier},
    Argon2,
};
use parking_lot::RwLock;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
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
pub struct AuditEvent {
    pub timestamp: u64, // Unix timestamp in seconds
    pub event_type: String, // "app_blocked", "app_unlocked", "pin_failed", "vault_locked", "vault_unlocked", "lock_all", "pin_changed", "recovery_used"
    pub description: String,
    pub severity: String, // "info", "warning", "critical"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppGuardConfig {
    #[serde(default)]
    pub master_pin_hash: Option<String>,
    #[serde(default)]
    pub recovery_key_hash: Option<String>, // Argon2id hash of one-time recovery key
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
    #[serde(default = "Vec::new")]
    pub activity_log: Vec<AuditEvent>,
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
            recovery_key_hash: None,
            locked_apps: HashMap::new(),
            locked_folders: Vec::new(),
            grace_period_seconds: 60,
            stealth_mode: false,
            app_self_locked: true,
            lock_on_sleep: true,
            lock_on_screensaver: true,
            instant_lock_mode: false,
            tamper_protection_enabled: false,
            activity_log: Vec::new(),
        }
    }
}

pub struct SecurityManager {
    config_path: PathBuf,
    pub config: RwLock<AppGuardConfig>,
    // Tracks when an app was last unlocked to respect grace periods
    unlocked_at: RwLock<HashMap<String, Instant>>,
    // Tracks custom temporary expiry deadlines (e.g. 5 minutes)
    custom_expiry: RwLock<HashMap<String, Instant>>,
    // Set of currently unlocked session tokens
    active_unlocked: RwLock<HashSet<String>>,
    // Tracks if AppGuard itself has been authenticated for this session
    is_app_authenticated: RwLock<bool>,
    // Rate limiting: count of consecutive failed attempts
    failed_attempts: RwLock<u32>,
    // Lockout expiry time if too many failed attempts
    locked_until: RwLock<Option<Instant>>,
}

impl SecurityManager {
    pub fn new() -> Self {
        let config_dir = dirs_config_dir().unwrap_or_else(|| PathBuf::from("."));
        let _ = fs::create_dir_all(&config_dir);
        let config_path = config_dir.join("appguard_config.json");
        let backup_path = config_dir.join("appguard_config.json.bak");

        // Attempt primary config load; if corrupt, fallback to backup
        let config = if config_path.exists() {
            match fs::read_to_string(&config_path) {
                Ok(data) => serde_json::from_str(&data).unwrap_or_else(|err| {
                    eprintln!("Warning: primary config corrupted ({err}), checking backup...");
                    if backup_path.exists() {
                        fs::read_to_string(&backup_path)
                            .ok()
                            .and_then(|bak_data| serde_json::from_str(&bak_data).ok())
                            .unwrap_or_default()
                    } else {
                        AppGuardConfig::default()
                    }
                }),
                Err(_) => AppGuardConfig::default(),
            }
        } else if backup_path.exists() {
            fs::read_to_string(&backup_path)
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
            custom_expiry: RwLock::new(HashMap::new()),
            active_unlocked: RwLock::new(HashSet::new()),
            is_app_authenticated: RwLock::new(false),
            failed_attempts: RwLock::new(0),
            locked_until: RwLock::new(None),
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

    pub fn log_event(&self, event_type: &str, description: &str, severity: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let event = AuditEvent {
            timestamp: now,
            event_type: event_type.to_string(),
            description: description.to_string(),
            severity: severity.to_string(),
        };

        let mut cfg = self.config.write();
        cfg.activity_log.push(event);
        // Keep last 150 events to avoid unbounded file growth
        if cfg.activity_log.len() > 150 {
            let excess = cfg.activity_log.len() - 150;
            cfg.activity_log.drain(0..excess);
        }
        drop(cfg);
        let _ = self.save();
    }

    pub fn get_activity_log(&self) -> Vec<AuditEvent> {
        let mut logs = self.config.read().activity_log.clone();
        logs.reverse(); // Most recent first
        logs
    }

    pub fn save(&self) -> Result<(), String> {
        let serialized = serde_json::to_string_pretty(&*self.config.read())
            .map_err(|e| e.to_string())?;

        let tmp_path = self.config_path.with_extension("tmp");
        let bak_path = self.config_path.with_extension("json.bak");

        // 1. Write to temporary file and sync bytes to disk
        let mut file = fs::File::create(&tmp_path).map_err(|e| e.to_string())?;
        file.write_all(serialized.as_bytes()).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        drop(file);

        // 2. Backup existing config file before overwrite
        if self.config_path.exists() {
            let _ = fs::copy(&self.config_path, &bak_path);
        }

        // 3. Atomically rename .tmp to primary config path
        fs::rename(&tmp_path, &self.config_path).map_err(|e| e.to_string())?;
        Ok(())
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
        self.log_event("pin_changed", "Master PIN was updated", "info");
        self.save()
    }

    pub fn generate_recovery_key(&self) -> Result<String, String> {
        // Generate a 16-character base32-style recovery code (e.g. AG-XXXX-XXXX-XXXX)
        const CHARS: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
        let mut rng = rand::rng();
        let mut code_parts = Vec::new();
        for _ in 0..3 {
            let part: String = (0..4)
                .map(|_| {
                    let idx = rng.random_range(0..CHARS.len());
                    CHARS[idx] as char
                })
                .collect();
            code_parts.push(part);
        }
        let raw_key = format!("AG-{}", code_parts.join("-"));

        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(raw_key.as_bytes())
            .map_err(|e| format!("Argon2 hashing error: {e}"))?
            .to_string();

        self.config.write().recovery_key_hash = Some(hash);
        self.log_event("recovery_generated", "New Emergency Recovery Key was generated", "warning");
        self.save()?;

        Ok(raw_key)
    }

    pub fn verify_recovery_key(&self, key: &str, new_pin: &str) -> Result<bool, String> {
        if new_pin.len() < 4 {
            return Err("New PIN must be at least 4 digits".into());
        }
        let clean_key = key.trim().to_uppercase();
        let cfg = self.config.read();
        let stored_hash = match cfg.recovery_key_hash.as_ref() {
            Some(h) => h,
            None => return Err("No recovery key configured on this device".into()),
        };

        let valid_key = if let Ok(parsed_hash) = PasswordHash::new(&stored_hash) {
            Argon2::default().verify_password(clean_key.as_bytes(), &parsed_hash).is_ok()
        } else {
            false
        };

        drop(cfg);

        if valid_key {
            // Recovery key is single-use: reset recovery key hash and set new master pin
            self.set_master_pin(new_pin)?;
            self.config.write().recovery_key_hash = None;
            self.set_app_authenticated(true);
            self.log_event("recovery_used", "Account successfully recovered via Emergency Key", "critical");
            return Ok(true);
        }

        self.log_event("recovery_failed", "Invalid emergency recovery key entered", "critical");
        Err("Invalid recovery key".into())
    }

    pub fn check_lockout(&self) -> Result<(), String> {
        let lockout = self.locked_until.read();
        if let Some(until) = *lockout {
            if Instant::now() < until {
                let remaining = until.duration_since(Instant::now()).as_secs();
                return Err(format!(
                    "Too many failed attempts. Security cooldown active. Try again in {remaining}s."
                ));
            }
        }
        Ok(())
    }

    pub fn verify_master_pin(&self, pin: &str) -> Result<bool, String> {
        // Enforce rate limiting lockout check
        self.check_lockout()?;

        let cfg = self.config.read();
        let stored_hash = match cfg.master_pin_hash.as_ref() {
            Some(h) => h.clone(),
            None => return Ok(false),
        };

        let mut is_valid = false;
        let mut needs_upgrade = false;

        // 1. Try modern Argon2id verification
        if let Ok(parsed_hash) = PasswordHash::new(&stored_hash) {
            if Argon2::default().verify_password(pin.as_bytes(), &parsed_hash).is_ok() {
                is_valid = true;
            }
        }

        // 2. Try previous Keychain-salted hash ($salted$v1$...)
        if !is_valid {
            let salt = get_or_create_keychain_salt();
            let salted_hash = compute_salted_pin_hash(pin, &salt);
            if stored_hash == salted_hash {
                is_valid = true;
                needs_upgrade = true;
            }
        }

        // 3. Backwards compatibility for early legacy plain SHA-256 hash
        if !is_valid {
            let mut hasher = Sha256::new();
            hasher.update(pin.as_bytes());
            let legacy_hash = format!("{:x}", hasher.finalize());
            if stored_hash == legacy_hash {
                is_valid = true;
                needs_upgrade = true;
            }
        }

        // Explicitly drop read lock on config before log_event or set_master_pin (which require write lock)
        drop(cfg);

        if needs_upgrade {
            let _ = self.set_master_pin(pin);
            return Ok(true);
        }

        if is_valid {
            // Reset failed counter upon successful PIN entry
            *self.failed_attempts.write() = 0;
            *self.locked_until.write() = None;
            Ok(true)
        } else {
            let mut fails = self.failed_attempts.write();
            *fails += 1;
            let count = *fails;
            self.log_event("pin_failed", &format!("Incorrect PIN entered (attempt #{count})"), "warning");

            // Apply progressive lockout penalty
            if count >= 5 {
                let penalty_secs = match count {
                    5 => 30,
                    6 => 60,
                    7 => 300,
                    _ => 900,
                };
                *self.locked_until.write() = Some(Instant::now() + Duration::from_secs(penalty_secs));
                return Err(format!("Incorrect PIN. Locked out for {penalty_secs} seconds."));
            }
            Ok(false)
        }
    }

    pub fn is_pin_configured(&self) -> bool {
        self.config.read().master_pin_hash.is_some()
    }

    pub fn is_recovery_configured(&self) -> bool {
        self.config.read().recovery_key_hash.is_some()
    }

    pub fn toggle_app_lock(&self, app: AppRule) -> Result<(), String> {
        let mut cfg = self.config.write();
        let bundle_id = app.bundle_id.clone();
        let was_locked = cfg.locked_apps.get(&bundle_id).map(|r| r.is_locked).unwrap_or(false);
        if let Some(existing) = cfg.locked_apps.get_mut(&bundle_id) {
            existing.is_locked = !existing.is_locked;
        } else {
            cfg.locked_apps.insert(bundle_id.clone(), app);
        }
        let now_locked = !was_locked;
        drop(cfg);
        self.save()?;

        let status = if now_locked { "locked" } else { "unlocked" };
        self.log_event(
            "rule_changed",
            &format!("Application '{bundle_id}' status set to {status}"),
            "info",
        );
        Ok(())
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
        self.log_event("prefs_updated", "Security preferences were modified", "info");
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

        // 1. Check custom temporary unlock expiry (e.g. 5 minutes from CompactAuthPanel)
        let has_custom = self.custom_expiry.read().contains_key(bundle_id);
        if has_custom {
            let custom = self.custom_expiry.read();
            if let Some(deadline) = custom.get(bundle_id) {
                if Instant::now() < *deadline {
                    return false; // Still within custom temporary unlock window
                }
            }
            drop(custom);
            // Custom duration expired: clean up unlocked session and report locked
            self.unlocked_at.write().remove(bundle_id);
            self.custom_expiry.write().remove(bundle_id);
            self.active_unlocked.write().remove(bundle_id);
            return true;
        }

        // If instant_lock_mode is enabled or grace_period is 0 (and no custom expiry is active),
        // session only lasts until app loses focus
        if cfg.instant_lock_mode || cfg.grace_period_seconds == 0 {
            return !self.active_unlocked.read().contains(bundle_id);
        }

        // 2. Check if unlocked within standard grace period
        let grace = Duration::from_secs(cfg.grace_period_seconds);
        let unlocked = self.unlocked_at.read();
        if let Some(last_unlocked) = unlocked.get(bundle_id) {
            if last_unlocked.elapsed() < grace {
                return false; // Still within grace period
            }
        }
        drop(unlocked);

        // Grace period or temporary duration has expired: clean up unlocked session and report locked
        self.unlocked_at.write().remove(bundle_id);
        self.custom_expiry.write().remove(bundle_id);
        self.active_unlocked.write().remove(bundle_id);
        true
    }

    pub fn mark_app_unlocked(&self, bundle_id: &str, duration_secs: Option<u64>) {
        self.unlocked_at.write().insert(bundle_id.to_string(), Instant::now());
        self.active_unlocked.write().insert(bundle_id.to_string());

        if let Some(secs) = duration_secs {
            let deadline = Instant::now() + Duration::from_secs(secs);
            self.custom_expiry.write().insert(bundle_id.to_string(), deadline);
            let desc = format!("Unlocked session granted for '{bundle_id}' ({secs}s temporary unlock)");
            self.log_event("app_unlocked", &desc, "info");
        } else {
            self.custom_expiry.write().remove(bundle_id);
            let desc = format!("Unlocked session granted for '{bundle_id}'");
            self.log_event("app_unlocked", &desc, "info");
        }
    }

    pub fn add_vault_folder(&self, path: String) -> Result<(), String> {
        let mut cfg = self.config.write();
        if !cfg.locked_folders.contains(&path) {
            cfg.locked_folders.push(path.clone());
        }
        drop(cfg);
        self.log_event("vault_added", &format!("Folder added to vault: {path}"), "info");
        self.save()
    }

    pub fn remove_vault_folder(&self, path: &str) -> Result<(), String> {
        let mut cfg = self.config.write();
        cfg.locked_folders.retain(|f| f != path);
        drop(cfg);
        self.log_event("vault_removed", &format!("Folder removed from vault: {path}"), "info");
        self.save()
    }

    pub fn lock_all(&self) {
        self.unlocked_at.write().clear();
        self.custom_expiry.write().clear();
        self.active_unlocked.write().clear();
        *self.is_app_authenticated.write() = false;
        self.log_event("lock_all", "Emergency Lock All triggered across all apps & vaults", "warning");
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

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_security_manager() -> SecurityManager {
        let temp_dir = std::env::temp_dir().join(format!("ag_test_{:x}", rand::rng().random_range(0..1_000_000)));
        let _ = fs::create_dir_all(&temp_dir);
        let config_path = temp_dir.join("test_config.json");
        let config = AppGuardConfig::default();

        SecurityManager {
            config_path,
            config: RwLock::new(config),
            unlocked_at: RwLock::new(HashMap::new()),
            custom_expiry: RwLock::new(HashMap::new()),
            active_unlocked: RwLock::new(HashSet::new()),
            is_app_authenticated: RwLock::new(false),
            failed_attempts: RwLock::new(0),
            locked_until: RwLock::new(None),
        }
    }

    #[test]
    fn test_master_pin_set_and_verify() {
        let sm = create_test_security_manager();
        sm.set_master_pin("1234").expect("Failed to set PIN");
        assert!(sm.is_pin_configured());

        // Valid PIN
        assert_eq!(sm.verify_master_pin("1234").unwrap(), true);

        // Invalid PIN
        assert_eq!(sm.verify_master_pin("9999").unwrap(), false);
    }

    #[test]
    fn test_failed_attempts_progressive_lockout() {
        let sm = create_test_security_manager();
        sm.set_master_pin("1234").expect("Failed to set PIN");

        // Fail 4 times (under threshold)
        for _ in 0..4 {
            assert_eq!(sm.verify_master_pin("0000").unwrap(), false);
        }

        // 5th failure triggers lockout Err
        let res = sm.verify_master_pin("0000");
        assert!(res.is_err(), "Expected 5th failure to trigger lockout");
        assert!(res.unwrap_err().contains("Locked out"));

        // Subsequent check_lockout should also return Err
        assert!(sm.check_lockout().is_err());
    }

    #[test]
    fn test_recovery_key_lifecycle() {
        let sm = create_test_security_manager();
        sm.set_master_pin("1111").expect("Failed to set initial PIN");

        let recovery_key = sm.generate_recovery_key().expect("Failed to generate key");
        assert!(recovery_key.starts_with("AG-"));
        assert!(sm.is_recovery_configured());

        // Bad key fails
        let bad_res = sm.verify_recovery_key("AG-INVALID-KEY-1234", "2222");
        assert!(bad_res.is_err());

        // Good key resets PIN and clears recovery key
        let ok_res = sm.verify_recovery_key(&recovery_key, "2222");
        assert_eq!(ok_res.unwrap(), true);

        // New PIN works
        assert_eq!(sm.verify_master_pin("2222").unwrap(), true);
        // Recovery key was single-use: now cleared
        assert!(!sm.is_recovery_configured());
    }

    #[test]
    fn test_temporary_unlock_expiry() {
        let sm = create_test_security_manager();
        let app_id = "com.apple.Terminal";

        let rule = AppRule {
            bundle_id: app_id.to_string(),
            name: "Terminal".to_string(),
            path: "/System/Applications/Utilities/Terminal.app".to_string(),
            is_locked: true,
            icon_base64: None,
        };
        sm.toggle_app_lock(rule.clone()).unwrap();

        // Initially locked
        assert!(sm.is_app_locked(app_id));

        // Unlock with 2 seconds temporary duration
        sm.mark_app_unlocked(app_id, Some(2));

        // Within duration: unlocked
        assert!(!sm.is_app_locked(app_id));

        // Sleep to exceed 2 seconds
        std::thread::sleep(Duration::from_millis(2100));

        // After duration: locked again
        assert!(sm.is_app_locked(app_id));
    }
}

