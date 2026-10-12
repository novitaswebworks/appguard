use argon2::{
    Argon2,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};
use parking_lot::{Mutex, RwLock};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRule {
    pub bundle_id: String,
    pub name: String,
    pub path: String,
    pub is_locked: bool,
    #[serde(default)]
    pub icon_base64: Option<String>,
    #[serde(default)]
    pub exec_path: Option<String>,
    #[serde(default)]
    pub startup_wm_class: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: u64,     // Unix timestamp in seconds
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
            lock_on_sleep: false,
            lock_on_screensaver: false,
            instant_lock_mode: false,
            tamper_protection_enabled: false,
            activity_log: Vec::new(),
        }
    }
}

pub struct SecurityManager {
    config_path: PathBuf,
    save_lock: Mutex<()>,
    pub operation_lock: Mutex<()>,
    pub challenge: Mutex<crate::session::Challenge>,
    pub window_lock: Mutex<()>,
    startup_error: RwLock<Option<String>>,
    pub config: RwLock<AppGuardConfig>,
    // Tracks when an app was last unlocked to respect grace periods
    unlocked_at: RwLock<HashMap<String, Instant>>,
    // Tracks custom temporary expiry deadlines (e.g. 5 minutes)
    custom_expiry: RwLock<HashMap<String, Instant>>,
    // Set of currently unlocked session tokens
    active_unlocked: RwLock<HashSet<String>>,
    // Tracks if AppGuard itself has been authenticated for this session
    is_app_authenticated: RwLock<bool>,
    auth_generation: RwLock<u64>,
    // Rate limiting: count of consecutive failed attempts
    failed_attempts: RwLock<u32>,
    // Lockout expiry time if too many failed attempts
    locked_until: RwLock<Option<Instant>>,
}

impl SecurityManager {
    pub fn new() -> Self {
        match dirs_config_dir() {
            Some(dir) => Self::from_path(dir.join("appguard_config.json")),
            None => {
                let state = Self::from_path(PathBuf::from("/nonexistent/appguard/config.json"));
                *state.startup_error.write() =
                    Some("Cannot determine the configuration directory".into());
                state
            }
        }
    }

    fn from_path(config_path: PathBuf) -> Self {
        let loaded = (|| -> Result<AppGuardConfig, String> {
            let dir = config_path
                .parent()
                .ok_or("Missing configuration directory")?;
            crate::storage::reject_symlinks(dir)?;
            fs::create_dir_all(dir).map_err(|e| e.to_string())?;
            set_private_permissions(dir)?;
            recover_credentials(&config_path)?;
            crate::storage::reject_symlinks(&config_path)?;
            if config_path.exists() {
                set_private_permissions(&config_path)?;
                let config: AppGuardConfig =
                    serde_json::from_slice(&fs::read(&config_path).map_err(|e| e.to_string())?)
                        .map_err(|e| {
                            format!("Configuration is damaged; restore a verified backup: {e}")
                        })?;
                validate_config(&config)?;
                Ok(config)
            } else if config_path.with_extension("json.bak").exists() {
                Err("Primary configuration is missing. Restore a verified backup before continuing.".into())
            } else {
                Ok(AppGuardConfig::default())
            }
        })();
        let (config, startup_error) = match loaded {
            Ok(config) => (config, None),
            Err(error) => (AppGuardConfig::default(), Some(error)),
        };

        Self {
            config_path,
            save_lock: Mutex::new(()),
            operation_lock: Mutex::new(()),
            challenge: Mutex::new(crate::session::Challenge::default()),
            window_lock: Mutex::new(()),
            startup_error: RwLock::new(startup_error),
            config: RwLock::new(config),
            unlocked_at: RwLock::new(HashMap::new()),
            custom_expiry: RwLock::new(HashMap::new()),
            active_unlocked: RwLock::new(HashSet::new()),
            is_app_authenticated: RwLock::new(false),
            auth_generation: RwLock::new(0),
            failed_attempts: RwLock::new(0),
            locked_until: RwLock::new(None),
        }
    }

    pub fn is_app_authenticated(&self) -> bool {
        if self.ensure_ready().is_err() {
            return false;
        }
        // If master PIN is not configured yet (first launch), allow access for setup
        if !self.is_pin_configured() {
            return true;
        }
        *self.is_app_authenticated.read()
    }

    pub fn set_app_authenticated(&self, auth: bool) {
        let mut generation = self.auth_generation.write();
        *self.is_app_authenticated.write() = auth;
        if !auth {
            *generation = generation.wrapping_add(1);
        }
    }

    pub fn auth_generation(&self) -> u64 {
        *self.auth_generation.read()
    }

    pub fn authenticate_dashboard(&self, generation: u64) -> Result<(), String> {
        let current = self.auth_generation.read();
        self.ensure_ready()?;
        if *current != generation {
            return Err("Dashboard was locked during authentication; try again".into());
        }
        *self.is_app_authenticated.write() = true;
        Ok(())
    }

    pub fn ensure_ready(&self) -> Result<(), String> {
        match &*self.startup_error.read() {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }

    pub fn require_authenticated(&self) -> Result<(), String> {
        self.ensure_ready()?;
        if self.is_pin_configured() && self.is_app_authenticated() {
            Ok(())
        } else {
            Err("AppGuard is locked. Authenticate before changing security settings.".into())
        }
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
        self.ensure_ready()?;
        let _save_guard = self.save_lock.lock();
        self.ensure_ready()?;
        let serialized =
            serde_json::to_string_pretty(&*self.config.read()).map_err(|e| e.to_string())?;

        crate::storage::atomic_write(&self.config_path, serialized.as_bytes())?;
        // Backup reflects the committed credentials, never a revoked PIN/key.
        crate::storage::atomic_write(
            &self.config_path.with_extension("json.bak"),
            serialized.as_bytes(),
        )?;
        Ok(())
    }

    pub fn set_master_pin(&self, pin: &str) -> Result<(), String> {
        self.ensure_ready()?;
        validate_pin(pin)?;
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(pin.as_bytes())
            .map_err(|e| format!("Argon2 hashing error: {e}"))?
            .to_string();

        let mut next = self.config.read().clone();
        next.master_pin_hash = Some(hash);
        self.commit_credentials(next, Vec::new())?;
        self.log_event("pin_changed", "Master PIN was updated", "info");
        Ok(())
    }

    pub fn generate_recovery_key(&self, pin: &str) -> Result<String, String> {
        if !self.verify_master_pin(pin)? {
            return Err("Incorrect Master PIN".into());
        }
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

        let mut next = self.config.read().clone();
        let mut updates = Vec::new();
        for folder in &next.locked_folders {
            if let Some(update) = crate::vault::prepare_recovery_wrapper(folder, pin, &raw_key)? {
                updates.push(update);
            }
        }
        next.recovery_key_hash = Some(hash);
        self.commit_credentials(next, updates)?;
        self.log_event(
            "recovery_generated",
            "New Emergency Recovery Key was generated",
            "warning",
        );

        Ok(raw_key)
    }

    pub fn verify_recovery_key(&self, key: &str, new_pin: &str) -> Result<bool, String> {
        self.ensure_ready()?;
        validate_pin(new_pin)?;
        self.check_lockout()?;
        let clean_key = key.trim().to_uppercase();
        let cfg = self.config.read();
        let stored_hash = match cfg.recovery_key_hash.as_ref() {
            Some(h) => h,
            None => return Err("No recovery key configured on this device".into()),
        };

        let valid_key = if let Ok(parsed_hash) = PasswordHash::new(&stored_hash) {
            Argon2::default()
                .verify_password(clean_key.as_bytes(), &parsed_hash)
                .is_ok()
        } else {
            false
        };

        drop(cfg);

        if valid_key {
            let mut next = self.config.read().clone();
            let mut updates = Vec::new();
            for folder in &next.locked_folders {
                if let Some(update) =
                    crate::vault::prepare_recovery_rewrap(folder, &clean_key, new_pin)?
                {
                    updates.push(update);
                }
            }
            next.master_pin_hash = Some(hash_pin(new_pin)?);
            next.recovery_key_hash = None;
            self.commit_credentials(next, updates)?;
            self.lock_all();
            self.set_app_authenticated(true);
            *self.failed_attempts.write() = 0;
            *self.locked_until.write() = None;
            self.log_event(
                "recovery_used",
                "Account successfully recovered via Emergency Key",
                "critical",
            );
            return Ok(true);
        }

        self.register_failed_attempt();
        self.log_event(
            "recovery_failed",
            "Invalid emergency recovery key entered",
            "critical",
        );
        Err("Invalid recovery key".into())
    }

    fn register_failed_attempt(&self) {
        let mut fails = self.failed_attempts.write();
        *fails += 1;
        let penalty_secs = match *fails {
            0..=4 => 0,
            5 => 30,
            6 => 60,
            7 => 300,
            _ => 900,
        };
        if penalty_secs > 0 {
            *self.locked_until.write() = Some(Instant::now() + Duration::from_secs(penalty_secs));
        }
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
        self.ensure_ready()?;
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
            if Argon2::default()
                .verify_password(pin.as_bytes(), &parsed_hash)
                .is_ok()
            {
                is_valid = true;
            }
        }

        // 2. Try previous Keychain-salted hash ($salted$v1$...) ONLY if stored hash has this prefix
        if !is_valid && stored_hash.starts_with("$salted$v1$") {
            let salt = read_legacy_keychain_salt()?;
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
            // Verify existing credentials under their original policy. A hash
            // upgrade must not reject an otherwise-valid legacy passphrase.
            let mut next = self.config.read().clone();
            next.master_pin_hash = Some(hash_pin(pin)?);
            self.commit_credentials(next, Vec::new())?;
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
            self.log_event(
                "pin_failed",
                &format!("Incorrect PIN entered (attempt #{count})"),
                "warning",
            );

            // Apply progressive lockout penalty
            if count >= 5 {
                let penalty_secs = match count {
                    5 => 30,
                    6 => 60,
                    7 => 300,
                    _ => 900,
                };
                *self.locked_until.write() =
                    Some(Instant::now() + Duration::from_secs(penalty_secs));
                return Err(format!(
                    "Incorrect PIN. Locked out for {penalty_secs} seconds."
                ));
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
        self.ensure_ready()?;
        if app.bundle_id.trim().is_empty() || app.name.trim().is_empty() {
            return Err("Invalid application identity".into());
        }
        let mut cfg = self.config.write();
        let bundle_id = app.bundle_id.clone();
        let requested_locked = app.is_locked;
        if let Some(existing) = cfg.locked_apps.get_mut(&bundle_id) {
            existing.is_locked = requested_locked;
            existing.name = app.name;
            existing.path = app.path;
            existing.icon_base64 = app.icon_base64.or(existing.icon_base64.take());
            existing.exec_path = app.exec_path.or(existing.exec_path.take());
            existing.startup_wm_class = app.startup_wm_class.or(existing.startup_wm_class.take());
        } else {
            cfg.locked_apps.insert(bundle_id.clone(), app);
        }
        let now_locked = requested_locked;
        drop(cfg);
        if requested_locked {
            self.unlocked_at.write().remove(&bundle_id);
            self.active_unlocked.write().remove(&bundle_id);
            self.custom_expiry.write().remove(&bundle_id);
        }
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
        self.require_authenticated()?;
        if grace_period_seconds > 86_400 {
            return Err("Grace period cannot exceed 24 hours".into());
        }
        let mut cfg = self.config.write();
        cfg.grace_period_seconds = grace_period_seconds;
        let _ = app_self_locked;
        cfg.app_self_locked = true;
        // These require native integrations. Stored legacy flags must not be
        // displayed as working features or re-enable themselves through IPC.
        let _ = (
            lock_on_sleep,
            lock_on_screensaver,
            stealth_mode,
            tamper_protection_enabled,
        );
        cfg.lock_on_sleep = false;
        cfg.lock_on_screensaver = false;
        cfg.instant_lock_mode = instant_lock_mode;
        cfg.stealth_mode = false;
        drop(cfg);
        self.log_event(
            "prefs_updated",
            "Security preferences were modified",
            "info",
        );
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
        self.unlocked_at
            .write()
            .insert(bundle_id.to_string(), Instant::now());
        self.active_unlocked.write().insert(bundle_id.to_string());

        if let Some(secs) = duration_secs {
            let deadline = Instant::now() + Duration::from_secs(secs);
            self.custom_expiry
                .write()
                .insert(bundle_id.to_string(), deadline);
            let desc =
                format!("Unlocked session granted for '{bundle_id}' ({secs}s temporary unlock)");
            self.log_event("app_unlocked", &desc, "info");
        } else {
            self.custom_expiry.write().remove(bundle_id);
            let desc = format!("Unlocked session granted for '{bundle_id}'");
            self.log_event("app_unlocked", &desc, "info");
        }
    }

    pub fn relock_on_focus_loss(&self, bundle_id: &str) {
        let cfg = self.config.read();
        if (cfg.instant_lock_mode || cfg.grace_period_seconds == 0)
            && !self.custom_expiry.read().contains_key(bundle_id)
        {
            self.unlocked_at.write().remove(bundle_id);
            self.custom_expiry.write().remove(bundle_id);
            self.active_unlocked.write().remove(bundle_id);
        }
    }

    pub fn add_vault_folder(&self, path: String) -> Result<(), String> {
        crate::storage::reject_symlinks(Path::new(&path))?;
        let canonical =
            fs::canonicalize(&path).map_err(|e| format!("Invalid vault folder: {e}"))?;
        if !canonical.is_dir() {
            return Err("Vault target must be a directory".into());
        }
        if let Some(config_dir) = self.config_path.parent() {
            if canonical.starts_with(config_dir) || config_dir.starts_with(&canonical) {
                return Err("The AppGuard configuration directory cannot be vaulted".into());
            }
        }

        let mut cfg = self.config.write();
        for existing in &cfg.locked_folders {
            if let Ok(existing_canonical) = fs::canonicalize(existing) {
                if canonical.starts_with(&existing_canonical)
                    || existing_canonical.starts_with(&canonical)
                {
                    return Err("Vault folders cannot overlap".into());
                }
            }
        }
        let canonical_path = canonical.to_string_lossy().to_string();
        if !cfg.locked_folders.contains(&canonical_path) {
            cfg.locked_folders.push(canonical_path.clone());
        }
        drop(cfg);
        self.log_event(
            "vault_added",
            &format!("Folder added to vault: {canonical_path}"),
            "info",
        );
        self.save()
    }

    pub fn remove_vault_folder(&self, path: &str) -> Result<(), String> {
        let mut cfg = self.config.write();
        cfg.locked_folders.retain(|f| f != path);
        drop(cfg);
        self.log_event(
            "vault_removed",
            &format!("Folder removed from vault: {path}"),
            "info",
        );
        self.save()
    }

    pub fn require_vault(&self, path: &str) -> Result<(), String> {
        crate::storage::reject_symlinks(Path::new(path))?;
        let canonical = fs::canonicalize(path).map_err(|e| e.to_string())?;
        if self
            .config
            .read()
            .locked_folders
            .iter()
            .any(|registered| Path::new(registered) == canonical)
        {
            Ok(())
        } else {
            Err("Folder is not a registered vault".into())
        }
    }

    pub fn lock_all(&self) {
        let _windows = self.window_lock.lock();
        self.unlocked_at.write().clear();
        self.custom_expiry.write().clear();
        self.active_unlocked.write().clear();
        self.set_app_authenticated(false);
        self.challenge.lock().clear();
        self.log_event(
            "lock_all",
            "Application sessions and dashboard locked",
            "warning",
        );
    }

    pub fn change_pin(&self, old: &str, new: &str) -> Result<(), String> {
        validate_pin(new)?;
        if !self.verify_master_pin(old)? {
            return Err("Incorrect current PIN".into());
        }
        let mut next = self.config.read().clone();
        let mut updates = Vec::new();
        for folder in &next.locked_folders {
            if let Some(update) = crate::vault::prepare_pin_rewrap(folder, old, new)? {
                updates.push(update);
            }
        }
        next.master_pin_hash = Some(hash_pin(new)?);
        self.commit_credentials(next, updates)?;
        self.lock_all();
        self.set_app_authenticated(true);
        Ok(())
    }

    fn commit_credentials(
        &self,
        mut config: AppGuardConfig,
        updates: Vec<crate::vault::MetadataUpdate>,
    ) -> Result<(), String> {
        self.ensure_ready()?;
        let _save = self.save_lock.lock();
        self.ensure_ready()?;
        config.activity_log = self.config.read().activity_log.clone();
        let transaction = CredentialTransaction {
            config: config.clone(),
            updates,
        };
        let journal = self.config_path.with_extension("transaction");
        if let Err(error) = crate::storage::atomic_write(
            &journal,
            &serde_json::to_vec(&transaction).map_err(|e| e.to_string())?,
        ) {
            *self.startup_error.write() = Some(format!(
                "Credential journal write failed. Restart to determine the committed state: {error}"
            ));
            return self.ensure_ready();
        }
        if let Err(error) = recover_credentials(&self.config_path) {
            *self.startup_error.write() = Some(format!(
                "Credential transaction needs recovery. Reconnect vault disks and restart: {error}"
            ));
            return self.ensure_ready();
        }
        *self.config.write() = config;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct CredentialTransaction {
    config: AppGuardConfig,
    updates: Vec<crate::vault::MetadataUpdate>,
}

fn recover_credentials(path: &Path) -> Result<(), String> {
    let journal = path.with_extension("transaction");
    crate::storage::reject_symlinks(&journal)?;
    if !journal.exists() {
        return Ok(());
    }
    let transaction: CredentialTransaction =
        serde_json::from_slice(&fs::read(&journal).map_err(|e| e.to_string())?)
            .map_err(|e| format!("Credential journal is damaged: {e}"))?;
    validate_config(&transaction.config)?;
    for update in transaction.updates {
        update.commit()?;
    }
    let data = serde_json::to_vec_pretty(&transaction.config).map_err(|e| e.to_string())?;
    crate::storage::atomic_write(path, &data)?;
    crate::storage::atomic_write(&path.with_extension("json.bak"), &data)?;
    fs::remove_file(&journal).map_err(|e| e.to_string())?;
    crate::storage::sync_directory(path.parent().ok_or("Missing parent")?)
}

fn hash_pin(pin: &str) -> Result<String, String> {
    Argon2::default()
        .hash_password(pin.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|e| e.to_string())
}

fn validate_config(config: &AppGuardConfig) -> Result<(), String> {
    if config
        .master_pin_hash
        .as_ref()
        .is_some_and(|hash| hash.is_empty())
        || (config.master_pin_hash.is_none()
            && (!config.locked_apps.is_empty()
                || !config.locked_folders.is_empty()
                || config.recovery_key_hash.is_some()))
        || config.grace_period_seconds > 86_400
        || config
            .locked_apps
            .iter()
            .any(|(id, rule)| id.is_empty() || id != &rule.bundle_id)
    {
        return Err(
            "Configuration is inconsistent. Restore a verified backup before continuing.".into(),
        );
    }
    Ok(())
}

fn dirs_config_dir() -> Option<PathBuf> {
    if let Some(config_home) = std::env::var_os("XDG_CONFIG_HOME") {
        if !config_home.is_empty() && Path::new(&config_home).is_absolute() {
            return Some(PathBuf::from(config_home).join("appguard"));
        }
    }
    let home = std::env::var("HOME")
        .ok()
        .or_else(|| std::env::var("USERPROFILE").ok())?;
    Some(PathBuf::from(home).join(".config").join("appguard"))
}

fn set_private_permissions(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if path.is_dir() { 0o700 } else { 0o600 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn validate_pin(pin: &str) -> Result<(), String> {
    if !(4..=8).contains(&pin.len()) || !pin.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("PIN must contain 4 to 8 digits".into());
    }
    Ok(())
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

fn read_legacy_keychain_salt() -> Result<String, String> {
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
                    return Ok(salt_str);
                }
            }
        }

        // Generating a replacement cannot verify the old hash and could
        // overwrite a temporarily inaccessible credential. Never do that.
        Err(
            "Legacy credential salt is unavailable. Unlock the login keychain or use recovery."
                .into(),
        )
    }

    #[cfg(not(target_os = "macos"))]
    {
        Ok("appguard_static_salt_fallback_platform".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_security_manager() -> SecurityManager {
        let temp_dir = std::env::temp_dir().join(format!(
            "ag_test_{:x}",
            rand::rng().random_range(0..1_000_000)
        ));
        fs::create_dir_all(&temp_dir).unwrap();
        SecurityManager::from_path(fs::canonicalize(temp_dir).unwrap().join("test_config.json"))
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
        sm.set_master_pin("1111")
            .expect("Failed to set initial PIN");

        let recovery_key = sm
            .generate_recovery_key("1111")
            .expect("Failed to generate key");
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
            exec_path: None,
            startup_wm_class: None,
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

    #[test]
    fn lock_all_revokes_dashboard_and_target_authentication() {
        let sm = create_test_security_manager();
        sm.set_master_pin("1234").expect("Failed to set PIN");

        sm.set_app_authenticated(true);
        let generation = sm.auth_generation();
        let target = sm.challenge.lock().set("app".into(), "App".into(), None);
        sm.challenge.lock().authorize(&target).unwrap();
        sm.lock_all();
        assert!(sm.require_authenticated().is_err());
        assert!(sm.authenticate_dashboard(generation).is_err());
        assert!(
            sm.challenge
                .lock()
                .consume("app", target.request_id)
                .is_err()
        );
    }

    fn transaction_fixture() -> (tempfile::TempDir, SecurityManager, Vec<String>) {
        let root = tempfile::tempdir_in(fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
        let sm = SecurityManager::from_path(root.path().join("config/appguard_config.json"));
        sm.set_master_pin("1234").unwrap();
        let mut folders = Vec::new();
        for name in ["one", "two"] {
            let folder = root.path().join(name);
            fs::create_dir(&folder).unwrap();
            fs::write(folder.join("data"), name).unwrap();
            let path = folder.to_str().unwrap().to_string();
            sm.add_vault_folder(path.clone()).unwrap();
            crate::vault::lock_folder(&path, "1234").unwrap();
            folders.push(path);
        }
        (root, sm, folders)
    }

    #[test]
    fn rejected_credentials_do_not_rewrap_any_vault() {
        let (_root, sm, folders) = transaction_fixture();
        let key = sm.generate_recovery_key("1234").unwrap();
        let before: Vec<_> = folders
            .iter()
            .map(|p| fs::read(Path::new(p).join(".appguard_vault_meta")).unwrap())
            .collect();
        let old_pin_hash = sm.config.read().master_pin_hash.clone();
        let old_recovery_hash = sm.config.read().recovery_key_hash.clone();
        assert!(sm.change_pin("1234", "bad").is_err());
        assert!(sm.verify_recovery_key(&key, "123").is_err());
        assert!(sm.verify_recovery_key("WRONG", "5678").is_err());
        assert_eq!(sm.config.read().master_pin_hash, old_pin_hash);
        assert_eq!(sm.config.read().recovery_key_hash, old_recovery_hash);
        for (path, expected) in folders.iter().zip(before) {
            assert_eq!(
                fs::read(Path::new(path).join(".appguard_vault_meta")).unwrap(),
                expected
            );
        }
        sm.verify_recovery_key(&key.to_lowercase(), "5678").unwrap();
        assert!(!sm.is_recovery_configured());
        let backup: AppGuardConfig =
            serde_json::from_slice(&fs::read(sm.config_path.with_extension("json.bak")).unwrap())
                .unwrap();
        assert_eq!(backup.master_pin_hash, sm.config.read().master_pin_hash);
        assert!(backup.recovery_key_hash.is_none());
        for path in folders {
            crate::vault::unlock_folder(&path, "5678").unwrap();
        }
    }

    #[test]
    fn second_vault_preparation_failure_leaves_first_vault_unchanged() {
        let (_root, sm, folders) = transaction_fixture();
        let first_meta = Path::new(&folders[0]).join(".appguard_vault_meta");
        let before = fs::read(&first_meta).unwrap();
        let pin_hash = sm.config.read().master_pin_hash.clone();
        fs::write(
            Path::new(&folders[1]).join(".appguard_vault_meta"),
            b"damaged",
        )
        .unwrap();
        assert!(sm.change_pin("1234", "5678").is_err());
        assert_eq!(fs::read(first_meta).unwrap(), before);
        assert_eq!(sm.config.read().master_pin_hash, pin_hash);
        assert!(!sm.config_path.with_extension("transaction").exists());
    }

    #[test]
    fn interrupted_multi_vault_transaction_blocks_writes_and_replays_on_restart() {
        let (root, sm, folders) = transaction_fixture();
        let updates = folders
            .iter()
            .map(|p| {
                crate::vault::prepare_pin_rewrap(p, "1234", "5678")
                    .unwrap()
                    .unwrap()
            })
            .collect();
        let mut next = sm.config.read().clone();
        next.master_pin_hash = Some(hash_pin("5678").unwrap());
        // Simulate losing the second disk after preparation, after the first
        // update can be committed. No synthetic success/failure mock is used.
        let detached = root.path().join("detached");
        fs::rename(&folders[1], &detached).unwrap();
        assert!(sm.commit_credentials(next, updates).is_err());
        assert!(sm.ensure_ready().is_err());
        assert!(sm.save().is_err());
        assert!(sm.config_path.with_extension("transaction").exists());
        fs::rename(detached, &folders[1]).unwrap();
        let restarted = SecurityManager::from_path(sm.config_path.clone());
        restarted.ensure_ready().unwrap();
        assert!(restarted.verify_master_pin("5678").unwrap());
        assert!(!restarted.verify_master_pin("1234").unwrap());
        assert!(!restarted.config_path.with_extension("transaction").exists());
        let backup: AppGuardConfig = serde_json::from_slice(
            &fs::read(restarted.config_path.with_extension("json.bak")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            backup.master_pin_hash,
            restarted.config.read().master_pin_hash
        );
        for path in folders {
            crate::vault::unlock_folder(&path, "5678").unwrap();
        }
    }

    #[test]
    fn damaged_or_missing_primary_never_becomes_fresh_setup() {
        let root = tempfile::tempdir_in(fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, b"{}").unwrap();
        let damaged = SecurityManager::from_path(path.clone());
        assert!(damaged.ensure_ready().is_err());
        assert!(damaged.set_master_pin("1234").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"{}");
        fs::rename(&path, path.with_extension("json.bak")).unwrap();
        let missing = SecurityManager::from_path(path);
        assert!(missing.ensure_ready().is_err());
        assert!(!missing.is_app_authenticated());
    }

    #[test]
    fn legacy_pin_hash_upgrade_preserves_existing_credential_policy() {
        let root = tempfile::tempdir_in(fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
        let sm = SecurityManager::from_path(root.path().join("config.json"));
        let legacy_pin = "legacy-password";
        sm.config.write().master_pin_hash =
            Some(format!("{:x}", Sha256::digest(legacy_pin.as_bytes())));
        sm.save().unwrap();
        assert!(sm.verify_master_pin(legacy_pin).unwrap());
        assert!(
            sm.config
                .read()
                .master_pin_hash
                .as_ref()
                .unwrap()
                .starts_with("$argon2id$")
        );
        assert!(sm.verify_master_pin(legacy_pin).unwrap());
        assert!(sm.change_pin(legacy_pin, "invalid-new-pin").is_err());
        sm.change_pin(legacy_pin, "5678").unwrap();
        assert!(sm.verify_master_pin("5678").unwrap());
    }
}
