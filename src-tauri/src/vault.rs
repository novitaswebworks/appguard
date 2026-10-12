//! Versioned vault keys and resumable, no-clobber file transfers.
//! This protects data at rest; it cannot erase SSD snapshots or stop a process
//! running as the same user from changing files during an operation.
use crate::storage::{atomic_write, reject_symlinks, sync_directory};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use argon2::Argon2;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Seek, Write},
    path::{Component, Path, PathBuf},
};
use zeroize::Zeroizing;

const EXT: &str = ".appguard_vault";
const META: &str = ".appguard_vault_meta";
const STATUS: &str = ".appguard_status";
const JOURNAL: &str = ".appguard_transfer.json";
const WORK: &str = ".appguard_transfer.tmp";
const MAGIC: &[u8; 4] = b"AGV3";
const CHUNK: usize = 1024 * 1024;
const LEGACY_LIMIT: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultItem {
    pub path: String,
    pub name: String,
    pub is_locked: bool,
    pub file_count: usize,
    pub total_size_bytes: u64,
    pub status: String,
    pub recovery_enabled: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultMetadata {
    version: u8,
    salt: Vec<u8>,
    wrap_nonce: Vec<u8>,
    wrapped_key: Vec<u8>,
    #[serde(default)]
    recovery_salt: Option<Vec<u8>>,
    #[serde(default)]
    recovery_nonce: Option<Vec<u8>>,
    #[serde(default)]
    recovery_wrapped_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataUpdate {
    folder: PathBuf,
    metadata: VaultMetadata,
}
impl MetadataUpdate {
    pub fn commit(&self) -> Result<(), String> {
        validate_folder(&self.folder)?;
        write_metadata(&self.folder, &self.metadata)
    }
}

fn random<const N: usize>() -> [u8; N] {
    let mut value = [0; N];
    rand::rng().fill_bytes(&mut value);
    value
}
fn derive_kek(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
    if salt.len() != 16 {
        return Err("Invalid vault salt".into());
    }
    let mut key = Zeroizing::new([0; 32]);
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut *key)
        .map_err(|e| e.to_string())?;
    Ok(key)
}
fn wrap(key: &[u8; 32], secret: &str) -> Result<VaultMetadata, String> {
    let salt = random::<16>();
    let nonce = random::<12>();
    let kek = derive_kek(secret, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&*kek).map_err(|e| e.to_string())?;
    let wrapped_key = cipher
        .encrypt(&Nonce::from(nonce), key.as_ref())
        .map_err(|e| e.to_string())?;
    Ok(VaultMetadata {
        version: 3,
        salt: salt.to_vec(),
        wrap_nonce: nonce.to_vec(),
        wrapped_key,
        recovery_salt: None,
        recovery_nonce: None,
        recovery_wrapped_key: None,
    })
}
fn unwrap_parts(
    salt: &[u8],
    nonce: &[u8],
    wrapped: &[u8],
    secret: &str,
) -> Result<Zeroizing<[u8; 32]>, String> {
    if nonce.len() != 12 || wrapped.len() != 48 {
        return Err("Invalid vault key metadata".into());
    }
    let kek = derive_kek(secret, salt)?;
    let cipher = Aes256Gcm::new_from_slice(&*kek).map_err(|e| e.to_string())?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(&Nonce::from(<[u8; 12]>::try_from(nonce).unwrap()), wrapped)
            .map_err(|_| "Incorrect vault credential or damaged metadata".to_string())?,
    );
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(&plaintext);
    Ok(key)
}
fn unwrap(metadata: &VaultMetadata, secret: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    if !matches!(metadata.version, 2 | 3) {
        return Err("Unsupported vault metadata version".into());
    }
    unwrap_parts(
        &metadata.salt,
        &metadata.wrap_nonce,
        &metadata.wrapped_key,
        secret,
    )
}
fn read_metadata(folder: &Path) -> Result<Option<VaultMetadata>, String> {
    let path = folder.join(META);
    reject_symlinks(&path)?;
    match fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| e.to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}
fn write_metadata(folder: &Path, metadata: &VaultMetadata) -> Result<(), String> {
    atomic_write(
        &folder.join(META),
        &serde_json::to_vec(metadata).map_err(|e| e.to_string())?,
    )
}

fn validate_folder(folder: &Path) -> Result<(), String> {
    reject_symlinks(folder)?;
    if !folder.is_absolute() || !folder.is_dir() {
        return Err("Vault must be an existing absolute directory".into());
    }
    Ok(())
}

/// Fully enumerate before modifying anything. Never follow symlinks or silently
/// ignore an unreadable entry. Hard-linked plaintext is rejected as well.
fn files(folder: &Path) -> Result<Vec<PathBuf>, String> {
    fn visit(root: &Path, dir: &Path, output: &mut Vec<PathBuf>) -> Result<(), String> {
        for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();
            let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "Remove symbolic link from vault: {}",
                    path.display()
                ));
            }
            if meta.is_dir() {
                visit(root, &path, output)?;
            } else if meta.is_file() {
                let name = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .ok_or("Vault filenames must be valid Unicode")?;
                if dir == root && [META, STATUS, JOURNAL, WORK].contains(&name) {
                    continue;
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if meta.nlink() > 1 {
                        return Err(format!(
                            "Hard-linked file cannot be vaulted: {}",
                            path.display()
                        ));
                    }
                }
                output.push(path);
            } else {
                return Err(format!("Unsupported special file: {}", path.display()));
            }
        }
        Ok(())
    }
    validate_folder(folder)?;
    let mut output = Vec::new();
    visit(folder, folder, &mut output)?;
    output.sort();
    Ok(output)
}
fn encrypted(path: &Path) -> bool {
    path.to_string_lossy().ends_with(EXT)
}
fn has_encrypted(folder: &Path) -> Result<bool, String> {
    Ok(files(folder)?.iter().any(|p| encrypted(p)))
}

fn metadata_for_rotation(folder: &Path) -> Result<Option<VaultMetadata>, String> {
    validate_folder(folder)?;
    if folder.join(JOURNAL).exists() {
        return Err("Finish the interrupted vault operation before changing credentials".into());
    }
    match read_metadata(folder)? {
        Some(metadata) => Ok(Some(metadata)),
        None if has_encrypted(folder)? => Err(
            "Decrypt legacy vault files with their original PIN before changing credentials".into(),
        ),
        None => Ok(None),
    }
}
pub fn prepare_pin_rewrap(
    folder: &str,
    old: &str,
    new: &str,
) -> Result<Option<MetadataUpdate>, String> {
    let folder = PathBuf::from(folder);
    let Some(metadata) = metadata_for_rotation(&folder)? else {
        return Ok(None);
    };
    let key = unwrap(&metadata, old)?;
    let mut next = wrap(&key, new)?;
    next.version = metadata.version;
    next.recovery_salt = metadata.recovery_salt;
    next.recovery_nonce = metadata.recovery_nonce;
    next.recovery_wrapped_key = metadata.recovery_wrapped_key;
    Ok(Some(MetadataUpdate {
        folder,
        metadata: next,
    }))
}
pub fn prepare_recovery_wrapper(
    folder: &str,
    pin: &str,
    recovery: &str,
) -> Result<Option<MetadataUpdate>, String> {
    let folder = PathBuf::from(folder);
    let Some(mut metadata) = metadata_for_rotation(&folder)? else {
        return Ok(None);
    };
    let key = unwrap(&metadata, pin)?;
    let recovery = wrap(&key, recovery)?;
    metadata.recovery_salt = Some(recovery.salt);
    metadata.recovery_nonce = Some(recovery.wrap_nonce);
    metadata.recovery_wrapped_key = Some(recovery.wrapped_key);
    Ok(Some(MetadataUpdate { folder, metadata }))
}
pub fn prepare_recovery_rewrap(
    folder: &str,
    recovery: &str,
    new: &str,
) -> Result<Option<MetadataUpdate>, String> {
    let folder = PathBuf::from(folder);
    let Some(metadata) = metadata_for_rotation(&folder)? else {
        return Ok(None);
    };
    let key = unwrap_parts(
        metadata
            .recovery_salt
            .as_deref()
            .ok_or("Vault was not enrolled in this recovery key")?,
        metadata
            .recovery_nonce
            .as_deref()
            .ok_or("Vault was not enrolled in this recovery key")?,
        metadata
            .recovery_wrapped_key
            .as_deref()
            .ok_or("Vault was not enrolled in this recovery key")?,
        recovery,
    )?;
    let mut next = wrap(&key, new)?;
    next.version = metadata.version;
    Ok(Some(MetadataUpdate {
        folder,
        metadata: next,
    }))
}

fn data_key(folder: &Path, pin: &str, create: bool) -> Result<Zeroizing<[u8; 32]>, String> {
    if let Some(metadata) = read_metadata(folder)? {
        return unwrap(&metadata, pin);
    }
    if create {
        if has_encrypted(folder)? {
            return Err("Decrypt the legacy vault before migrating it".into());
        }
        let key = Zeroizing::new(random::<32>());
        write_metadata(folder, &wrap(&key, pin)?)?;
        Ok(key)
    } else {
        let mut hasher = Sha256::new();
        hasher.update(b"AppGuardVaultSecretKeySalt_v1_");
        hasher.update(pin.as_bytes());
        Ok(Zeroizing::new(hasher.finalize().into()))
    }
}

fn file_hash(path: &Path) -> Result<String, String> {
    reject_symlinks(path)?;
    let mut file = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut hash = Sha256::new();
    let mut buffer = Zeroizing::new(vec![0; CHUNK]);
    loop {
        let len = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if len == 0 {
            break;
        }
        hash.update(&buffer[..len]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

#[derive(Serialize, Deserialize)]
struct Transfer {
    source: PathBuf,
    target: PathBuf,
    source_hash: String,
    target_hash: String,
}
fn contained(root: &Path, relative: &Path) -> Result<PathBuf, String> {
    if relative
        .components()
        .any(|c| !matches!(c, Component::Normal(_)))
        || relative.as_os_str().is_empty()
    {
        return Err("Invalid vault journal path".into());
    }
    let path = root.join(relative);
    reject_symlinks(&path)?;
    Ok(path)
}
fn finish_transfer(root: &Path) -> Result<(), String> {
    let journal = root.join(JOURNAL);
    reject_symlinks(&journal)?;
    if !journal.exists() {
        let work = root.join(WORK);
        reject_symlinks(&work)?;
        // Without a journal we cannot establish ownership of this filename.
        if work.exists() {
            return Err("Unjournaled vault scratch file found. Move .appguard_transfer.tmp outside the vault before retrying; original files are retained.".into());
        }
        return Ok(());
    }
    let transfer: Transfer =
        serde_json::from_slice(&fs::read(&journal).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let source = contained(root, &transfer.source)?;
    let target = contained(root, &transfer.target)?;
    if source == target {
        return Err("Invalid vault transfer: source equals destination".into());
    }
    let work = root.join(WORK);
    reject_symlinks(&work)?;
    if !target.exists() {
        if file_hash(&work)? != transfer.target_hash {
            return Err("Vault scratch checksum mismatch; source retained".into());
        }
        // hard_link is an atomic no-clobber publication on the same volume.
        fs::hard_link(&work, &target)
            .map_err(|e| format!("Cannot publish vault file without overwriting: {e}"))?;
        sync_directory(target.parent().ok_or("No parent")?)?;
    }
    if file_hash(&target)? != transfer.target_hash {
        return Err("Vault destination changed; source retained".into());
    }
    if source.exists() {
        if file_hash(&source)? != transfer.source_hash {
            return Err("Source changed while vaulting; both copies retained".into());
        }
        fs::remove_file(&source).map_err(|e| e.to_string())?;
        sync_directory(source.parent().ok_or("No parent")?)?;
    }
    if work.exists() {
        fs::remove_file(work).map_err(|e| e.to_string())?;
    }
    fs::remove_file(journal).map_err(|e| e.to_string())?;
    sync_directory(root)
}

fn mode(metadata: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o777
    }
    #[cfg(not(unix))]
    {
        if metadata.permissions().readonly() {
            0o400
        } else {
            0o600
        }
    }
}
fn restore_mode(file: &fs::File, value: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(value & 0o777))
            .map_err(|e| e.to_string())?;
    }
    #[cfg(not(unix))]
    {
        let mut permissions = file.metadata().map_err(|e| e.to_string())?.permissions();
        permissions.set_readonly(value & 0o200 == 0);
        file.set_permissions(permissions)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}
fn chunk_nonce(prefix: &[u8], index: u32) -> [u8; 12] {
    let mut nonce = [0; 12];
    nonce[..8].copy_from_slice(prefix);
    nonce[8..].copy_from_slice(&index.to_be_bytes());
    nonce
}
fn transform(
    source: &Path,
    output: &mut fs::File,
    cipher: &Aes256Gcm,
    encrypt: bool,
    legacy: bool,
) -> Result<(), String> {
    let mut input = fs::File::open(source).map_err(|e| e.to_string())?;
    let metadata = input.metadata().map_err(|e| e.to_string())?;
    let old_format = if !encrypt && legacy {
        let mut prefix = [0; 4];
        input.read_exact(&mut prefix).map_err(|e| e.to_string())?;
        input.rewind().map_err(|e| e.to_string())?;
        &prefix != MAGIC
    } else {
        false
    };
    if old_format {
        if metadata.len() > LEGACY_LIMIT {
            return Err(
                "Legacy files above 128 MiB need offline migration; original retained".into(),
            );
        }
        let mut bytes = Zeroizing::new(Vec::new());
        input.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
        if bytes.len() < 28 {
            return Err("Truncated legacy ciphertext".into());
        }
        let nonce: [u8; 12] = bytes[..12].try_into().unwrap();
        let plain = Zeroizing::new(
            cipher
                .decrypt(&Nonce::from(nonce), &bytes[12..])
                .map_err(|_| "Incorrect legacy PIN or damaged ciphertext")?,
        );
        output.write_all(&plain).map_err(|e| e.to_string())?;
        return Ok(());
    }
    let mut header = [0u8; 24];
    if encrypt {
        header[..4].copy_from_slice(MAGIC);
        header[4..12].copy_from_slice(&random::<8>());
        header[12..20].copy_from_slice(&metadata.len().to_be_bytes());
        header[20..].copy_from_slice(&mode(&metadata).to_be_bytes());
        output.write_all(&header).map_err(|e| e.to_string())?;
    } else {
        input.read_exact(&mut header).map_err(|e| e.to_string())?;
        if &header[..4] != MAGIC {
            return Err("Unsupported vault file version".into());
        }
    }
    let size = u64::from_be_bytes(header[12..20].try_into().unwrap());
    let chunks = (size.div_ceil(CHUNK as u64)).max(1);
    if chunks > u32::MAX as u64 {
        return Err("Vault file too large".into());
    }
    if !encrypt && metadata.len() != 24 + size + 16 * chunks {
        return Err("Truncated or extended vault file".into());
    }
    let mut remaining = size;
    for index in 0..chunks as u32 {
        let count = remaining.min(CHUNK as u64) as usize;
        let mut buffer = Zeroizing::new(vec![0; count + if encrypt { 0 } else { 16 }]);
        input.read_exact(&mut buffer).map_err(|e| e.to_string())?;
        let nonce = Nonce::from(chunk_nonce(&header[4..12], index));
        let payload = Payload {
            msg: &buffer,
            aad: &header,
        };
        let transformed = Zeroizing::new(
            if encrypt {
                cipher.encrypt(&nonce, payload)
            } else {
                cipher.decrypt(&nonce, payload)
            }
            .map_err(|_| "Vault authentication failed; encrypted source retained")?,
        );
        output.write_all(&transformed).map_err(|e| e.to_string())?;
        remaining -= count as u64;
    }
    let mut extra = [0];
    if input.read(&mut extra).map_err(|e| e.to_string())? != 0 {
        return Err("File changed while processing".into());
    }
    if !encrypt {
        restore_mode(output, u32::from_be_bytes(header[20..].try_into().unwrap()))?;
    }
    Ok(())
}

fn transfer(
    root: &Path,
    source: &Path,
    target: &Path,
    cipher: &Aes256Gcm,
    encrypt: bool,
    legacy: bool,
) -> Result<(), String> {
    reject_symlinks(source)?;
    reject_symlinks(target)?;
    if target.exists() {
        return Err(format!("Refusing to overwrite {}", target.display()));
    }
    let source_hash = file_hash(source)?;
    let work = root.join(WORK);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(&work).map_err(|e| e.to_string())?;
    if let Err(error) = transform(source, &mut output, cipher, encrypt, legacy) {
        drop(output);
        // This invocation created the scratch; a failed authentication must
        // not leave partially decrypted plaintext behind.
        fs::remove_file(&work)
            .map_err(|cleanup| format!("{error}; scratch cleanup failed: {cleanup}"))?;
        return Err(error);
    }
    // Preserve basic timestamps; extended attributes/ACLs need external backup.
    if let Ok(modified) = fs::metadata(source).and_then(|m| m.modified()) {
        output.set_modified(modified).map_err(|e| e.to_string())?;
    }
    output.sync_all().map_err(|e| e.to_string())?;
    drop(output);
    if file_hash(source)? != source_hash {
        return Err("Source changed during vault operation; source retained".into());
    }
    let transfer = Transfer {
        source: source.strip_prefix(root).map_err(|e| e.to_string())?.into(),
        target: target.strip_prefix(root).map_err(|e| e.to_string())?.into(),
        source_hash,
        target_hash: file_hash(&work)?,
    };
    atomic_write(
        &root.join(JOURNAL),
        &serde_json::to_vec(&transfer).map_err(|e| e.to_string())?,
    )?;
    finish_transfer(root)
}

fn operate(folder: &str, pin: &str, encrypt: bool) -> Result<bool, String> {
    let root = Path::new(folder);
    validate_folder(root)?;
    // Old macOS releases removed all permissions. Restore owner-only access
    // for migration, never world-readable 0755.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(root)
            .map_err(|e| e.to_string())?
            .permissions()
            .mode()
            & 0o777
            == 0
        {
            fs::set_permissions(root, fs::Permissions::from_mode(0o700))
                .map_err(|e| e.to_string())?;
        }
    }
    let metadata = read_metadata(root)?;
    let legacy = metadata
        .as_ref()
        .is_none_or(|metadata| metadata.version == 2);
    // Authenticate the key before resuming a journal that can remove sources.
    let existing_key = if let Some(metadata) = &metadata {
        Some(unwrap(metadata, pin)?)
    } else {
        None
    };
    finish_transfer(root)?;
    let entries = files(root)?;
    // Validate every destination before deleting any source.
    let mut pairs = Vec::new();
    for path in &entries {
        if encrypted(path) == encrypt {
            continue;
        }
        let text = path.to_str().ok_or("Invalid filename")?;
        let target = if encrypt {
            PathBuf::from(format!("{text}{EXT}"))
        } else {
            PathBuf::from(
                text.strip_suffix(EXT)
                    .ok_or("Invalid ciphertext filename")?,
            )
        };
        if target.exists() {
            return Err(format!("Destination already exists: {}", target.display()));
        }
        pairs.push((path, target));
    }
    let key = match existing_key {
        Some(key) => key,
        None => data_key(root, pin, encrypt)?,
    };
    let cipher = Aes256Gcm::new_from_slice(&*key).map_err(|e| e.to_string())?;
    atomic_write(
        &root.join(STATUS),
        if encrypt {
            b"ENCRYPTING"
        } else {
            b"DECRYPTING"
        },
    )?;
    for (source, target) in pairs {
        transfer(root, source, &target, &cipher, encrypt, legacy)?;
    }
    if encrypt {
        atomic_write(&root.join(STATUS), b"LOCKED")?;
    } else {
        fs::remove_file(root.join(STATUS)).map_err(|e| e.to_string())?;
        sync_directory(root)?;
    }
    Ok(true)
}
pub fn lock_folder(folder: &str, pin: &str) -> Result<bool, String> {
    operate(folder, pin, true)
}
pub fn unlock_folder(folder: &str, pin: &str) -> Result<bool, String> {
    operate(folder, pin, false)
}

pub fn inspect_vault(folder: &str) -> Option<VaultItem> {
    let root = Path::new(folder);
    let scan = files(root);
    let marker = fs::read_to_string(root.join(STATUS)).unwrap_or_default();
    let metadata = read_metadata(root);
    let recovery_enabled = metadata
        .as_ref()
        .ok()
        .and_then(|m| m.as_ref())
        .is_some_and(|m| m.recovery_wrapped_key.is_some());
    let error = scan.as_ref().err().cloned().or_else(|| metadata.err());
    let paths = scan.unwrap_or_default();
    let has_ciphertext = paths.iter().any(|p| encrypted(p));
    let has_plaintext = paths.iter().any(|p| !encrypted(p));
    let partial = root.join(JOURNAL).exists()
        || ["ENCRYPTING", "DECRYPTING"].contains(&marker.as_str())
        || (has_plaintext && (has_ciphertext || marker == "LOCKED"));
    let status = if error.is_some() {
        "unavailable"
    } else if partial {
        "partial"
    } else if has_ciphertext || marker == "LOCKED" {
        "encrypted"
    } else {
        "open"
    };
    Some(VaultItem {
        path: folder.into(),
        name: root
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into(),
        is_locked: has_ciphertext || !marker.is_empty() || error.is_some(),
        file_count: paths.len(),
        total_size_bytes: paths
            .iter()
            .filter_map(|p| fs::metadata(p).ok())
            .map(|m| m.len())
            .sum(),
        status: status.into(),
        recovery_enabled,
        error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn folder() -> tempfile::TempDir {
        tempfile::tempdir_in(fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap()
    }
    #[test]
    fn nested_chunked_roundtrip_preserves_names_and_detects_tampering() {
        let dir = folder();
        let root = dir.path();
        fs::create_dir(root.join("nested")).unwrap();
        let source = root.join("nested/README");
        let bytes = vec![42; CHUNK + 37];
        fs::write(&source, &bytes).unwrap();
        fs::write(root.join("empty"), []).unwrap();
        lock_folder(root.to_str().unwrap(), "1234").unwrap();
        assert!(!source.exists());
        let encrypted = root.join("nested/README.appguard_vault");
        let original = fs::read(&encrypted).unwrap();
        let mut bad = original.clone();
        bad[30] ^= 1;
        fs::write(&encrypted, &bad).unwrap();
        assert!(unlock_folder(root.to_str().unwrap(), "1234").is_err());
        assert!(encrypted.exists());
        fs::write(&encrypted, original).unwrap();
        unlock_folder(root.to_str().unwrap(), "1234").unwrap();
        assert_eq!(fs::read(&source).unwrap(), bytes);
        assert_eq!(fs::read(root.join("empty")).unwrap().len(), 0);
    }
    #[test]
    fn refuses_collision_before_modifying_plaintext() {
        let dir = folder();
        let root = dir.path();
        fs::write(root.join("a"), b"original").unwrap();
        fs::write(root.join("a.appguard_vault"), b"existing").unwrap();
        assert!(lock_folder(root.to_str().unwrap(), "1234").is_err());
        assert_eq!(fs::read(root.join("a")).unwrap(), b"original");
    }
    #[test]
    fn pin_and_recovery_rewrap_preserve_data() {
        let dir = folder();
        let root = dir.path();
        let path = root.to_str().unwrap();
        fs::write(root.join("file"), b"secret").unwrap();
        lock_folder(path, "1234").unwrap();
        prepare_recovery_wrapper(path, "1234", "RECOVERY")
            .unwrap()
            .unwrap()
            .commit()
            .unwrap();
        prepare_pin_rewrap(path, "1234", "5678")
            .unwrap()
            .unwrap()
            .commit()
            .unwrap();
        assert!(unlock_folder(path, "1234").is_err());
        prepare_recovery_rewrap(path, "RECOVERY", "9876")
            .unwrap()
            .unwrap()
            .commit()
            .unwrap();
        assert!(prepare_recovery_rewrap(path, "RECOVERY", "0000").is_err());
        unlock_folder(path, "9876").unwrap();
        assert_eq!(fs::read(root.join("file")).unwrap(), b"secret");
    }
    #[test]
    fn interrupted_published_transfer_is_resumed_without_overwrite() {
        let dir = folder();
        let root = dir.path();
        fs::write(root.join("a"), b"source").unwrap();
        fs::write(root.join(WORK), b"dest").unwrap();
        let journal = Transfer {
            source: "a".into(),
            target: "b".into(),
            source_hash: file_hash(&root.join("a")).unwrap(),
            target_hash: file_hash(&root.join(WORK)).unwrap(),
        };
        atomic_write(&root.join(JOURNAL), &serde_json::to_vec(&journal).unwrap()).unwrap();
        fs::hard_link(root.join(WORK), root.join("b")).unwrap();
        finish_transfer(root).unwrap();
        assert!(!root.join("a").exists());
        assert_eq!(fs::read(root.join("b")).unwrap(), b"dest");
    }
    #[cfg(unix)]
    #[test]
    fn symlink_is_rejected_before_any_file_changes() {
        let dir = folder();
        let external = folder();
        fs::write(dir.path().join("a"), b"safe").unwrap();
        std::os::unix::fs::symlink(external.path(), dir.path().join("link")).unwrap();
        assert!(lock_folder(dir.path().to_str().unwrap(), "1234").is_err());
        assert_eq!(fs::read(dir.path().join("a")).unwrap(), b"safe");
    }

    #[test]
    fn reads_v2_ciphertext_after_pin_and_recovery_rotation() {
        let dir = folder();
        let root = dir.path();
        let path = root.to_str().unwrap();
        let key = random::<32>();
        let mut metadata = wrap(&key, "1234").unwrap();
        metadata.version = 2;
        write_metadata(root, &metadata).unwrap();
        let nonce = [7; 12];
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let mut payload = nonce.to_vec();
        payload.extend(
            cipher
                .encrypt(&Nonce::from(nonce), b"v2 data".as_ref())
                .unwrap(),
        );
        fs::write(root.join("old.txt.appguard_vault"), payload).unwrap();
        fs::write(root.join("new"), b"chunked data").unwrap();
        lock_folder(path, "1234").unwrap();
        prepare_recovery_wrapper(path, "1234", "KEY")
            .unwrap()
            .unwrap()
            .commit()
            .unwrap();
        prepare_pin_rewrap(path, "1234", "5678")
            .unwrap()
            .unwrap()
            .commit()
            .unwrap();
        prepare_recovery_rewrap(path, "KEY", "9876")
            .unwrap()
            .unwrap()
            .commit()
            .unwrap();
        unlock_folder(path, "9876").unwrap();
        assert_eq!(fs::read(root.join("old.txt")).unwrap(), b"v2 data");
        assert_eq!(fs::read(root.join("new")).unwrap(), b"chunked data");
    }

    #[test]
    fn legacy_v1_roundtrip_preserves_the_recorded_filename() {
        let dir = folder();
        let root = dir.path();
        let path = root.to_str().unwrap();
        let key = data_key(root, "1234", false).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&*key).unwrap();
        let nonce = [9; 12];
        let mut payload = nonce.to_vec();
        payload.extend(
            cipher
                .encrypt(&Nonce::from(nonce), b"legacy".as_ref())
                .unwrap(),
        );
        // v1 encoded extensionless names with an extra dot. It cannot be
        // distinguished from an actual trailing dot, so retain the recorded name.
        fs::write(root.join("README..appguard_vault"), payload).unwrap();
        unlock_folder(path, "1234").unwrap();
        assert_eq!(fs::read(root.join("README.")).unwrap(), b"legacy");
        lock_folder(path, "1234").unwrap();
        unlock_folder(path, "1234").unwrap();
        assert_eq!(fs::read(root.join("README.")).unwrap(), b"legacy");
    }

    #[test]
    fn unknown_scratch_is_never_deleted() {
        let dir = folder();
        let root = dir.path();
        fs::write(root.join(WORK), b"user data").unwrap();
        assert!(lock_folder(root.to_str().unwrap(), "1234").is_err());
        assert_eq!(fs::read(root.join(WORK)).unwrap(), b"user data");
    }
}
