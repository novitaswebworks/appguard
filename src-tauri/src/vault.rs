use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

const NONCE_SIZE: usize = 12; // 96-bit nonce for AES-GCM
const VAULT_EXT: &str = ".appguard_vault";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultItem {
    pub path: String,
    pub name: String,
    pub is_locked: bool,
    pub file_count: usize,
    pub total_size_bytes: u64,
}

/// Derives a 256-bit AES key from a passphrase/PIN using SHA-256
fn derive_key(passphrase: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"AppGuardVaultSecretKeySalt_v1_");
    hasher.update(passphrase.as_bytes());
    hasher.finalize().into()
}

/// Encrypts all files inside a directory in-place with AES-256-GCM and enforces OS-level folder shielding
pub fn lock_folder(folder_path_str: &str, passphrase: &str) -> Result<bool, String> {
    let folder = Path::new(folder_path_str);
    if !folder.exists() || !folder.is_dir() {
        return Err("Target folder does not exist or is not a directory".into());
    }

    let key_bytes = derive_key(passphrase);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| format!("Cipher initialization failed: {e}"))?;

    encrypt_directory_recursive(folder, &cipher)?;

    // Create marker file indicating the vault is locked
    let marker = folder.join(".appguard_status");
    let _ = fs::write(marker, b"LOCKED");

    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        // Hide the folder in Finder and set permission shield
        let _ = Command::new("chflags").arg("hidden").arg(folder_path_str).status();
        let _ = Command::new("chmod").arg("000").arg(folder_path_str).status();
    }

    Ok(true)
}

/// Decrypts all files inside a directory in-place with AES-256-GCM and restores normal folder access
pub fn unlock_folder(folder_path_str: &str, passphrase: &str) -> Result<bool, String> {
    let folder = Path::new(folder_path_str);
    if !folder.exists() || !folder.is_dir() {
        return Err("Target folder does not exist or is not a directory".into());
    }

    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        // First restore permissions so files can be decrypted
        let _ = Command::new("chmod").arg("755").arg(folder_path_str).status();
        let _ = Command::new("chflags").arg("nohidden").arg(folder_path_str).status();
    }

    let key_bytes = derive_key(passphrase);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| format!("Cipher initialization failed: {e}"))?;

    decrypt_directory_recursive(folder, &cipher)?;

    // Remove status marker
    let marker = folder.join(".appguard_status");
    let _ = fs::remove_file(marker);

    Ok(true)
}

fn encrypt_directory_recursive(dir: &Path, cipher: &Aes256Gcm) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|e| e.to_string())?;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            let filename = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            // Skip hidden status file, temporary staging files, or already encrypted vault files
            if filename == ".appguard_status" || filename.ends_with(VAULT_EXT) || filename.ends_with(".staging") {
                continue;
            }

            let plaintext = fs::read(&path).map_err(|e| e.to_string())?;
            // Generate cryptographically random 12-byte nonce
            let mut nonce_bytes = [0u8; NONCE_SIZE];
            rand::rng().fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from(nonce_bytes);

            let ciphertext = cipher
                .encrypt(&nonce, plaintext.as_ref())
                .map_err(|e| format!("Encryption failed: {e}"))?;

            // Store nonce (12 bytes) + ciphertext
            let mut payload = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
            payload.extend_from_slice(&nonce_bytes);
            payload.extend_from_slice(&ciphertext);

            let encrypted_path = path.with_extension(format!(
                "{}{VAULT_EXT}",
                path.extension().and_then(|s| s.to_str()).unwrap_or("")
            ));
            let staging_path = encrypted_path.with_extension("staging");

            // Transaction step 1: Write to staging file and flush to disk
            fs::write(&staging_path, &payload).map_err(|e| e.to_string())?;

            // Transaction step 2: Verify written file matches payload
            let written_len = fs::metadata(&staging_path).map(|m| m.len()).unwrap_or(0);
            if written_len != payload.len() as u64 {
                let _ = fs::remove_file(&staging_path);
                return Err("Vault transaction failed: staging file size mismatch".into());
            }

            // Transaction step 3: Atomically rename staging file into place
            fs::rename(&staging_path, &encrypted_path).map_err(|e| e.to_string())?;

            // Transaction step 4: Only now delete original plaintext file safely
            let _ = fs::remove_file(&path);
        } else if path.is_dir() {
            encrypt_directory_recursive(&path, cipher)?;
        }
    }

    Ok(())
}

fn decrypt_directory_recursive(dir: &Path, cipher: &Aes256Gcm) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|e| e.to_string())?;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            let path_str = path.to_string_lossy();
            if path_str.ends_with(VAULT_EXT) {
                let payload = fs::read(&path).map_err(|e| e.to_string())?;
                if payload.len() < NONCE_SIZE {
                    continue;
                }

                let nonce_bytes = &payload[0..NONCE_SIZE];
                let ciphertext = &payload[NONCE_SIZE..];
                let mut nonce_arr = [0u8; NONCE_SIZE];
                nonce_arr.copy_from_slice(nonce_bytes);
                let nonce = Nonce::from(nonce_arr);

                let plaintext = cipher
                    .decrypt(&nonce, ciphertext)
                    .map_err(|e| format!("Decryption failed (incorrect key or corrupted data): {e}"))?;

                // Strip .appguard_vault suffix
                let restored_path_str = path_str.trim_end_matches(VAULT_EXT);
                let restored_path = PathBuf::from(restored_path_str);
                let staging_path = restored_path.with_extension("staging_dec");

                // Transaction step 1: Write decrypted plaintext to staging file
                fs::write(&staging_path, &plaintext).map_err(|e| e.to_string())?;

                // Transaction step 2: Verify decrypted length
                let written_len = fs::metadata(&staging_path).map(|m| m.len()).unwrap_or(0);
                if written_len != plaintext.len() as u64 {
                    let _ = fs::remove_file(&staging_path);
                    return Err("Vault transaction failed: decrypted size mismatch".into());
                }

                // Transaction step 3: Atomically rename staging file to restored path
                fs::rename(&staging_path, &restored_path).map_err(|e| e.to_string())?;

                // Transaction step 4: Only now delete encrypted container file
                let _ = fs::remove_file(&path);
            }
        } else if path.is_dir() {
            decrypt_directory_recursive(&path, cipher)?;
        }
    }

    Ok(())
}

/// Scans a folder to check its status (locked/unlocked) and size
pub fn inspect_vault(path_str: &str) -> Option<VaultItem> {
    let path = Path::new(path_str);
    if !path.exists() || !path.is_dir() {
        return None;
    }

    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(path_str)
        .to_string();

    let is_locked = path.join(".appguard_status").exists() || {
        // If chmod 000 is active, fs::read_dir or status check will encounter permission denied
        fs::read_dir(path).is_err()
    };
    let mut file_count = 0;
    let mut total_size = 0;

    count_files_and_size(path, &mut file_count, &mut total_size);

    Some(VaultItem {
        path: path_str.to_string(),
        name,
        is_locked,
        file_count,
        total_size_bytes: total_size,
    })
}

fn count_files_and_size(dir: &Path, count: &mut usize, size: &mut u64) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file() {
                if let Ok(meta) = p.metadata() {
                    *count += 1;
                    *size += meta.len();
                }
            } else if p.is_dir() {
                count_files_and_size(&p, count, size);
            }
        }
    }
}
