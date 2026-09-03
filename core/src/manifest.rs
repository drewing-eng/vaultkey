use crate::aead;
use crate::error::VaultKeyError;
use crate::master_key::MasterKey;
use crate::nonce::NonceTracker;
use base64::prelude::*;
use serde::{Deserialize, Serialize};

/// Une entrée par fichier stocké dans le coffre (PRD §5.2). Le manifeste
/// entier est chiffré en bloc, donc `real_name` n'apparaît jamais en clair
/// sur disque, uniquement une fois le manifeste déchiffré en mémoire.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileEntry {
    pub real_name: String,
    pub blob_id: String,
    pub nonce: String,
    pub size: u64,
    pub modified: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Manifest {
    pub entries: Vec<FileEntry>,
}

impl Manifest {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn find(&self, real_name: &str) -> Option<&FileEntry> {
        self.entries.iter().find(|e| e.real_name == real_name)
    }

    pub fn remove(&mut self, real_name: &str) -> Option<FileEntry> {
        let index = self.entries.iter().position(|e| e.real_name == real_name)?;
        Some(self.entries.remove(index))
    }
}

/// Chiffre le manifeste entier (`manifest.enc`, PRD §5.1). Contrairement aux
/// entrées de fichier, le manifeste n'a pas d'endroit externe où stocker son
/// propre nonce : celui-ci est donc packé au début du fichier produit, comme
/// pour les enveloppes de clé.
pub fn encrypt_manifest(
    manifest: &Manifest,
    master_key: &MasterKey,
    nonce_tracker: &mut NonceTracker,
) -> Vec<u8> {
    let json = serde_json::to_vec(manifest).expect("Manifest sérialise toujours en JSON valide");
    let nonce = nonce_tracker.fresh();
    let ciphertext = aead::encrypt(master_key.as_bytes(), &nonce, &json);
    aead::pack(&nonce, ciphertext)
}

pub fn decrypt_manifest(data: &[u8], master_key: &MasterKey) -> Result<Manifest, VaultKeyError> {
    let (nonce, ciphertext) = aead::unpack(data)?;
    let json = aead::decrypt(master_key.as_bytes(), nonce, ciphertext)?;
    serde_json::from_slice(&json).map_err(|_| VaultKeyError::MalformedManifest)
}

pub fn encode_nonce(nonce: &[u8; 12]) -> String {
    BASE64_STANDARD.encode(nonce)
}

pub fn decode_nonce(nonce_b64: &str) -> Result<[u8; 12], VaultKeyError> {
    let bytes = BASE64_STANDARD
        .decode(nonce_b64)
        .map_err(|_| VaultKeyError::MalformedCiphertext)?;
    bytes.try_into().map_err(|_| VaultKeyError::MalformedCiphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let master_key = MasterKey::generate();
        let mut tracker = NonceTracker::new();
        let mut manifest = Manifest::new();
        manifest.entries.push(FileEntry {
            real_name: "facture_janvier.pdf".into(),
            blob_id: "blob-1".into(),
            nonce: encode_nonce(&[7u8; 12]),
            size: 214_000,
            modified: 1_787_000_000,
        });

        let encrypted = encrypt_manifest(&manifest, &master_key, &mut tracker);
        let decrypted = decrypt_manifest(&encrypted, &master_key).unwrap();

        assert_eq!(decrypted.entries.len(), 1);
        assert_eq!(decrypted.entries[0].real_name, "facture_janvier.pdf");
    }

    #[test]
    fn encrypted_manifest_does_not_leak_filename() {
        let master_key = MasterKey::generate();
        let mut tracker = NonceTracker::new();
        let mut manifest = Manifest::new();
        let secret_name = "diagnostic_médical_confidentiel.pdf";
        manifest.entries.push(FileEntry {
            real_name: secret_name.into(),
            blob_id: "blob-1".into(),
            nonce: encode_nonce(&[1u8; 12]),
            size: 42,
            modified: 0,
        });

        let encrypted = encrypt_manifest(&manifest, &master_key, &mut tracker);

        assert!(!encrypted
            .windows(secret_name.len())
            .any(|window| window == secret_name.as_bytes()));
    }

    #[test]
    fn wrong_key_fails() {
        let master_key = MasterKey::generate();
        let other_key = MasterKey::generate();
        let mut tracker = NonceTracker::new();
        let manifest = Manifest::new();

        let encrypted = encrypt_manifest(&manifest, &master_key, &mut tracker);

        assert!(matches!(
            decrypt_manifest(&encrypted, &other_key),
            Err(VaultKeyError::DecryptionFailed)
        ));
    }
}
