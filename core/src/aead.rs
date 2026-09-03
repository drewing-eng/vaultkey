//! Primitive AES-256-GCM partagée par blob.rs, manifest.rs et envelope.rs.
//! Module interne : ce fichier ne décide jamais lui-même d'un nonce, il ne
//! fait qu'exécuter le chiffrement/déchiffrement pour un nonce déjà choisi
//! par l'appelant (via `NonceTracker`).

use crate::error::VaultKeyError;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};

/// Chiffre `plaintext` avec `key` et `nonce`. Le résultat contient le tag
/// d'authentification à la fin (convention de la crate `aes-gcm`).
pub fn encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));
    cipher
        .encrypt(&Nonce::from(*nonce), plaintext)
        .expect("le chiffrement AES-GCM ne peut échouer que sur une entrée absurdement longue")
}

/// Déchiffre `ciphertext` (contenant le tag) avec `key` et `nonce`.
pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, VaultKeyError> {
    let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key));
    cipher
        .decrypt(&Nonce::from(*nonce), ciphertext)
        .map_err(|_| VaultKeyError::DecryptionFailed)
}

/// Concatène nonce ∥ (ciphertext ∥ tag) en un seul blob opaque, tel que
/// stocké dans `wrappedMasterKey` (PRD §5.3) et dans les blobs de fichiers.
pub fn pack(nonce: &[u8; 12], ciphertext_with_tag: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + ciphertext_with_tag.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ciphertext_with_tag);
    out
}

/// Sépare un blob packé en (nonce, ciphertext_with_tag). Erreur si le blob
/// est plus court que la taille du nonce seul.
pub fn unpack(data: &[u8]) -> Result<(&[u8; 12], &[u8]), VaultKeyError> {
    if data.len() < 12 {
        return Err(VaultKeyError::MalformedCiphertext);
    }
    let (nonce_slice, ciphertext) = data.split_at(12);
    let nonce: &[u8; 12] = nonce_slice
        .try_into()
        .expect("split_at(12) garantit une tranche de 12 octets");
    Ok((nonce, ciphertext))
}
