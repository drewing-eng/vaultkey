use crate::aead;
use crate::error::VaultKeyError;
use crate::master_key::MasterKey;
use crate::nonce::NonceTracker;
use uuid::Uuid;

/// Chiffre le contenu d'un fichier avec la clé maîtresse du coffre. Contrairement
/// au manifeste ou aux enveloppes, le blob de fichier ne contient PAS son propre
/// nonce : celui-ci est stocké séparément dans l'entrée de manifeste correspondante
/// (PRD §5.2, "index nom réel → nom de blob + nonce par fichier"), pas dans le
/// fichier `<blob-id>.enc` lui-même.
///
/// Retourne (identifiant de blob, nonce utilisé, ciphertext+tag à écrire tel quel).
pub fn encrypt_blob(
    plaintext: &[u8],
    master_key: &MasterKey,
    nonce_tracker: &mut NonceTracker,
) -> (String, [u8; 12], Vec<u8>) {
    let blob_id = Uuid::new_v4().to_string();
    let nonce = nonce_tracker.fresh();
    let ciphertext = aead::encrypt(master_key.as_bytes(), &nonce, plaintext);
    (blob_id, nonce, ciphertext)
}

/// Déchiffre un blob de fichier. Le nonce doit venir de l'entrée de manifeste
/// correspondante, pas du fichier `<blob-id>.enc` (qui ne le contient pas).
pub fn decrypt_blob(
    ciphertext: &[u8],
    nonce: &[u8; 12],
    master_key: &MasterKey,
) -> Result<Vec<u8>, VaultKeyError> {
    aead::decrypt(master_key.as_bytes(), nonce, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let master_key = MasterKey::generate();
        let mut tracker = NonceTracker::new();
        let plaintext = b"contenu du fichier de test";

        let (_blob_id, nonce, ciphertext) = encrypt_blob(plaintext, &master_key, &mut tracker);
        let recovered = decrypt_blob(&ciphertext, &nonce, &master_key).unwrap();

        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let master_key = MasterKey::generate();
        let other_key = MasterKey::generate();
        let mut tracker = NonceTracker::new();

        let (_blob_id, nonce, ciphertext) = encrypt_blob(b"secret", &master_key, &mut tracker);

        assert!(matches!(
            decrypt_blob(&ciphertext, &nonce, &other_key),
            Err(VaultKeyError::DecryptionFailed)
        ));
    }
}
