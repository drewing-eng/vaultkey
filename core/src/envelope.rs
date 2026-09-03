use crate::aead;
use crate::error::VaultKeyError;
use crate::master_key::MasterKey;
use crate::nonce::NonceTracker;
use base64::prelude::*;
use rand::{rngs::SysRng, TryRng};
use serde::{Deserialize, Serialize};

/// Une entrée par YubiKey autorisée sur ce coffre (PRD §5.3). `salt` n'est
/// pas secret (sert à différencier les sorties PRF, pas à protéger à lui
/// seul), `wrapped_master_key` l'est.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct YubikeyEnvelope {
    pub credential_id: String,
    pub salt: String,
    pub wrapped_master_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryPhraseEnvelope {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrapped_master_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct KeyEnvelopes {
    pub yubikeys: Vec<YubikeyEnvelope>,
    pub recovery_phrase: RecoveryPhraseEnvelope,
}

/// Génère un sel frais pour associer une nouvelle YubiKey à un coffre. Pas
/// secret, uniquement là pour différencier les sorties PRF d'une même clé
/// physique entre plusieurs coffres (PRD §5.3).
pub fn generate_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    SysRng
        .try_fill_bytes(&mut salt)
        .expect("le générateur aléatoire du système doit toujours réussir");
    salt
}

/// Enveloppe (chiffre) la clé maîtresse avec une clé de wrap (sortie PRF pour
/// une YubiKey, ou dérivée BIP39 pour la récupération). Retourne le blob
/// opaque en base64 tel que stocké dans `wrappedMasterKey`.
pub fn wrap_master_key(
    master_key: &MasterKey,
    wrap_key: &[u8; 32],
    nonce_tracker: &mut NonceTracker,
) -> String {
    let nonce = nonce_tracker.fresh();
    let ciphertext = aead::encrypt(wrap_key, &nonce, master_key.as_bytes());
    let packed = aead::pack(&nonce, ciphertext);
    BASE64_STANDARD.encode(packed)
}

/// Déballe la clé maîtresse depuis un blob `wrappedMasterKey` avec la clé de
/// wrap correspondante.
pub fn unwrap_master_key(
    wrapped_b64: &str,
    wrap_key: &[u8; 32],
) -> Result<MasterKey, VaultKeyError> {
    let packed = BASE64_STANDARD
        .decode(wrapped_b64)
        .map_err(|_| VaultKeyError::MalformedCiphertext)?;
    let (nonce, ciphertext) = aead::unpack(&packed)?;
    let plaintext = aead::decrypt(wrap_key, nonce, ciphertext)?;
    let bytes: [u8; 32] = plaintext
        .try_into()
        .map_err(|_| VaultKeyError::MalformedCiphertext)?;
    Ok(MasterKey::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let master_key = MasterKey::generate();
        let wrap_key = generate_salt(); // n'importe quelle valeur 32 octets fait l'affaire ici
        let mut tracker = NonceTracker::new();

        let wrapped = wrap_master_key(&master_key, &wrap_key, &mut tracker);
        let unwrapped = unwrap_master_key(&wrapped, &wrap_key).unwrap();

        assert_eq!(master_key.as_bytes(), unwrapped.as_bytes());
    }

    #[test]
    fn wrong_wrap_key_fails_without_panic() {
        let master_key = MasterKey::generate();
        let wrap_key = generate_salt();
        let wrong_key = generate_salt();
        let mut tracker = NonceTracker::new();

        let wrapped = wrap_master_key(&master_key, &wrap_key, &mut tracker);

        assert!(matches!(
            unwrap_master_key(&wrapped, &wrong_key),
            Err(VaultKeyError::DecryptionFailed)
        ));
    }

    #[test]
    fn key_envelopes_serialize_matches_prd_schema() {
        let envelopes = KeyEnvelopes {
            yubikeys: vec![YubikeyEnvelope {
                credential_id: "cred123".into(),
                salt: "c2FsdA==".into(),
                wrapped_master_key: "d3JhcHBlZA==".into(),
            }],
            recovery_phrase: RecoveryPhraseEnvelope {
                enabled: true,
                wrapped_master_key: Some("cmVjb3Zlcnk=".into()),
            },
        };

        let json = serde_json::to_value(&envelopes).unwrap();
        assert_eq!(json["yubikeys"][0]["credentialId"], "cred123");
        assert_eq!(json["recoveryPhrase"]["enabled"], true);
    }
}
