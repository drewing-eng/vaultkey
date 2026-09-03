use crate::error::VaultKeyError;
use bip39::Mnemonic;
use hkdf::Hkdf;
use rand::{rngs::SysRng, TryRng};
use sha2::Sha256;
use zeroize::Zeroize;

/// Contexte de séparation de domaine HKDF : garantit que cette clé de wrap
/// ne peut jamais coïncider avec une dérivation faite ailleurs dans le
/// système à partir de la même entropie brute.
const HKDF_INFO: &[u8] = b"vaultkey-recovery-wrap-v1";

/// Génère une nouvelle phrase de récupération de 24 mots (256 bits d'entropie
/// pleine, même générateur que la clé maîtresse) et la clé de wrap qui en
/// dérive. Les 24 mots doivent être affichés une seule fois à l'utilisateur
/// (voir PRD §6.1) : ce module ne les persiste jamais lui-même.
pub fn generate_recovery_phrase() -> (Mnemonic, [u8; 32]) {
    let mut entropy = [0u8; 32];
    SysRng
        .try_fill_bytes(&mut entropy)
        .expect("le générateur aléatoire du système doit toujours réussir");

    let mnemonic =
        Mnemonic::from_entropy(&entropy).expect("32 octets est une longueur d'entropie valide");
    let wrap_key = wrap_key_from_mnemonic(&mnemonic);

    entropy.zeroize();
    (mnemonic, wrap_key)
}

/// Reconstruit la clé de wrap à partir d'une phrase de récupération saisie
/// par l'utilisateur (flux de déverrouillage via BIP39).
pub fn parse_recovery_phrase(phrase: &str) -> Result<[u8; 32], VaultKeyError> {
    let mnemonic = Mnemonic::parse(phrase)
        .map_err(|e| VaultKeyError::InvalidRecoveryPhrase(e.to_string()))?;
    Ok(wrap_key_from_mnemonic(&mnemonic))
}

/// Dérive de façon déterministe une clé de wrap 256 bits depuis l'entropie
/// brute d'une mnemonic BIP39, via HKDF-SHA256. Pas de PBKDF2 façon BIP39
/// standard : l'entropie est déjà pleine (256 bits), l'étirement anti-brute-force
/// n'apporte rien ici, et VaultKey n'a pas besoin d'interopérer avec un wallet.
fn wrap_key_from_mnemonic(mnemonic: &Mnemonic) -> [u8; 32] {
    let mut entropy = mnemonic.to_entropy();
    let hk = Hkdf::<Sha256>::new(None, &entropy);
    let mut wrap_key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut wrap_key)
        .expect("32 octets est une longueur de sortie valide pour HKDF-SHA256");
    entropy.zeroize();
    wrap_key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_24_words() {
        let (mnemonic, _wrap_key) = generate_recovery_phrase();
        assert_eq!(mnemonic.word_count(), 24);
    }

    #[test]
    fn derivation_is_deterministic() {
        let (mnemonic, wrap_key_a) = generate_recovery_phrase();
        let wrap_key_b = wrap_key_from_mnemonic(&mnemonic);
        assert_eq!(wrap_key_a, wrap_key_b);
    }

    #[test]
    fn parse_roundtrip() {
        let (mnemonic, wrap_key) = generate_recovery_phrase();
        let phrase = mnemonic.to_string();
        let reparsed_wrap_key = parse_recovery_phrase(&phrase).unwrap();
        assert_eq!(wrap_key, reparsed_wrap_key);
    }

    #[test]
    fn two_generations_differ() {
        let (_m1, wrap_key_a) = generate_recovery_phrase();
        let (_m2, wrap_key_b) = generate_recovery_phrase();
        assert_ne!(wrap_key_a, wrap_key_b);
    }
}
