use rand::{rngs::SysRng, TryRng};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Clé maîtresse du coffre : 256 bits d'entropie pleine, jamais dérivée d'une
/// saisie utilisateur. N'existe qu'en mémoire, effacée explicitement au drop
/// (verrouillage du coffre).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    /// Génère une nouvelle clé maîtresse via le CSPRNG du système d'exploitation.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        SysRng
            .try_fill_bytes(&mut bytes)
            .expect("le générateur aléatoire du système doit toujours réussir");
        Self(bytes)
    }

    /// Reconstruit une clé maîtresse à partir d'octets déjà obtenus (ex. après
    /// déballage d'une enveloppe). Ne valide pas la provenance : à l'appelant
    /// de s'assurer que ces octets viennent bien d'un déchiffrement authentifié.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
