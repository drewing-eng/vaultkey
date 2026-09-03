use rand::{rngs::SysRng, TryRng};
use std::collections::HashSet;

/// Émet des nonces AES-GCM de 96 bits, imprévisibles (CSPRNG), et garantit
/// explicitement qu'aucun nonce n'est émis deux fois pendant la durée de vie
/// de ce tracker (une session de `Vault`). Défense en profondeur au-delà de
/// la probabilité de collision déjà négligeable (2^-96) d'un tirage aléatoire.
#[derive(Default)]
pub struct NonceTracker {
    seen: HashSet<[u8; 12]>,
}

impl NonceTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Génère un nonce frais, garanti distinct de tous les nonces déjà émis
    /// par ce tracker. Retire (via le CSPRNG du système) jusqu'à obtenir une
    /// valeur inédite ; en pratique une seule tentative suffit toujours.
    pub fn fresh(&mut self) -> [u8; 12] {
        loop {
            let mut candidate = [0u8; 12];
            SysRng
                .try_fill_bytes(&mut candidate)
                .expect("le générateur aléatoire du système doit toujours réussir");
            if self.seen.insert(candidate) {
                return candidate;
            }
        }
    }

    /// Nombre de nonces distincts émis jusqu'ici. Utilisé par le test
    /// anti-réutilisation de `vault.rs`.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.seen.len()
    }
}
