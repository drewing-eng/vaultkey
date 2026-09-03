//! Cœur cryptographique de VaultKey (PRD v3 §4, §9 étape 1).
//!
//! Aucune dépendance réseau (vérifiable dans `Cargo.toml`), aucune I/O disque,
//! aucune connaissance de WebAuthn/PRF ou de Docker : ce crate reçoit des
//! clés de wrap déjà obtenues par l'appelant (navigateur, plus tard WASM) et
//! des `Vec<u8>` à chiffrer/déchiffrer, rien d'autre. Reste auditable
//! indépendamment du reste du système.

mod aead;
mod blob;
mod envelope;
mod error;
mod manifest;
mod master_key;
mod nonce;
mod recovery;
mod vault;

pub use envelope::{generate_salt, KeyEnvelopes, RecoveryPhraseEnvelope, YubikeyEnvelope};
pub use error::VaultKeyError;
pub use manifest::{FileEntry, Manifest};
pub use master_key::MasterKey;
pub use recovery::parse_recovery_phrase;
pub use vault::Vault;

// Ré-export pour que les appelants puissent manipuler la mnemonic retournée
// par `Vault::enable_recovery_phrase` (afficher les mots, appeler `to_string()`)
// sans ajouter leur propre dépendance directe à `bip39`.
pub use bip39::Mnemonic;
