use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultKeyError {
    #[error("échec de déchiffrement ou clé de déballage incorrecte")]
    DecryptionFailed,
    #[error("blob chiffré malformé (trop court ou encodage base64 invalide)")]
    MalformedCiphertext,
    #[error("manifeste malformé (JSON invalide après déchiffrement)")]
    MalformedManifest,
    #[error("phrase de récupération invalide: {0}")]
    InvalidRecoveryPhrase(String),
    #[error("aucune enveloppe YubiKey enregistrée pour ce credentialId")]
    EnvelopeNotFound,
    #[error("aucune récupération par phrase activée pour ce coffre")]
    RecoveryPhraseNotEnabled,
    #[error("fichier introuvable dans le manifeste: {0}")]
    FileNotFound(String),
    #[error("coffre verrouillé, aucune opération possible avant unlock")]
    VaultLocked,
}
