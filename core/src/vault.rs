use crate::envelope::{self, KeyEnvelopes, RecoveryPhraseEnvelope, YubikeyEnvelope};
use crate::error::VaultKeyError;
use crate::manifest::{self, FileEntry, Manifest};
use crate::master_key::MasterKey;
use crate::nonce::NonceTracker;
use crate::recovery;
use crate::{blob, error};
use base64::prelude::*;
use bip39::Mnemonic;
use web_time::{SystemTime, UNIX_EPOCH};

/// État d'un coffre en cours d'utilisation. Ne fait aucune I/O disque : les
/// blobs chiffrés et le manifeste chiffré transitent en `Vec<u8>`, à charge
/// de l'appelant (CLI de test aujourd'hui, plus tard le serveur Docker) de
/// les écrire selon la structure `/data/vaults/<id>/...` du PRD §5.1.
pub struct Vault {
    envelopes: KeyEnvelopes,
    nonce_tracker: NonceTracker,
    master_key: Option<MasterKey>,
    manifest: Option<Manifest>,
}

impl Vault {
    /// Crée un nouveau coffre vide : génère la clé maîtresse et initialise un
    /// manifeste vide, déverrouillé (on vient de le créer). Aucune méthode de
    /// déverrouillage n'est encore enregistrée : appeler `add_yubikey` et/ou
    /// `enable_recovery_phrase` avant de verrouiller, sous peine de perdre
    /// l'accès au coffre définitivement (PRD §6.1, décision de sauvegarde forcée).
    pub fn create() -> Self {
        Self {
            envelopes: KeyEnvelopes::default(),
            nonce_tracker: NonceTracker::new(),
            master_key: Some(MasterKey::generate()),
            manifest: Some(Manifest::new()),
        }
    }

    /// Reconstruit un `Vault` verrouillé à partir des enveloppes de clé déjà
    /// persistées (chargées depuis le disque par l'appelant). Il faut appeler
    /// `unlock_with_yubikey` ou `unlock_with_recovery_phrase` avant de pouvoir
    /// lire ou écrire des fichiers.
    pub fn from_envelopes(envelopes: KeyEnvelopes) -> Self {
        Self {
            envelopes,
            nonce_tracker: NonceTracker::new(),
            master_key: None,
            manifest: None,
        }
    }

    pub fn is_unlocked(&self) -> bool {
        self.master_key.is_some()
    }

    pub fn envelopes(&self) -> &KeyEnvelopes {
        &self.envelopes
    }

    /// Autorise une nouvelle YubiKey à déverrouiller ce coffre. `salt` et
    /// `wrap_key` sont tous les deux fournis par l'appelant : le sel doit
    /// être connu *avant* l'appel WebAuthn PRF (c'est un paramètre de cet
    /// appel, pas une sortie), donc généré en amont via `generate_salt()` et
    /// utilisé dans la cérémonie WebAuthn avant même d'arriver ici. Ce crate
    /// ne parle jamais lui-même à WebAuthn (étape 3 du PRD, hors scope de ce
    /// module) — la génération du sel *en interne*, tentée à l'étape 1,
    /// rendait la séquence irréalisable en pratique.
    pub fn add_yubikey(
        &mut self,
        credential_id: impl Into<String>,
        salt: &[u8; 32],
        wrap_key: &[u8; 32],
    ) -> Result<(), VaultKeyError> {
        let master_key = self.master_key.as_ref().ok_or(VaultKeyError::VaultLocked)?;
        let wrapped_master_key =
            envelope::wrap_master_key(master_key, wrap_key, &mut self.nonce_tracker);

        self.envelopes.yubikeys.push(YubikeyEnvelope {
            credential_id: credential_id.into(),
            salt: BASE64_STANDARD.encode(salt),
            wrapped_master_key,
        });

        Ok(())
    }

    /// Retire l'accès d'une YubiKey à ce coffre. Ne vérifie pas ici qu'il
    /// resterait au moins une méthode de déverrouillage : cette garde relève
    /// de l'UI (PRD §6.4, avertissement bloquant), pas du cœur cryptographique.
    pub fn remove_yubikey(&mut self, credential_id: &str) {
        self.envelopes
            .yubikeys
            .retain(|e| e.credential_id != credential_id);
    }

    /// Active la récupération par phrase BIP39, génère les 24 mots et les
    /// retourne pour affichage unique à l'utilisateur (PRD §6.1, §7.D). Ne
    /// peut être appelé qu'une fois : ce choix est figé à la création du
    /// coffre, pas modifiable ensuite.
    pub fn enable_recovery_phrase(&mut self) -> Result<Mnemonic, VaultKeyError> {
        let master_key = self.master_key.as_ref().ok_or(VaultKeyError::VaultLocked)?;
        let (mnemonic, wrap_key) = recovery::generate_recovery_phrase();
        let wrapped_master_key =
            envelope::wrap_master_key(master_key, &wrap_key, &mut self.nonce_tracker);

        self.envelopes.recovery_phrase = RecoveryPhraseEnvelope {
            enabled: true,
            wrapped_master_key: Some(wrapped_master_key),
        };

        Ok(mnemonic)
    }

    /// Déverrouille le coffre avec la sortie PRF d'une YubiKey déjà enregistrée
    /// et le manifeste chiffré correspondant (lu du disque par l'appelant).
    pub fn unlock_with_yubikey(
        &mut self,
        credential_id: &str,
        wrap_key: &[u8; 32],
        encrypted_manifest: &[u8],
    ) -> Result<(), VaultKeyError> {
        let entry = self
            .envelopes
            .yubikeys
            .iter()
            .find(|e| e.credential_id == credential_id)
            .ok_or(error::VaultKeyError::EnvelopeNotFound)?;

        let master_key = envelope::unwrap_master_key(&entry.wrapped_master_key, wrap_key)?;
        let manifest = manifest::decrypt_manifest(encrypted_manifest, &master_key)?;

        self.master_key = Some(master_key);
        self.manifest = Some(manifest);
        Ok(())
    }

    /// Déverrouille le coffre avec la phrase de récupération BIP39.
    pub fn unlock_with_recovery_phrase(
        &mut self,
        phrase: &str,
        encrypted_manifest: &[u8],
    ) -> Result<(), VaultKeyError> {
        if !self.envelopes.recovery_phrase.enabled {
            return Err(VaultKeyError::RecoveryPhraseNotEnabled);
        }
        let wrapped_master_key = self
            .envelopes
            .recovery_phrase
            .wrapped_master_key
            .as_ref()
            .ok_or(VaultKeyError::RecoveryPhraseNotEnabled)?;

        let wrap_key = recovery::parse_recovery_phrase(phrase)?;
        let master_key = envelope::unwrap_master_key(wrapped_master_key, &wrap_key)?;
        let manifest = manifest::decrypt_manifest(encrypted_manifest, &master_key)?;

        self.master_key = Some(master_key);
        self.manifest = Some(manifest);
        Ok(())
    }

    /// Efface la clé maîtresse déballée et le manifeste déchiffré de la
    /// mémoire de session active (PRD §6.5). `MasterKey` implémente
    /// `ZeroizeOnDrop` : la mise à `None` déclenche l'effacement explicite
    /// des octets, pas seulement la désallocation.
    pub fn lock(&mut self) {
        self.master_key = None;
        self.manifest = None;
    }

    /// Chiffre un nouveau fichier et met à jour le manifeste en mémoire.
    /// Retourne l'identifiant de blob et le contenu chiffré à écrire en
    /// `<blob-id>.enc`. Le manifeste modifié n'est pas persisté automatiquement :
    /// appeler `export_encrypted_manifest` pour obtenir le nouveau `manifest.enc`.
    pub fn add_file(
        &mut self,
        real_name: impl Into<String>,
        plaintext: &[u8],
    ) -> Result<(String, Vec<u8>), VaultKeyError> {
        let master_key = self.master_key.as_ref().ok_or(VaultKeyError::VaultLocked)?;
        let (blob_id, nonce, ciphertext) =
            blob::encrypt_blob(plaintext, master_key, &mut self.nonce_tracker);

        let manifest = self.manifest.as_mut().ok_or(VaultKeyError::VaultLocked)?;
        manifest.entries.push(FileEntry {
            real_name: real_name.into(),
            blob_id: blob_id.clone(),
            nonce: manifest::encode_nonce(&nonce),
            size: plaintext.len() as u64,
            modified: unix_now(),
        });

        Ok((blob_id, ciphertext))
    }

    /// Déchiffre un fichier déjà présent dans le manifeste. `ciphertext` est
    /// le contenu brut de `<blob-id>.enc` correspondant, fourni par l'appelant.
    pub fn read_file(&self, real_name: &str, ciphertext: &[u8]) -> Result<Vec<u8>, VaultKeyError> {
        let master_key = self.master_key.as_ref().ok_or(VaultKeyError::VaultLocked)?;
        let manifest = self.manifest.as_ref().ok_or(VaultKeyError::VaultLocked)?;
        let entry = manifest
            .find(real_name)
            .ok_or_else(|| VaultKeyError::FileNotFound(real_name.to_string()))?;
        let nonce = manifest::decode_nonce(&entry.nonce)?;
        blob::decrypt_blob(ciphertext, &nonce, master_key)
    }

    /// Retire un fichier du manifeste. Ne supprime pas le blob sur disque :
    /// c'est à l'appelant de le faire (ce crate ne fait pas d'I/O).
    pub fn remove_file(&mut self, real_name: &str) -> Result<(), VaultKeyError> {
        let manifest = self.manifest.as_mut().ok_or(VaultKeyError::VaultLocked)?;
        manifest
            .remove(real_name)
            .map(|_| ())
            .ok_or_else(|| VaultKeyError::FileNotFound(real_name.to_string()))
    }

    /// Liste les fichiers du coffre déverrouillé, tels qu'ils apparaissent
    /// dans le manifeste en mémoire (nécessaire pour proposer un
    /// téléchargement sans déjà connaître le nom du fichier à l'avance).
    pub fn list_files(&self) -> Result<&[FileEntry], VaultKeyError> {
        self.manifest
            .as_ref()
            .map(|m| m.entries.as_slice())
            .ok_or(VaultKeyError::VaultLocked)
    }

    /// Sérialise et chiffre le manifeste courant, prêt à être écrit en
    /// `manifest.enc`.
    pub fn export_encrypted_manifest(&mut self) -> Result<Vec<u8>, VaultKeyError> {
        let master_key = self.master_key.as_ref().ok_or(VaultKeyError::VaultLocked)?;
        let manifest = self.manifest.as_ref().ok_or(VaultKeyError::VaultLocked)?;
        Ok(manifest::encrypt_manifest(
            manifest,
            master_key,
            &mut self.nonce_tracker,
        ))
    }

    #[cfg(test)]
    pub(crate) fn nonce_tracker_len(&self) -> usize {
        self.nonce_tracker.len()
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("l'horloge système est après 1970")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_add_yubikey_lock_unlock_roundtrip() {
        let mut vault = Vault::create();
        let salt = [7u8; 32];
        let wrap_key = [42u8; 32]; // valeur fixe = tient lieu de sortie PRF pour ce test
        vault.add_yubikey("credential-abc", &salt, &wrap_key).unwrap();

        let (_blob_id, ciphertext) = vault.add_file("secret.txt", b"contenu confidentiel").unwrap();
        let encrypted_manifest = vault.export_encrypted_manifest().unwrap();

        vault.lock();
        assert!(!vault.is_unlocked());

        let mut reopened = Vault::from_envelopes(vault.envelopes().clone());
        reopened
            .unlock_with_yubikey("credential-abc", &wrap_key, &encrypted_manifest)
            .unwrap();

        let plaintext = reopened.read_file("secret.txt", &ciphertext).unwrap();
        assert_eq!(plaintext, b"contenu confidentiel");
    }

    #[test]
    fn unlock_with_wrong_wrap_key_fails() {
        let mut vault = Vault::create();
        let salt = [8u8; 32];
        let wrap_key = [1u8; 32];
        vault.add_yubikey("credential-abc", &salt, &wrap_key).unwrap();
        let encrypted_manifest = vault.export_encrypted_manifest().unwrap();
        vault.lock();

        let mut reopened = Vault::from_envelopes(vault.envelopes().clone());
        let wrong_key = [2u8; 32];
        assert!(reopened
            .unlock_with_yubikey("credential-abc", &wrong_key, &encrypted_manifest)
            .is_err());
    }

    #[test]
    fn recovery_phrase_unlock_roundtrip() {
        let mut vault = Vault::create();
        let mnemonic = vault.enable_recovery_phrase().unwrap();
        let (_blob_id, ciphertext) = vault.add_file("secret.txt", b"data").unwrap();
        let encrypted_manifest = vault.export_encrypted_manifest().unwrap();
        vault.lock();

        let mut reopened = Vault::from_envelopes(vault.envelopes().clone());
        reopened
            .unlock_with_recovery_phrase(&mnemonic.to_string(), &encrypted_manifest)
            .unwrap();

        assert_eq!(reopened.read_file("secret.txt", &ciphertext).unwrap(), b"data");
    }

    #[test]
    fn lock_clears_in_memory_state() {
        let mut vault = Vault::create();
        vault
            .add_yubikey("credential-abc", &[6u8; 32], &[9u8; 32])
            .unwrap();
        assert!(vault.is_unlocked());
        vault.lock();
        assert!(!vault.is_unlocked());
        assert!(vault.add_file("x", b"y").is_err());
    }

    #[test]
    fn list_files_reflects_manifest() {
        let mut vault = Vault::create();
        vault
            .add_yubikey("credential-abc", &[4u8; 32], &[11u8; 32])
            .unwrap();
        vault.add_file("a.txt", b"a").unwrap();
        vault.add_file("b.txt", b"b").unwrap();

        let names: Vec<&str> = vault
            .list_files()
            .unwrap()
            .iter()
            .map(|e| e.real_name.as_str())
            .collect();
        assert_eq!(names, ["a.txt", "b.txt"]);
    }

    #[test]
    fn list_files_fails_when_locked() {
        let vault = Vault::from_envelopes(KeyEnvelopes::default());
        assert!(vault.list_files().is_err());
    }

    /// Exigence non négociable du PRD (§7.E) : aucun nonce AES-GCM réutilisé
    /// dans un même coffre. On chiffre un grand nombre de fichiers plus le
    /// manifeste et on vérifie que `NonceTracker` n'a jamais laissé passer
    /// de collision.
    #[test]
    fn no_nonce_reuse_across_many_files() {
        let mut vault = Vault::create();
        vault
            .add_yubikey("credential-abc", &[5u8; 32], &[3u8; 32])
            .unwrap();

        const FILE_COUNT: usize = 2_000;
        for i in 0..FILE_COUNT {
            vault
                .add_file(format!("fichier-{i}.bin"), format!("contenu {i}").as_bytes())
                .unwrap();
        }
        vault.export_encrypted_manifest().unwrap();

        // add_yubikey (1) + FILE_COUNT blobs + export_encrypted_manifest (1)
        assert_eq!(vault.nonce_tracker_len(), 1 + FILE_COUNT + 1);
    }
}
