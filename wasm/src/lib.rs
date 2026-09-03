//! Binding wasm-bindgen du cœur Rust (`vaultkey_core::Vault`) pour le vrai
//! front (`web/index.html`) : voir `WasmVault` ci-dessous.

use vaultkey_core::{Vault, VaultKeyError};
use wasm_bindgen::prelude::*;

/// Convertit un panic Rust en message lisible dans la console JS au lieu
/// d'un simple trap WASM opaque ("unreachable"). Appelé automatiquement au
/// chargement du module.
#[wasm_bindgen(start)]
fn start() {
    console_error_panic_hook::set_once();
}

fn to_js_error(err: VaultKeyError) -> JsValue {
    JsValue::from_str(&err.to_string())
}

fn bytes32(bytes: &[u8], field: &str) -> Result<[u8; 32], JsValue> {
    bytes
        .try_into()
        .map_err(|_| JsValue::from_str(&format!("{field} doit faire exactement 32 octets")))
}

/// Génère un sel frais (32 octets, CSPRNG du cœur Rust) à utiliser comme
/// `eval.first` d'une évaluation PRF WebAuthn, *avant* d'appeler
/// `WasmVault::add_yubikey` avec le secret qui en résultera.
#[wasm_bindgen]
pub fn generate_salt() -> Vec<u8> {
    vaultkey_core::generate_salt().to_vec()
}

/// Résultat de `WasmVault::add_file` : l'identifiant de blob et le contenu
/// chiffré à envoyer au serveur. Pas de tuple natif en JS via wasm-bindgen,
/// donc un petit type dédié avec des getters, pattern standard ici.
#[wasm_bindgen]
pub struct AddFileResult {
    blob_id: String,
    ciphertext: Vec<u8>,
}

#[wasm_bindgen]
impl AddFileResult {
    #[wasm_bindgen(getter)]
    pub fn blob_id(&self) -> String {
        self.blob_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }
}

/// Enveloppe wasm-bindgen autour du vrai `Vault` de `core/`. Surface conçue
/// pour le flux complet de l'étape 5 (`web/index.html`) : création,
/// enregistrement YubiKey, upload, verrouillage/déverrouillage, liste et
/// téléchargement. Ce type ne parle jamais lui-même à WebAuthn ni au réseau :
/// il reçoit des octets déjà obtenus par JS (secret PRF, réponses du
/// serveur) et en renvoie à écrire/envoyer, exactement comme `Vault` lui-même.
#[wasm_bindgen]
pub struct WasmVault(Vault);

#[wasm_bindgen]
impl WasmVault {
    /// Crée un nouveau coffre vide et déverrouillé.
    #[wasm_bindgen(constructor)]
    pub fn create() -> WasmVault {
        WasmVault(Vault::create())
    }

    /// Reconstruit un coffre verrouillé à partir de `envelopes.json` (lu du
    /// serveur). Appeler `unlock_with_yubikey` ensuite.
    #[wasm_bindgen(js_name = fromEnvelopesJson)]
    pub fn from_envelopes_json(json: &str) -> Result<WasmVault, JsValue> {
        let envelopes = serde_json::from_str(json)
            .map_err(|e| JsValue::from_str(&format!("envelopes.json invalide : {e}")))?;
        Ok(WasmVault(Vault::from_envelopes(envelopes)))
    }

    #[wasm_bindgen(js_name = isUnlocked)]
    pub fn is_unlocked(&self) -> bool {
        self.0.is_unlocked()
    }

    /// Sérialise les enveloppes de clé courantes, prêtes à envoyer au
    /// serveur en `envelopes.json` (PUT `/vaults/{id}/envelopes`).
    #[wasm_bindgen(js_name = envelopesJson)]
    pub fn envelopes_json(&self) -> String {
        serde_json::to_string(self.0.envelopes())
            .expect("KeyEnvelopes sérialise toujours en JSON valide")
    }

    /// Autorise une YubiKey à déverrouiller ce coffre. `salt` doit être celui
    /// obtenu via `generate_salt()` et déjà utilisé dans l'appel WebAuthn qui
    /// a produit `wrap_key` — pas un nouveau sel choisi ici.
    #[wasm_bindgen(js_name = addYubikey)]
    pub fn add_yubikey(
        &mut self,
        credential_id: &str,
        salt: &[u8],
        wrap_key: &[u8],
    ) -> Result<(), JsValue> {
        let salt = bytes32(salt, "salt")?;
        let wrap_key = bytes32(wrap_key, "wrap_key")?;
        self.0
            .add_yubikey(credential_id, &salt, &wrap_key)
            .map_err(to_js_error)
    }

    /// Retire l'accès d'une YubiKey à ce coffre. Ne vérifie pas ici qu'il
    /// resterait au moins une méthode de déverrouillage — cette garde relève
    /// de l'UI (PRD §6.4), qui doit désactiver l'action plutôt que de laisser
    /// l'utilisateur retirer la dernière clé restante.
    #[wasm_bindgen(js_name = removeYubikey)]
    pub fn remove_yubikey(&mut self, credential_id: &str) {
        self.0.remove_yubikey(credential_id);
    }

    /// Déverrouille le coffre avec la sortie PRF d'une YubiKey déjà
    /// enregistrée et le `manifest.enc` correspondant (lu du serveur).
    #[wasm_bindgen(js_name = unlockWithYubikey)]
    pub fn unlock_with_yubikey(
        &mut self,
        credential_id: &str,
        wrap_key: &[u8],
        encrypted_manifest: &[u8],
    ) -> Result<(), JsValue> {
        let wrap_key = bytes32(wrap_key, "wrap_key")?;
        self.0
            .unlock_with_yubikey(credential_id, &wrap_key, encrypted_manifest)
            .map_err(to_js_error)
    }

    /// Efface la clé maîtresse et le manifeste déchiffré de la mémoire.
    pub fn lock(&mut self) {
        self.0.lock();
    }

    /// Active la récupération par phrase BIP39 (24 mots) et la retourne pour
    /// affichage unique (PRD §6.1) : n'est jamais reconsultable ensuite, cet
    /// appel ne la persiste nulle part lui-même.
    #[wasm_bindgen(js_name = enableRecoveryPhrase)]
    pub fn enable_recovery_phrase(&mut self) -> Result<String, JsValue> {
        self.0
            .enable_recovery_phrase()
            .map(|mnemonic| mnemonic.to_string())
            .map_err(to_js_error)
    }

    /// Déverrouille le coffre avec la phrase de récupération BIP39, sans
    /// passer par WebAuthn/PRF.
    #[wasm_bindgen(js_name = unlockWithRecoveryPhrase)]
    pub fn unlock_with_recovery_phrase(
        &mut self,
        phrase: &str,
        encrypted_manifest: &[u8],
    ) -> Result<(), JsValue> {
        self.0
            .unlock_with_recovery_phrase(phrase, encrypted_manifest)
            .map_err(to_js_error)
    }

    /// Chiffre un nouveau fichier. Retourne l'identifiant de blob et le
    /// contenu chiffré à PUT sur le serveur ; le manifeste est mis à jour en
    /// mémoire mais pas persisté (appeler `exportEncryptedManifest` ensuite).
    #[wasm_bindgen(js_name = addFile)]
    pub fn add_file(&mut self, real_name: &str, plaintext: &[u8]) -> Result<AddFileResult, JsValue> {
        let (blob_id, ciphertext) = self.0.add_file(real_name, plaintext).map_err(to_js_error)?;
        Ok(AddFileResult { blob_id, ciphertext })
    }

    /// Déchiffre un fichier déjà présent dans le manifeste. `ciphertext` est
    /// le contenu brut du blob correspondant, obtenu du serveur.
    #[wasm_bindgen(js_name = readFile)]
    pub fn read_file(&self, real_name: &str, ciphertext: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.0.read_file(real_name, ciphertext).map_err(to_js_error)
    }

    /// Retire un fichier du manifeste en mémoire (appeler
    /// `exportEncryptedManifest` ensuite pour persister). Ne supprime pas le
    /// blob chiffré côté serveur ni en cache local : à la charge de l'appelant.
    #[wasm_bindgen(js_name = removeFile)]
    pub fn remove_file(&mut self, real_name: &str) -> Result<(), JsValue> {
        self.0.remove_file(real_name).map_err(to_js_error)
    }

    /// Liste les fichiers du coffre déverrouillé, sérialisés en JSON
    /// (tableau d'objets `{realName, blobId, size, modified}`).
    #[wasm_bindgen(js_name = listFilesJson)]
    pub fn list_files_json(&self) -> Result<String, JsValue> {
        let files = self.0.list_files().map_err(to_js_error)?;
        serde_json::to_string(files)
            .map_err(|e| JsValue::from_str(&format!("erreur de sérialisation : {e}")))
    }

    /// Sérialise et chiffre le manifeste courant, prêt à PUT en `manifest.enc`.
    #[wasm_bindgen(js_name = exportEncryptedManifest)]
    pub fn export_encrypted_manifest(&mut self) -> Result<Vec<u8>, JsValue> {
        self.0.export_encrypted_manifest().map_err(to_js_error)
    }
}
