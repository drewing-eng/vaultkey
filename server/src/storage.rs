//! Stockage aveugle : ne connaît que des chemins et des octets, jamais le
//! format du coffre (aucune dépendance à `vaultkey-core`). PRD §4, §7.A :
//! le serveur ne doit même pas avoir le code pour comprendre ce qu'il stocke.

use std::path::PathBuf;

const MAX_ID_LEN: usize = 64;

/// Un identifiant (vault_id ou blob_id) n'est accepté que sous cette forme
/// restrictive, validée AVANT toute construction de chemin sur disque :
/// jamais de confiance dans un segment d'URL fourni par le client, pour
/// exclure toute traversée de répertoire (`../`, chemins absolus, etc.).
fn validate_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID_LEN
        && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

#[derive(Clone)]
pub struct Storage {
    data_dir: PathBuf,
}

impl Storage {
    pub fn new(data_dir: PathBuf) -> Self {
        Self { data_dir }
    }

    fn vault_dir(&self, vault_id: &str) -> PathBuf {
        self.data_dir.join("vaults").join(vault_id)
    }

    /// PRD §5.1 : `/data/vaults/<vault-id>/manifest.enc`.
    pub fn manifest_path(&self, vault_id: &str) -> Option<PathBuf> {
        validate_id(vault_id).then(|| self.vault_dir(vault_id).join("manifest.enc"))
    }

    /// Extension du PRD §5.1 (non précisé explicitement par le PRD) : les
    /// enveloppes de clé (§5.3) vivent à côté du manifeste.
    pub fn envelopes_path(&self, vault_id: &str) -> Option<PathBuf> {
        validate_id(vault_id).then(|| self.vault_dir(vault_id).join("envelopes.json"))
    }

    /// Extension étape 7 (non précisée par le PRD) : métadonnées d'UI (nom
    /// lisible du coffre), volontairement séparées d'`envelopes.json` pour
    /// garder ce dernier fidèle au schéma exact du PRD §5.3 (matériel
    /// cryptographique uniquement, pas de métadonnée d'interface).
    pub fn meta_path(&self, vault_id: &str) -> Option<PathBuf> {
        validate_id(vault_id).then(|| self.vault_dir(vault_id).join("meta.json"))
    }

    /// PRD §5.1 : `/data/vaults/<vault-id>/blobs/<blob-id>.enc`.
    pub fn blob_path(&self, vault_id: &str, blob_id: &str) -> Option<PathBuf> {
        if !validate_id(vault_id) || !validate_id(blob_id) {
            return None;
        }
        Some(
            self.vault_dir(vault_id)
                .join("blobs")
                .join(format!("{blob_id}.enc")),
        )
    }

    /// Chemin du répertoire complet d'un coffre (`/data/vaults/<vault-id>/`),
    /// utilisé uniquement pour sa suppression définitive : les autres
    /// opérations passent par les chemins plus spécifiques ci-dessus, jamais
    /// par le répertoire entier.
    pub fn vault_dir_path(&self, vault_id: &str) -> Option<PathBuf> {
        validate_id(vault_id).then(|| self.vault_dir(vault_id))
    }

    /// Supprime récursivement un répertoire. Idempotent : l'absence
    /// préalable du répertoire n'est pas une erreur (suppression déjà
    /// effective, rien à faire).
    pub async fn delete_dir(&self, path: &std::path::Path) -> std::io::Result<()> {
        match tokio::fs::remove_dir_all(path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Énumère les identifiants de coffre existants (noms des sous-dossiers
    /// de `vaults/`). Énumération aveugle : ne lit ni n'interprète le
    /// contenu d'aucun coffre, juste les noms de dossiers déjà validés à
    /// leur création. Retourne une liste vide si `vaults/` n'existe pas
    /// encore (aucun coffre créé jusqu'ici), pas une erreur.
    pub async fn list_vaults(&self) -> std::io::Result<Vec<String>> {
        let vaults_dir = self.data_dir.join("vaults");
        let mut entries = match tokio::fs::read_dir(&vaults_dir).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };

        let mut vault_ids = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_dir()
                && let Some(name) = entry.file_name().to_str()
            {
                vault_ids.push(name.to_string());
            }
        }
        Ok(vault_ids)
    }

    pub async fn write(&self, path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(path, data).await
    }

    pub async fn read(&self, path: &std::path::Path) -> std::io::Result<Vec<u8>> {
        tokio::fs::read(path).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_uuid_like_ids() {
        let s = Storage::new(PathBuf::from("/data"));
        assert!(s.manifest_path("a1b2c3d4-e5f6-7890-abcd-ef1234567890").is_some());
    }

    #[test]
    fn rejects_path_traversal() {
        let s = Storage::new(PathBuf::from("/data"));
        assert!(s.manifest_path("../../etc").is_none());
        assert!(s.manifest_path("..").is_none());
        assert!(s.manifest_path("a/b").is_none());
        assert!(s.blob_path("valid-vault", "../../../etc/passwd").is_none());
    }

    #[test]
    fn rejects_empty_and_oversized_ids() {
        let s = Storage::new(PathBuf::from("/data"));
        assert!(s.manifest_path("").is_none());
        assert!(s.manifest_path(&"a".repeat(65)).is_none());
        assert!(s.manifest_path(&"a".repeat(64)).is_some());
    }

    #[test]
    fn meta_path_follows_same_id_rules() {
        let s = Storage::new(PathBuf::from("/data"));
        assert_eq!(
            s.meta_path("vault-1").unwrap(),
            PathBuf::from("/data/vaults/vault-1/meta.json")
        );
        assert!(s.meta_path("../../etc").is_none());
    }

    #[test]
    fn vault_dir_path_rejects_traversal() {
        let s = Storage::new(PathBuf::from("/data"));
        assert_eq!(
            s.vault_dir_path("vault-1").unwrap(),
            PathBuf::from("/data/vaults/vault-1")
        );
        assert!(s.vault_dir_path("../../etc").is_none());
        assert!(s.vault_dir_path("a/b").is_none());
    }

    #[tokio::test]
    async fn delete_dir_removes_existing_vault_directory() {
        let dir = tempfile_dir();
        let s = Storage::new(dir.clone());
        let vault_path = s.vault_dir_path("vault-1").unwrap();
        tokio::fs::create_dir_all(vault_path.join("blobs")).await.unwrap();
        tokio::fs::write(vault_path.join("manifest.enc"), b"x").await.unwrap();
        assert!(vault_path.exists());

        s.delete_dir(&vault_path).await.unwrap();
        assert!(!vault_path.exists());

        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    #[tokio::test]
    async fn delete_dir_is_idempotent_when_already_absent() {
        let dir = tempfile_dir();
        let s = Storage::new(dir.clone());
        let vault_path = s.vault_dir_path("never-created").unwrap();
        assert!(s.delete_dir(&vault_path).await.is_ok());
        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    #[tokio::test]
    async fn list_vaults_empty_when_no_vaults_dir() {
        let dir = tempfile_dir();
        let s = Storage::new(dir.clone());
        assert_eq!(s.list_vaults().await.unwrap(), Vec::<String>::new());
        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    #[tokio::test]
    async fn list_vaults_lists_subdirectories_only() {
        let dir = tempfile_dir();
        let vaults = dir.join("vaults");
        tokio::fs::create_dir_all(vaults.join("vault-a")).await.unwrap();
        tokio::fs::create_dir_all(vaults.join("vault-b")).await.unwrap();
        tokio::fs::write(vaults.join("not-a-vault.txt"), b"stray file")
            .await
            .unwrap();

        let s = Storage::new(dir.clone());
        let mut ids = s.list_vaults().await.unwrap();
        ids.sort();
        assert_eq!(ids, vec!["vault-a".to_string(), "vault-b".to_string()]);

        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    fn tempfile_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vaultkey-server-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn blob_path_is_scoped_under_its_vault() {
        let s = Storage::new(PathBuf::from("/data"));
        let path = s.blob_path("vault-1", "blob-1").unwrap();
        assert_eq!(
            path,
            PathBuf::from("/data/vaults/vault-1/blobs/blob-1.enc")
        );
    }
}
