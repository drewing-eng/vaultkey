# PRD v3 — VaultKey, drive chiffré self-hébergé (Docker + WebAuthn)

Nom de travail : **VaultKey**. Ce document remplace `PRD-vault-yubikey-app-v2.md` (architecture native macOS, abandonnée, voir section 1). Licence prévue : **MIT**. Dépôt : GitHub public, code entièrement auditable.

## 1. Historique des décisions — à ne pas rouvrir sans raison nouvelle

Plusieurs architectures ont été explorées avant celle-ci. Les noter évite de reperdre le temps déjà investi.

- **age + gocryptfs + macFUSE** : rejetée. macFUSE classique exige Recovery Mode / Reduced Security sur Apple Silicon.
- **FSKit natif (Swift)** : rejetée. L'entitlement `com.apple.developer.fskit.fsmodule` est catégoriquement refusé aux comptes développeur Apple gratuits ("Personal Team"), confirmé empiriquement (erreur de provisioning profile) et par un ingénieur DTS Apple. Un compte payant (99$/an) lèverait le blocage, mais rendrait le projet impayable à reproduire pour quiconque le compile depuis les sources avec un compte gratuit — incompatible avec l'objectif 0€ + open source de ce projet, pas seulement avec le budget personnel de l'auteur.
- **FUSE-T + crate Rust `fuser`** : rejetée. `fuser` réimplémente le protocole FUSE noyau bas niveau sur le file descriptor renvoyé par `fuse_mount_compat25`, ce que seul un vrai kext (macFUSE) supporte. FUSE-T, un serveur NFS en espace utilisateur, ne peut pas être piloté ainsi. Confirmé par lecture du code source de `fuser` et par l'issue GitHub `cberner/fuser#273`, ouverte et sans solution.
- **FUSE-T + `libfuse-sys`** (bindings bas niveau vers la vraie boucle `fuse_main`) : viable techniquement, écartée en dernier ressort au profit de l'architecture ci-dessous, une fois l'objectif du projet clarifié (0€ pour tout contributeur, open source, installation simple via Docker plutôt que compilation native par plateforme).
- **Architecture retenue** : application web servie par un conteneur Docker auto-hébergé, chiffrement de bout en bout dans le navigateur via WebAuthn PRF, aucune dépendance à un compte développeur, un kernel extension, ou une licence tierce restrictive.

## 2. Objectif produit

Un drive chiffré que chacun peut héberger chez soi en une commande (`docker run` ou `docker compose up`), déverrouillable uniquement par une YubiKey physique (ou, si explicitement activé à la création d'un coffre, par une phrase de récupération de 24 mots), avec une UX de gestionnaire de fichiers classique une fois déverrouillé.

### Principes de self-custody, visibles dans l'UX, pas seulement dans le moteur

- **Aucun flux "mot de passe oublié".** Il n'existe pas et l'app le dit clairement dès la première utilisation.
- **Le setup initial force la décision de sauvegarde** avant de laisser stocker un premier fichier réel : enregistrer une deuxième YubiKey tout de suite, ou cocher explicitement "je comprends que je n'ai aucune sauvegarde".
- **Aucun compte administrateur** qui voit ou peut réinitialiser le contenu d'un coffre.

## 3. Portée V1

**Inclus** : instance Docker mono-utilisateur, plusieurs coffres indépendants par instance (façon Seafile), navigateurs desktop (Firefox 148+ recommandé en premier, Chrome/Chromium supporté ; Safari déconseillé pour l'instant, bugs WebKit ouverts affectant PRF avec des clés de sécurité USB/NFC externes).

**Explicitement hors scope V1** : accès mobile avec YubiKey physique (bloqué par la plateforme iOS/iPadOS, pas par ce produit — voir section 8), multi-utilisateur avec permissions différenciées, application native (le cœur Rust/WASM reste réutilisable pour ça plus tard si le besoin revient).

## 4. Architecture technique

- **Cœur de chiffrement — Rust, compilé en WebAssembly** (`wasm-pack`). Contient : format du coffre, chiffrement/déchiffrement AES-256-GCM par fichier, gestion du manifeste chiffré, logique des enveloppes de clé maîtresse. Aucune dépendance réseau dans ce crate (vérifiable au niveau du `Cargo.toml`), pour qu'il reste auditable indépendamment du reste.
- **Navigateur — WebCrypto + WebAuthn (extension PRF).** Tout le chiffrement/déchiffrement a lieu ici. `SubtleCrypto` pour l'AES-GCM et la génération de clé, `navigator.credentials` pour la cérémonie WebAuthn et l'extension PRF.
- **Cache local — OPFS.** Contient exclusivement des blobs déjà chiffrés, jamais de contenu déchiffré, copie de travail pour le mode hors ligne. Synchronisé avec le conteneur à la reconnexion.
- **Serveur — conteneur Docker, stockage aveugle.** Ne reçoit et ne stocke que des blobs chiffrés, des manifestes chiffrés, des enveloppes de clé illisibles sans opération PRF ou sans les mots BIP39. Aucune logique de déchiffrement côté serveur, à aucun endroit du code serveur. Stockage propre au conteneur (volume Docker), pas de dépendance à un service tiers comme Seafile — un contributeur qui déploie VaultKey n'a besoin de rien d'autre.
- **Contrôle d'accès réseau (distinct du chiffrement)** : authentification WebAuthn par YubiKey (sans extension PRF — simple preuve de possession, pas de dérivation de clé). Premier démarrage : enregistrement de la YubiKey comme appareil autorisé pour ce serveur, ouvert à quiconque atteint le port tant qu'aucun appareil n'est encore enregistré (fenêtre de bootstrap — ne pas exposer publiquement le port avant d'avoir fait ce premier enregistrement). Ensuite : connexion par simple contact, plusieurs appareils possibles par serveur, gérables une fois connecté. Remplace un jeton statique généré dans les logs (abandonné : ergonomie insuffisante — récupération manuelle dans les logs à chaque nouvel appareil/navigateur). Protège contre l'accès réseau non autorisé, ne remplace pas le chiffrement de bout en bout et n'en est pas une garantie équivalente (voir section 7.A). Recommandation documentée : restreindre l'exposition réseau (Tailscale/VPN/reverse proxy) en défense supplémentaire, en particulier pendant la fenêtre de bootstrap.
- **Mitigation du risque "code re-servi à chaque chargement"** (inhérent à toute app web, voir section 8) : construire l'app comme PWA avec service worker, mise en cache du code, revérification des mises à jour uniquement sur action explicite plutôt qu'à chaque ouverture. Réduit sans éliminer l'écart avec un binaire natif installé une fois.
- **Prior art à consulter avant de coder** : `Gatewatcher/hoddor` sur GitHub, un projet existant qui implémente déjà un coffre navigateur avec PRF. Petit projet, pas forcément prêt à l'emploi, mais à regarder pour éviter de redécouvrir ce qu'il a déjà résolu.

## 5. Modèle de données

### 5.1 Structure du drive

Un conteneur = un drive = plusieurs coffres indépendants.

```
/data/
  vaults/
    <vault-id>/
      manifest.enc
      blobs/
        <blob-id>.enc
```

### 5.2 Manifeste d'un coffre (chiffré avec la clé maîtresse du coffre)

Contient, une fois déchiffré : index nom réel → nom de blob + nonce par fichier, taille, horodatage. Chiffré dans son ensemble, y compris les noms de fichiers.

### 5.3 Enveloppes de clé maîtresse (non chiffrées elles-mêmes, mais sans valeur sans le secret correspondant)

Une liste par coffre, une entrée par méthode de déverrouillage autorisée :

```json
{
  "yubikeys": [
    { "credentialId": "...", "salt": "...", "wrappedMasterKey": "..." }
  ],
  "recoveryPhrase": {
    "enabled": true,
    "wrappedMasterKey": "..."
  }
}
```

`recoveryPhrase.enabled` est écrit une seule fois, à la création du coffre, et n'est plus modifiable ensuite (voir section 7.D).

Une même YubiKey physique (même `credentialId` racine) peut apparaître dans les enveloppes de plusieurs coffres différents, avec un `salt` distinct à chaque fois : une seule cérémonie d'enregistrement WebAuthn par YubiKey suffit pour l'ensemble du drive, l'utilisateur choisit ensuite librement à quels coffres chaque clé donne accès.

## 6. Écrans et flux

### 6.1 Premier lancement d'un nouveau coffre
1. Enregistrement de la YubiKey principale (cérémonie WebAuthn + PRF).
2. Décision de sauvegarde forcée, non contournable silencieusement : enregistrer une deuxième YubiKey maintenant, ou générer et afficher une seule fois les 24 mots BIP39 (si l'utilisateur choisit cette option ici, à la création, jamais après), ou cocher explicitement l'acquittement d'absence de sauvegarde.
3. Coffre vide, prêt à recevoir des fichiers.

### 6.2 Déverrouillage
Brancher la YubiKey, toucher. Fonctionne identiquement en ligne ou hors ligne si un cache local existe déjà pour ce coffre. Échec (mauvais coffre pour cette clé, timeout) → message clair.

### 6.3 Navigation
Dossiers, liste de fichiers, glisser-déposer, indicateur de statut de synchronisation par fichier (synchronisé / en attente / hors ligne uniquement).

### 6.4 Réglages d'un coffre
- Liste des YubiKey enregistrées, ajout/retrait. Avertissement fort et bloquant si le retrait ferait passer le coffre à zéro moyen de déverrouillage restant.
- Bouton **Supprimer ce coffre** : suppression définitive (manifeste, enveloppes, blobs, côté serveur et cache local). Exige un contact physique avec une YubiKey déjà enregistrée sur ce coffre avant d'agir, s'il en existe au moins une (preuve de présence, pas une opération cryptographique — aucune donnée à ré-envelopper puisque le coffre disparaît) ; sur un coffre protégé uniquement par une phrase BIP39 (zéro YubiKey), une confirmation explicite suffit, aucun contact requis. Scopé strictement à ce coffre : ne touche jamais aux autres coffres du même drive. Remplace un bouton RESET (vider le coffre en le gardant) envisagé plus tôt puis retiré du produit, jugé sans usage réel une fois la suppression complète disponible.
- Export chiffré : télécharge le dossier du coffre (manifeste + blobs) tel quel, aucune opération cryptographique ni YubiKey nécessaire à l'export lui-même.
- Import chiffré : charge un export précédent dans une instance, déchiffrable ensuite via une YubiKey enregistrée sur ce coffre ou via les mots BIP39 s'ils ont été générés.

### 6.5 Verrouillage
Efface la clé maîtresse déballée de la mémoire de session active.

## 7. Sécurité

### A. Modèle de confiance
Zero-knowledge strict : le serveur ne voit jamais rien d'exploitable, à aucun moment — pas le contenu, pas les noms de fichiers, pas la clé maîtresse, pas les secrets YubiKey. Compromettre entièrement le serveur ne donne accès à rien d'exploitable sans un secret qui, lui, ne transite jamais par le réseau.

**L'authentification réseau (ci-dessous, section 4) est une couche distincte, pas une extension du modèle zero-knowledge.** Elle protège contre l'accès non autorisé à l'API de stockage (lire/écrire des blobs chiffrés, énumérer des coffres), pas contre le déchiffrement — un serveur qui l'a franchie n'obtient toujours rien d'exploitable sans les secrets de déverrouillage d'un coffre (YubiKey PRF ou BIP39), qui restent entièrement indépendants.

### B. Mécanisme YubiKey

**Déverrouillage d'un coffre.** Extension PRF de WebAuthn. Une entrée `{credentialId, salt, wrappedMasterKey}` par YubiKey autorisée, par coffre. Touch physique requis à chaque déverrouillage. Aucune mise en cache du secret dérivé au-delà de la session en mémoire active.

**Authentification réseau au serveur (section 4).** Cérémonie WebAuthn distincte, sans extension PRF (simple preuve de possession, pas de dérivation de clé) : n'intervient à aucun moment dans le chiffrement, seulement dans le droit d'atteindre l'API. Une session obtenue par cette voie ne donne accès à aucun contenu de coffre sans, en plus, la cérémonie PRF ci-dessus (ou la phrase BIP39) pour le coffre visé.

### C. Non-extractibilité
Le secret racine reste dans l'élément sécurisé de la YubiKey, jamais exporté, jamais lisible même par l'app. Le secret PRF obtenu à chaque déverrouillage est un résultat de calcul pour un sel donné, pas une extraction du secret racine.

### D. Backup et recovery
- **Principal, recommandé** : plusieurs YubiKey par coffre, indépendantes.
- **Optionnel, figé à la création, non modifiable ensuite** : 24 mots BIP39 (256 bits), affichés une seule fois. Le choix est écrit dans le manifeste à la création. Changer d'avis = créer un nouveau coffre.
- **RESET** : voir 6.4, scopé au coffre, exige la dernière clé restante.
- **Export/import** : voir 6.4, aucune opération cryptographique nécessaire à l'export.
- Les deux chemins de déballage (YubiKey, BIP39) sont mathématiquement indépendants : connaître les mots ne renseigne rien sur le secret YubiKey et inversement. La fuite des mots d'un coffre compromet ce coffre précis, pas les autres coffres protégés par la même YubiKey.

### E. Entropie
- Clé maîtresse : `crypto.getRandomValues` (WebCrypto), 256 bits pleins, jamais dérivée d'une saisie utilisateur.
- Nonces AES-GCM : aléatoires, uniques par chiffrement, jamais réutilisés avec la même clé — test explicite requis pour vérifier l'absence de réutilisation dans un même coffre.
- Mots BIP39 : 256 bits d'entropie complète depuis le même générateur, liste de mots et somme de contrôle standard.
- Sels PRF : uniques par association coffre/YubiKey, non secrets par nature (leur rôle est de différencier les sorties, pas de protéger à eux seuls).

### F. Stockage au repos
Jamais en clair, ni côté serveur ni dans le cache local hors ligne (OPFS) : uniquement des blobs déjà chiffrés dans les deux cas. Le contenu déchiffré n'existe qu'en mémoire JavaScript active, reconstruit à chaque consultation, jamais persisté avant ni après synchronisation. Les noms de fichiers sont chiffrés dans le manifeste, pas seulement le contenu des fichiers.

### G. Intégrité
AES-GCM authentifié : toute altération d'un blob ou du manifeste est détectée au déchiffrement. **Risque résiduel connu, non résolu en v1** : rien n'empêche aujourd'hui un opérateur serveur malveillant de remplacer un fichier chiffré par une ancienne version valide du même fichier (rejeu/rollback) — authentique mais périmé, sans détection garantie. Durcissement futur envisagé : compteur de version signé.

### H. Ce qui n'est explicitement pas protégé
- Le code de chiffrement est servi par le conteneur à chaque chargement de page, un modèle de confiance différent d'un binaire installé une fois. L'open source et l'épinglage d'un digest d'image Docker précis (pas `:latest`) réduisent ce risque sans l'éliminer. La PWA/service worker (section 4) l'atténue encore, sans l'annuler.
- Une machine déjà compromise pendant un usage légitime (contenu déchiffré en RAM pendant l'usage) n'est protégée par aucun logiciel de chiffrement, celui-ci ou un autre.
- Accès mobile avec la YubiKey physique bloqué sur iOS/iPadOS : l'implémentation WebAuthn d'Apple sur ces plateformes ne transmet pas les données d'extension PRF vers un authentificateur externe itinérant, quel que soit le navigateur (Safari, Firefox iOS, Chrome iOS partagent tous le moteur WebKit imposé par Apple). Limite de plateforme, pas de ce produit.
- Métadonnées visibles côté serveur malgré le chiffrement : taille des fichiers, horodatage des accès, volume de trafic.

## 8. Critères d'acceptation

- [x] `docker compose up` démarre une instance fonctionnelle sans étape manuelle supplémentaire. Validé le 2026-08-26 (consolidation en un seul service) et reconfirmé le 2026-09-01.
- [x] Le premier démarrage permet d'enregistrer une YubiKey comme appareil autorisé pour le serveur ; les démarrages suivants exigent une authentification par une YubiKey déjà enregistrée avant tout accès à l'API. Validé sur la vraie YubiKey le 2026-09-01 (cycle complet : enregistrement, persistance de session, ajout/retrait d'appareil).
- [x] Créer un coffre force la décision de sauvegarde avant d'autoriser l'upload d'un premier fichier réel. Validé le 2026-08-26 (multi-coffre) et le 2026-09-01 (option BIP39 en particulier, jamais testée avant cette date).
- [x] Le déverrouillage fonctionne identiquement en ligne et hors ligne (cache local déjà présent). Validé le 2026-08-25 (étape 6, coupure réelle du conteneur Docker) ; PWA/cache du code applicatif revalidé séparément le 2026-09-01.
- [x] Un fichier de n'importe quel type (image, PDF, vidéo, archive) peut être uploadé, il est chiffré avant tout appel réseau. Validé le 2026-08-25 et reconfirmé le 2026-09-01 (upload par input et par glisser-déposer).
- [x] La suppression d'un coffre exige un contact YubiKey préalable dès qu'il en existe une sur ce coffre (simple confirmation sinon, coffre BIP39-only), et n'affecte que le coffre concerné, jamais les autres coffres du même drive. Validé sur la vraie YubiKey le 2026-09-01, les deux cas (avec et sans YubiKey).
- [x] Les 24 mots BIP39, si générés, ne sont affichés qu'une seule fois et jamais reconsultables ensuite. Validé le 2026-08-26 (étape 8) et le 2026-09-01.
- [x] Export puis import d'un coffre sur une nouvelle instance redonne accès à son contenu via une YubiKey enregistrée ou via les mots BIP39. Validé le 2026-08-26 (étape 8) et le 2026-09-01.
- [ ] Aucun test d'intégration ne trouve de contenu déchiffré ou de nonce réutilisé, ni côté serveur ni dans OPFS. Partiellement couvert : `core/` a un test automatisé dédié (anti-réutilisation de nonce, `NonceTracker`, 2000 fichiers). Pas de suite de tests d'intégration automatisée qui traverse serveur/OPFS à ce jour — seulement des vérifications manuelles répétées (`curl`, inspection OPFS) à chaque étape. Ne pas cocher tant qu'un test automatisé de ce périmètre exact n'existe pas.
- [x] Le crate Rust du cœur compile et passe ses tests sans aucune dépendance réseau déclarée. `cargo test` (17 tests) et `cargo tree` vérifiés sans dépendance réseau à l'étape 1, revérifié le 2026-09-01.

## 9. Ordre de développement suggéré

1. Cœur Rust (format du coffre, chiffrement AES-GCM, manifeste, enveloppes) — testable indépendamment, sans WASM, sans UI, sans Docker.
2. Compilation WASM du cœur, testée depuis une page HTML minimale sans backend.
3. Cérémonie WebAuthn + PRF minimale : enregistrer une YubiKey, dériver un secret, l'utiliser pour envelopper/déballer une clé de test.
4. Serveur Docker minimal : stockage de blobs, jeton d'accès, aucune logique de déchiffrement.
5. Flux complet sur un seul coffre codé en dur : création, upload, déverrouillage, téléchargement.
6. Mode hors ligne : cache OPFS, synchronisation à la reconnexion.
7. Multi-coffre, écran de gestion des YubiKey par coffre.
8. RESET, export/import, mots BIP39.
9. PWA/service worker, polish, README avec modèle de menace résumé (renvoi vers la section 7 de ce document).

## 10. Après le développement local

Deux étapes distinctes, à ne pas fusionner : une version de développement local (Claude Code, itérations rapides, pas encore d'audit de sécurité formel), puis une passe de durcissement dédiée avant toute mise en ligne publique du dépôt ou d'une image Docker publiée (revue de la frontière WASM/JS, vérification qu'aucune dépendance ne fuit de données, documentation du modèle de menace dans le README, choix définitif de la licence MIT avec fichier `LICENSE`).
