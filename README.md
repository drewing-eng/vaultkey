# VaultKey

Drive chiffré self-hébergé, déverrouillé par YubiKey physique (extension PRF de WebAuthn), ou par une phrase de récupération BIP39 optionnelle. Le serveur ne voit jamais rien d'exploitable : ni le contenu, ni les noms de fichiers, ni la clé maîtresse.

Spécification complète : [`PRD-vaultkey-web-v3.md`](./PRD-vaultkey-web-v3.md).

## Démarrage

```
docker compose up --build
```

Puis ouvrir `http://localhost:8080/` (redirige vers l'app). Le conteneur sert à la fois l'API et le frontend, même origine : le champ « URL de l'API » se remplit tout seul, il n'y a rien à saisir manuellement.

**Premier accès : enregistre ta YubiKey comme appareil autorisé pour ce serveur** (un touch, cérémonie WebAuthn — pas de PIN à recopier, pas de jeton dans les logs). Les accès suivants ne demandent qu'un simple contact pour se connecter ; la session obtenue est mémorisée localement (OPFS du navigateur) pour ne pas avoir à retoucher à chaque ouverture. D'autres appareils/YubiKey peuvent être ajoutés ensuite depuis « Appareils » dans le pied de la barre latérale.

**Fenêtre de bootstrap à connaître** : tant qu'aucun appareil n'est encore enregistré, le premier qui charge la page et complète cet enregistrement devient l'appareil autorisé. Sur un VPS exposé publiquement, ne pas ouvrir le port avant d'avoir fait cet enregistrement toi-même (pare-feu/VPN pendant la mise en place, puis ouverture du port).

Déploiement sur un VPS : identique, `docker compose up --build -d` sur la machine cible, en restreignant l'exposition réseau du port 8080 (Tailscale/VPN/reverse proxy TLS — ce conteneur ne gère pas TLS lui-même, voir modèle de menace ci-dessous). **Variables d'environnement à définir pour tout déploiement autre que `localhost`** : `RP_ID` (nom de domaine, ex. `vault.example.com`) et `RP_ORIGIN` (URL complète en HTTPS, ex. `https://vault.example.com`) — WebAuthn refuse toute autre origine que `localhost` ou une origine HTTPS valide, ce n'est pas configurable autrement.

Par défaut, aucune origine tierce n'est autorisée en CORS (le déploiement recommandé, un seul conteneur pour l'API et le frontend, n'en a de toute façon pas besoin — une requête same-origin n'est jamais soumise au contrôle CORS du navigateur). Seulement si tu choisis de séparer frontend et API sur deux origines distinctes, définis `CORS_ALLOWED_ORIGIN` sur l'origine exacte du frontend (ex. `https://app.example.com`, jamais un wildcard).

**Navigateur recommandé : Firefox 148+.** Chrome/Chromium est supporté. Safari est déconseillé pour l'instant (bugs WebKit ouverts affectant l'extension PRF avec des clés de sécurité USB/NFC externes).

**Un gestionnaire de mots de passe/passkeys actif dans le navigateur (Bitwarden, etc.) peut intercepter la cérémonie WebAuthn** et faire échouer le déverrouillage avec une erreur générique. Le désactiver le temps d'utiliser VaultKey si ça arrive.

**La YubiKey doit avoir un PIN FIDO2 défini** (distinct d'un éventuel PIN PIV) — nécessaire aussi bien pour se connecter au serveur que pour déverrouiller un coffre, les deux cérémonies exigent une vérification utilisateur. Sans lui, la cérémonie reste bloquée sans message explicite. Se définit via le panneau de sécurité du système ou `ykman fido access change-pin`.

## Modèle de menace (résumé — détail complet en section 7 du PRD)

**Ce qui est protégé.** Le chiffrement (AES-256-GCM par fichier, clé maîtresse 256 bits générée par `crypto.getRandomValues`) a lieu exclusivement dans le navigateur, avant tout appel réseau. Le serveur, le trafic réseau, et le cache hors ligne (OPFS) ne contiennent jamais que des blobs déjà chiffrés — jamais de contenu en clair, jamais de nom de fichier en clair (les noms sont chiffrés dans le manifeste). Compromettre entièrement le serveur ne donne accès à rien d'exploitable sans un secret qui ne transite jamais par le réseau : le secret racine de la YubiKey (jamais extractible, reste dans son élément sécurisé) ou les mots BIP39 (jamais transmis au serveur). Un touch physique de la YubiKey est requis à chaque déverrouillage.

**Ce qui n'est explicitement pas protégé, en l'état.**
- **Le code de chiffrement est resservi par le conteneur à chaque chargement de page** — modèle de confiance différent d'un binaire installé une fois. L'open source du dépôt et l'épinglage d'un digest d'image Docker précis (pas `:latest`) réduisent ce risque sans l'éliminer ; le service worker (PWA, voir plus bas) l'atténue encore, sans l'annuler.
- **Rejeu/rollback côté serveur** : rien n'empêche aujourd'hui un opérateur serveur malveillant de remplacer un blob chiffré par une ancienne version valide du même fichier — authentique mais périmé, non détecté. Durcissement futur envisagé : compteur de version signé.
- **Une machine déjà compromise pendant l'usage** (contenu déchiffré en RAM pendant la consultation) n'est protégée par aucun logiciel de chiffrement, celui-ci ou un autre.
- **Accès mobile avec la YubiKey physique** : bloqué sur iOS/iPadOS par l'implémentation WebAuthn d'Apple (n'expose pas l'extension PRF à un authentificateur externe itinérant, quel que soit le navigateur — tous imposés sur le moteur WebKit sur ces plateformes). Limite de plateforme, pas de ce produit.
- **Métadonnées visibles côté serveur malgré le chiffrement** : taille des fichiers, horodatage des accès, volume de trafic.
- **L'authentification réseau par YubiKey (voir « Premier accès » plus haut) protège contre l'accès réseau non autorisé, pas contre le déchiffrement** — ce n'est pas un mécanisme cryptographique équivalent au chiffrement de bout en bout ; un compte serveur compromis n'ouvre toujours aucun coffre sans, en plus, la YubiKey (PRF) ou la phrase BIP39 propre à ce coffre. Restreindre l'exposition réseau du conteneur (Tailscale/VPN/reverse proxy) est recommandé en défense supplémentaire.
- **Fenêtre de bootstrap du tout premier enregistrement d'appareil** : quiconque atteint le port avant que l'opérateur ait enregistré sa YubiKey peut s'enregistrer à sa place et prendre le contrôle de l'accès au serveur (pas des coffres eux-mêmes, protégés séparément). Fenêtre courte en usage normal, mais réelle sur un port exposé publiquement dès le démarrage — voir « Premier accès » plus haut pour la mitigation recommandée. Récupération en cas de mauvais enregistrement : supprimer `device_credentials.json` dans le volume de données et recommencer.

**Pas de flux « mot de passe oublié ».** Il n'existe pas, volontairement. La perte de toutes les YubiKey enregistrées sur un coffre et l'absence de phrase de récupération BIP39 rendent ce coffre définitivement inaccessible — aucune porte dérobée, y compris pour l'opérateur de l'instance.

## PWA et mise en cache du code applicatif

L'app se comporte comme une PWA (manifest + service worker, `sw.js` à la racine du dépôt) : le code (page, module WASM) est mis en cache après le premier chargement, et n'est resservi par le réseau qu'à la demande explicite de l'utilisateur (bouton « Vérifier » dans le pied de la barre latérale), jamais silencieusement à chaque ouverture. Ceci n'affaiblit ni ne remplace le point « code resservi à chaque chargement » ci-dessus — ça atténue seulement la fréquence à laquelle un serveur compromis pourrait effectivement resservir un code différent, ça ne l'empêche pas structurellement.

Le cache applicatif du service worker (code) est strictement distinct du cache OPFS (données de coffre déjà chiffrées, utilisé pour le mode hors ligne — voir PRD §6.2) : le service worker ne met jamais en cache d'appel vers `/vaults/...`.

## État actuel du projet

Les étapes 1 à 9 de l'ordre de développement du PRD (§9) sont faites et validées sur du matériel réel (YubiKey physique, conteneur Docker, vrai navigateur) — voir `CLAUDE.md` pour le détail de chaque étape et les décisions de conception prises en cours de route.

Le premier critère d'acceptation du PRD (§8 : « `docker compose up` démarre une instance fonctionnelle sans étape manuelle supplémentaire ») est désormais respecté à la lettre : un seul conteneur sert l'API et le frontend depuis la même origine.

Passe de durcissement (PRD §10) faite le 2026-09-01 : revue de la frontière WASM/JS (`wasm/src/lib.rs` ne parle jamais lui-même au réseau ni à WebAuthn, ne fait que passer des octets ; aucun `console.log`/`console.error` dans `web/index.html`, aucun secret en `localStorage`), CORS resserré (deny-all par défaut, opt-in via `CORS_ALLOWED_ORIGIN`, voir plus haut), licence MIT figée avec fichier `LICENSE`.

## Licence

MIT — voir [`LICENSE`](./LICENSE).
