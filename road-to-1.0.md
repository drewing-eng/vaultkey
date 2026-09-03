# Road to 1.0 — alignement design maquette ↔ réel

Contexte : comparatif fait le 2026-08-26 entre `vaultkey-saas-prototype.html` (maquette statique, jamais mise à jour depuis) et `web/index.html` (implémentation réelle, construite aux étapes 5 à 9 du PRD comme banc de test fonctionnel, jamais encore repassée au filtre du produit fini que la maquette dessinait). Détail complet du comparatif et des décisions déjà prises : `CLAUDE.md`.

**Hors scope de ce document**, volontairement : la passe de durcissement sécurité (PRD §10 — revue de la frontière WASM/JS, resserrement du CORS permissif, licence MIT + fichier `LICENSE`), non entamée, à traiter séparément et après ce polissage. Ne pas la mélanger aux chantiers ci-dessous.

## Déjà fait (ne pas refaire)

- [x] Logs de debug retirés (`pre.output` → `.status-line`, une ligne à la fois, invisible si vide, pas de placeholder "(pas encore lancé)")
- [x] Point de statut par coffre dans la sidebar (vert/gris, un par coffre, plusieurs simultanés possibles)
- [x] Bascule thème clair/sombre (bouton texte dans le header, préférence retenue en `localStorage`)
- [x] Responsive : écran de blocage explicite sous 620px de large (`.mobile-block`), message "ouvre sur un ordinateur"
- [x] Plusieurs coffres peuvent rester déverrouillés simultanément (`unlockedVaults`) — changer de coffre ne verrouille plus les autres

## Chantier A — Icônes et identité visuelle du header

Le réel est actuellement 100% texte, la maquette a des SVG partout (logo, boutons, icônes de fichier). Ce chantier est la fondation des chantiers B/C/D ci-dessous (rail d'icônes à 860px, icônes de type de fichier, icône de clé animée) — à faire en premier si possible, mais chaque chantier peut démarrer avec un texte/placeholder en attendant si l'ordre est inversé.

- [x] Logo dans le header (`.brand`), inspiré du SVG de la maquette (carré arrondi + glyphe clé/serrure) — cohérence à vérifier avec `web/icons/icon-*.png` déjà générés à l'étape 9 (même motif de trou de serrure), pas forcément à redessiner de zéro
- [x] Numéro de version affiché sous le nom (ex. `v1.0.0-dev`), petite police mono discrète — comme la maquette
- [x] Icône (cadenas) sur le bouton "Verrouiller"
- [x] Icônes de croix sur les boutons de retrait (YubiKey d'un coffre, appareils autorisés) — actuellement un caractère `✕` brut ; à trancher si un vrai SVG apporte assez vs le garder tel quel
- [x] Icône (soleil/lune) sur la bascule de thème, à la place du texte actuel "Mode clair"/"Mode sombre"
- [x] SVG inline uniquement, pas de dépendance à une librairie d'icônes externe (cohérent avec l'app 100% vanilla JS/CSS, aucune dépendance de build ajoutée pour le frontend)

## Chantier B — Vue fichiers en table façon gestionnaire de fichiers

Dépend du chantier A pour les icônes de type de fichier (peut démarrer avant, avec une icône générique ou aucune icône en attendant).

- [x] Topbar (fil d'Ariane + actions "Verrouiller"/"Importer" alignées à droite), remplace le haut de `.main` actuel
- [x] Vraie `<table>` (colonnes Nom / Taille / Modifié / Statut) à la place des `.file-row` actuelles
- [x] Colonne "Modifié" : **le manifeste porte déjà un horodatage par fichier**, vérifié dans `core/src/manifest.rs` (`FileEntry.modified: u64`, secondes Unix) et déjà exposé par `listFilesJson()` (`{realName, blobId, size, modified}`) — aucun changement `core/`/`wasm/` nécessaire, juste formater `f.modified` côté JS (`new Date(f.modified * 1000)`)
- [x] Icône de type de fichier (générique, ou par extension si le temps le permet)
- [x] Zone de glisser-déposer (`.dropzone`), **en plus** de l'`<input type="file">` actuel, pas à la place — l'upload doit rester accessible sans souris/glisser-déposer

**Passe de correction faite le 2026-08-27** suite à une revue d'écarts détaillée demandée par l'utilisateur après la première implémentation (structure encore trop proche de l'ancien empilement de cartes) : écran fichiers rendu ISO à la maquette (plus de carte/titre autour de la table et du dropzone, tous deux en pleine largeur), style `.btn.ghost` porté depuis la maquette, actions de ligne réduites à des pictogrammes (téléchargement + **suppression, nouvelle fonctionnalité** : `Vault::remove_file` existait déjà dans `core/` mais n'était pas exposé au WASM), input fichier natif masqué, barre de statut/sync repliée dans la topbar. Détail complet des décisions : `CLAUDE.md`.

**Deuxième passe de correction faite le 2026-08-27** : les cartes "YubiKey enregistrées" et "Export", qui restaient empilées sous la table de fichiers depuis la première passe, sortent dans une modale "Réglages du coffre" derrière un bouton dédié dans la topbar (roue crantée, icône seule). Détail complet : `CLAUDE.md`.

## Chantier C — Déverrouillage intégré en un clic

Dépend du chantier A pour l'icône de clé (peut utiliser un placeholder texte en attendant).

- [x] Modale de déverrouillage avec icône de clé qui pulse pendant l'attente du contact YubiKey (animation CSS, respecter `@media (prefers-reduced-motion: reduce)`, repris de la maquette)
- [x] Texte d'état qui évolue pendant la cérémonie réelle (pas simulée comme dans la maquette : reflète les vrais états déjà loggés aujourd'hui, lecture des enveloppes, attente du touch, lecture du manifeste)
- [x] Sélectionner un coffre verrouillé déclenche directement cette modale (donc la cérémonie YubiKey), au lieu d'exiger un second clic sur "Déverrouiller avec la YubiKey"
- [x] Le déverrouillage par phrase BIP39 reste un choix explicite de l'utilisateur, jamais déclenché automatiquement à la sélection d'un coffre (seule la YubiKey l'est)

Détail des décisions de conception (bouton "Annuler" avec `AbortController`, retry, garde anti-course) : `CLAUDE.md`. **Pas testé dans un vrai navigateur (vraie YubiKey)** : à valider avant de passer au chantier D.

## Chantier D — Rail d'icônes à 860px (responsive intermédiaire)

Dépend du chantier A — sans icônes, un rail réduit n'a rien à afficher, ne pas commencer avant.

- [x] Sidebar réduite à ~64px sous 860px de large (icônes seules, noms de coffres masqués), comme la maquette
- [x] Vérifier que la sidebar réduite reste utilisable : tooltip au survol avec le nom du coffre, ou équivalent accessible au clavier

## Manière de travailler pour ce document

- Un chantier à la fois, dans l'ordre du document ou un autre si justifié — mais ne pas enchaîner plusieurs chantiers sans validation intermédiaire.
- Pas d'outil de navigateur disponible pour Claude dans ce projet à ce jour : chaque chantier doit être validé visuellement par l'utilisateur dans un vrai navigateur avant de passer au suivant.
- Après chaque changement : vérifier la syntaxe JS (`node --check` sur le contenu du `<script type="module">`), l'équilibrage des balises, puis `docker compose up -d --build` et `diff` entre la page servie (`curl`) et le fichier source.
- Cocher les cases faites dans ce document au fur et à mesure, pas seulement à la fin d'un chantier.
- Mettre à jour `CLAUDE.md` au fil de l'eau (décisions de conception prises, résultats empiriques imprévus, bugs trouvés et corrigés) — c'est la mémoire de référence du projet, pas ce document, qui reste une checklist.
