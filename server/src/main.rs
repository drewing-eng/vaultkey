mod device_auth;
mod storage;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderValue, StatusCode},
    middleware,
    response::{IntoResponse, Redirect, Response},
    routing::{delete, get, post},
    Router,
};
use device_auth::DeviceAuthState;
use std::{net::SocketAddr, path::PathBuf};
use storage::Storage;
use tower_http::{
    cors::{Any, CorsLayer},
    services::{ServeDir, ServeFile},
};

#[derive(Clone)]
struct AppState {
    storage: Storage,
    device_auth: DeviceAuthState,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let data_dir = PathBuf::from(std::env::var("DATA_DIR").unwrap_or_else(|_| "/data".into()));
    // Racine des fichiers statiques (frontend + module WASM), servis par ce
    // même conteneur pour que le client n'ait plus à connaître/saisir une
    // URL d'API séparée : même origine, appels relatifs. Disposition
    // préservée telle quelle (web/, wasm/pkg/, sw.js à la racine) pour
    // rester identique à celle utilisée en développement local
    // (`python3 -m http.server` depuis la racine du dépôt) — aucune
    // adaptation des chemins relatifs dans web/index.html ni de la portée
    // du service worker (sw.js) n'a donc été nécessaire.
    let static_root =
        PathBuf::from(std::env::var("STATIC_DIR").unwrap_or_else(|_| ".".into()));
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    // RP_ID/RP_ORIGIN : identité WebAuthn de ce serveur. Par défaut adaptés
    // au développement local (`http://localhost:8080`, exception "contexte
    // sécurisé" que les navigateurs accordent à localhost). Pour tout
    // déploiement réel (VPS), DOIVENT être définis sur le vrai domaine en
    // HTTPS — WebAuthn refuse toute autre origine (voir README).
    let rp_id = std::env::var("RP_ID").unwrap_or_else(|_| "localhost".into());
    let rp_origin =
        std::env::var("RP_ORIGIN").unwrap_or_else(|_| format!("http://localhost:{port}"));

    let device_auth = DeviceAuthState::load(&data_dir, &rp_id, &rp_origin).await;

    let state = AppState {
        storage: Storage::new(data_dir),
        device_auth,
    };

    let app = Router::new()
        // --- Routes exigeant une session valide (voir device_auth::require_session) ---
        .route("/vaults", get(list_vaults))
        .route("/vaults/{vault_id}", delete(delete_vault))
        .route(
            "/vaults/{vault_id}/manifest",
            get(get_manifest).put(put_manifest),
        )
        .route(
            "/vaults/{vault_id}/envelopes",
            get(get_envelopes).put(put_envelopes),
        )
        .route("/vaults/{vault_id}/meta", get(get_meta).put(put_meta))
        .route(
            "/vaults/{vault_id}/blobs/{blob_id}",
            get(get_blob).put(put_blob),
        )
        .route("/auth/devices", get(device_auth::list_devices))
        .route("/auth/devices/{cred_id}", delete(device_auth::remove_device))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            device_auth::require_session,
        ))
        // --- Routes volontairement hors session : bootstrap (premier
        // enregistrement) et login doivent être atteignables avant qu'aucune
        // session n'existe encore. register_start applique lui-même sa
        // propre garde (session requise dès qu'un appareil existe déjà). ---
        .route("/auth/status", get(device_auth::status))
        .route("/auth/register/start", post(device_auth::register_start))
        .route("/auth/register/finish", post(device_auth::register_finish))
        .route("/auth/login/start", post(device_auth::login_start))
        .route("/auth/login/finish", post(device_auth::login_finish))
        // --- Fichiers statiques (frontend + WASM), aussi hors session : il
        // faut pouvoir charger la page avant même de s'authentifier. Sans
        // conséquence sur le modèle zero-knowledge : uniquement du code
        // public, jamais une donnée de coffre. ---
        .route("/", get(|| async { Redirect::permanent("/web/index.html") }))
        .nest_service("/web", ServeDir::new(static_root.join("web")))
        .nest_service("/wasm/pkg", ServeDir::new(static_root.join("wasm/pkg")))
        .route_service("/sw.js", ServeFile::new(static_root.join("sw.js")))
        // PRD §10 : CORS resserré. Le déploiement recommandé (ce conteneur
        // sert API + frontend sur une seule origine) n'a besoin d'aucun
        // en-tête CORS : une requête same-origin n'est jamais soumise au
        // contrôle CORS du navigateur, qu'un CorsLayer soit présent ou non.
        // Par défaut (CORS_ALLOWED_ORIGIN absente) : CorsLayer::new() sans
        // origine autorisée, donc aucune origine tierce ne peut lire les
        // réponses de ce serveur. Écarté seulement si l'opérateur choisit
        // explicitement de séparer frontend et API sur deux origines
        // (STATIC_DIR/apiBase), auquel cas CORS_ALLOWED_ORIGIN doit pointer
        // sur l'origine exacte du frontend (une seule, pas de wildcard).
        .layer(cors_layer())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("impossible d'écouter sur le port configuré");
    tracing::info!("VaultKey server à l'écoute sur {addr}");
    axum::serve(listener, app).await.expect("le serveur s'est arrêté de façon inattendue");
}

/// `CORS_ALLOWED_ORIGIN` non définie : aucune origine autorisée (défaut,
/// couvre le déploiement à origine unique). Définie : reflète exactement
/// cette seule origine, jamais un wildcard, avec l'en-tête Authorization
/// (jeton de session) explicitement autorisé.
fn cors_layer() -> CorsLayer {
    match std::env::var("CORS_ALLOWED_ORIGIN") {
        Ok(origin) => {
            let origin: HeaderValue = origin
                .parse()
                .expect("CORS_ALLOWED_ORIGIN doit être une origine valide (ex. https://vault.example.com)");
            CorsLayer::new()
                .allow_origin(origin)
                .allow_methods(Any)
                .allow_headers(Any)
        }
        Err(_) => CorsLayer::new(),
    }
}

/// Énumération aveugle des coffres existants (PRD : aucune notion côté
/// serveur de ce que contient un coffre, juste la liste de leurs id).
async fn list_vaults(State(state): State<AppState>) -> Response {
    match state.storage.list_vaults().await {
        Ok(ids) => axum::Json(ids).into_response(),
        Err(e) => {
            tracing::error!("erreur de lecture du répertoire vaults/ : {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Suppression définitive d'un coffre : tout son répertoire (manifeste,
/// enveloppes, meta, blobs) en une seule opération, contrairement au RESET
/// (géré entièrement côté client, ne touche jamais ce répertoire en bloc).
/// Aveugle comme le reste de ce serveur : ne sait pas ce qu'il supprime,
/// seulement qu'un répertoire dont l'id est passé la validation disparaît.
async fn delete_vault(State(state): State<AppState>, Path(vault_id): Path<String>) -> StatusCode {
    let Some(path) = state.storage.vault_dir_path(&vault_id) else {
        return StatusCode::BAD_REQUEST;
    };
    match state.storage.delete_dir(&path).await {
        Ok(()) => StatusCode::OK,
        Err(e) => {
            tracing::error!("erreur de suppression {path:?} : {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

async fn get_meta(State(state): State<AppState>, Path(vault_id): Path<String>) -> Response {
    read_blob(&state, state.storage.meta_path(&vault_id)).await
}

async fn put_meta(
    State(state): State<AppState>,
    Path(vault_id): Path<String>,
    body: Bytes,
) -> StatusCode {
    write_blob(&state, state.storage.meta_path(&vault_id), &body).await
}

async fn get_manifest(State(state): State<AppState>, Path(vault_id): Path<String>) -> Response {
    read_blob(&state, state.storage.manifest_path(&vault_id)).await
}

async fn put_manifest(
    State(state): State<AppState>,
    Path(vault_id): Path<String>,
    body: Bytes,
) -> StatusCode {
    write_blob(&state, state.storage.manifest_path(&vault_id), &body).await
}

async fn get_envelopes(State(state): State<AppState>, Path(vault_id): Path<String>) -> Response {
    read_blob(&state, state.storage.envelopes_path(&vault_id)).await
}

async fn put_envelopes(
    State(state): State<AppState>,
    Path(vault_id): Path<String>,
    body: Bytes,
) -> StatusCode {
    write_blob(&state, state.storage.envelopes_path(&vault_id), &body).await
}

async fn get_blob(
    State(state): State<AppState>,
    Path((vault_id, blob_id)): Path<(String, String)>,
) -> Response {
    read_blob(&state, state.storage.blob_path(&vault_id, &blob_id)).await
}

async fn put_blob(
    State(state): State<AppState>,
    Path((vault_id, blob_id)): Path<(String, String)>,
    body: Bytes,
) -> StatusCode {
    write_blob(&state, state.storage.blob_path(&vault_id, &blob_id), &body).await
}

async fn read_blob(state: &AppState, path: Option<PathBuf>) -> Response {
    let Some(path) = path else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match state.storage.read(&path).await {
        Ok(data) => data.into_response(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            StatusCode::NOT_FOUND.into_response()
        }
        Err(e) => {
            tracing::error!("erreur de lecture {path:?} : {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn write_blob(state: &AppState, path: Option<PathBuf>, body: &[u8]) -> StatusCode {
    let Some(path) = path else {
        return StatusCode::BAD_REQUEST;
    };
    match state.storage.write(&path, body).await {
        Ok(()) => StatusCode::OK,
        Err(e) => {
            tracing::error!("erreur d'écriture {path:?} : {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}
