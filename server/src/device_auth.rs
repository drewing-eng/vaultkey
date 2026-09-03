//! Authentification réseau au serveur par YubiKey (WebAuthn "passkey", sans
//! extension PRF — remplace le jeton statique généré dans les logs). Couche
//! strictement distincte du déverrouillage d'un coffre (cérémonie PRF
//! séparée, entièrement côté client) : ce module ne touche à aucune donnée
//! de coffre, seulement à qui a le droit d'atteindre l'API réseau.
//!
//! Pas de multi-utilisateur (cohérent avec le PRD §3 : "aucun compte
//! administrateur") : toutes les YubiKey enregistrées ici sont des
//! appareils équivalents pour un seul opérateur d'instance, pas des
//! identités distinctes.

use crate::AppState;
use axum::{
    extract::{Path, Request, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::{rngs::SysRng, TryRng};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};
use webauthn_rs::prelude::*;

// Durée de vie d'une session : assez longue pour ne pratiquement jamais
// redemander de contact YubiKey en usage normal (le jeton de session est de
// toute façon persisté côté client, voir web/index.html), assez courte pour
// qu'une session oubliée sur un appareil perdu finisse par expirer d'elle-même.
const SESSION_TTL: Duration = Duration::from_secs(60 * 60 * 24 * 30);

// Identité WebAuthn fixe : ce n'est pas un compte utilisateur, juste ce que
// l'API WebAuthn exige comme "user handle". Toutes les YubiKey de ce serveur
// partagent la même, volontairement.
const OPERATOR_UUID: Uuid = Uuid::nil();

#[derive(Serialize, Deserialize, Clone)]
struct StoredDevice {
    label: String,
    passkey: Passkey,
}

#[derive(Clone)]
pub struct DeviceAuthState {
    webauthn: Arc<Webauthn>,
    devices_path: PathBuf,
    devices: Arc<Mutex<Vec<StoredDevice>>>,
    // Une seule cérémonie d'enregistrement/authentification à la fois :
    // usage mono-opérateur, pas besoin d'une table par requête/cookie.
    reg_state: Arc<Mutex<Option<PasskeyRegistration>>>,
    auth_state: Arc<Mutex<Option<PasskeyAuthentication>>>,
    // En mémoire uniquement (pas persisté sur disque) : un redémarrage du
    // conteneur invalide les sessions actives, il faut retoucher la
    // YubiKey. Compromis assumé pour rester simple — un self-host
    // mono-opérateur redémarre rarement, et retoucher la clé est un geste
    // léger comparé à aller chercher un jeton dans les logs.
    sessions: Arc<Mutex<HashMap<String, SystemTime>>>,
}

impl DeviceAuthState {
    pub async fn load(data_dir: &std::path::Path, rp_id: &str, rp_origin: &str) -> Self {
        let origin = Url::parse(rp_origin)
            .unwrap_or_else(|e| panic!("RP_ORIGIN invalide ({rp_origin:?}) : {e}"));
        let webauthn = WebauthnBuilder::new(rp_id, &origin)
            .expect("configuration WebAuthn invalide (RP_ID/RP_ORIGIN incohérents)")
            .rp_name("VaultKey")
            .build()
            .expect("configuration WebAuthn invalide");

        let devices_path = data_dir.join("device_credentials.json");
        let devices = match tokio::fs::read(&devices_path).await {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Err(_) => Vec::new(),
        };

        Self {
            webauthn: Arc::new(webauthn),
            devices_path,
            devices: Arc::new(Mutex::new(devices)),
            reg_state: Arc::new(Mutex::new(None)),
            auth_state: Arc::new(Mutex::new(None)),
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn persist_devices(&self) {
        let devices = self.devices.lock().unwrap().clone();
        if let (Some(parent), Ok(json)) =
            (self.devices_path.parent(), serde_json::to_vec_pretty(&devices))
        {
            let _ = std::fs::create_dir_all(parent);
            if let Err(e) = std::fs::write(&self.devices_path, json) {
                tracing::error!("échec d'écriture de {:?} : {e}", self.devices_path);
            }
        }
    }

    fn create_session(&self) -> String {
        let mut bytes = [0u8; 32];
        SysRng
            .try_fill_bytes(&mut bytes)
            .expect("le générateur aléatoire du système doit toujours réussir");
        let token = URL_SAFE_NO_PAD.encode(bytes);
        self.sessions
            .lock()
            .unwrap()
            .insert(token.clone(), SystemTime::now() + SESSION_TTL);
        token
    }

    fn session_valid(&self, token: &str) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        let now = SystemTime::now();
        sessions.retain(|_, expiry| *expiry > now);
        sessions.contains_key(token)
    }

    fn has_devices(&self) -> bool {
        !self.devices.lock().unwrap().is_empty()
    }
}

/// Sans effet de bord (contrairement à `login_start`, qui initie une vraie
/// cérémonie) : sert uniquement à ce que le frontend sache s'il doit
/// proposer un enregistrement (premier démarrage) ou une connexion.
pub async fn status(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({ "hasDevices": state.device_auth.has_devices() }))
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

/// Middleware appliqué aux routes de données (`/vaults/...`) et de gestion
/// des appareils : exige une session valide, obtenue via
/// `/auth/register/finish` ou `/auth/login/finish`.
pub async fn require_session(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    match bearer_token(req.headers()) {
        Some(token) if state.device_auth.session_valid(token) => Ok(next.run(req).await),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

/// Démarre l'enregistrement d'une YubiKey. Ouvert sans session si aucun
/// appareil n'est encore enregistré (premier démarrage — fenêtre de
/// bootstrap documentée dans le README : ne pas exposer publiquement le
/// port avant d'avoir fait ce premier enregistrement). Exige une session
/// valide sinon (ajout d'un appareil supplémentaire).
pub async fn register_start(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<CreationChallengeResponse>, StatusCode> {
    let already_has_devices = state.device_auth.has_devices();
    if already_has_devices {
        let authorized = bearer_token(&headers)
            .map(|t| state.device_auth.session_valid(t))
            .unwrap_or(false);
        if !authorized {
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    let exclude: Option<Vec<CredentialID>> = {
        let devices = state.device_auth.devices.lock().unwrap();
        if devices.is_empty() {
            None
        } else {
            Some(devices.iter().map(|d| d.passkey.cred_id().clone()).collect())
        }
    };

    let (ccr, reg_state) = state
        .device_auth
        .webauthn
        .start_passkey_registration(OPERATOR_UUID, "vaultkey", "VaultKey", exclude)
        .map_err(|e| {
            tracing::error!("webauthn register_start : {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    *state.device_auth.reg_state.lock().unwrap() = Some(reg_state);
    Ok(Json(ccr))
}

#[derive(Deserialize)]
pub struct FinishRegistration {
    label: String,
    credential: RegisterPublicKeyCredential,
}

pub async fn register_finish(
    State(state): State<AppState>,
    Json(body): Json<FinishRegistration>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let reg_state = state
        .device_auth
        .reg_state
        .lock()
        .unwrap()
        .take()
        .ok_or(StatusCode::BAD_REQUEST)?;

    let passkey = state
        .device_auth
        .webauthn
        .finish_passkey_registration(&body.credential, &reg_state)
        .map_err(|e| {
            tracing::warn!("webauthn register_finish : {e}");
            StatusCode::BAD_REQUEST
        })?;

    {
        let mut devices = state.device_auth.devices.lock().unwrap();
        devices.push(StoredDevice { label: body.label, passkey });
    }
    state.device_auth.persist_devices();

    let token = state.device_auth.create_session();
    Ok(Json(json!({ "sessionToken": token })))
}

/// Démarre une authentification : liste tous les appareils enregistrés en
/// `allowCredentials`, n'importe lequel d'entre eux peut répondre au touch.
pub async fn login_start(
    State(state): State<AppState>,
) -> Result<Json<RequestChallengeResponse>, StatusCode> {
    let passkeys: Vec<Passkey> = {
        let devices = state.device_auth.devices.lock().unwrap();
        devices.iter().map(|d| d.passkey.clone()).collect()
    };
    if passkeys.is_empty() {
        return Err(StatusCode::NOT_FOUND);
    }

    let (rcr, auth_state) = state
        .device_auth
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| {
            tracing::error!("webauthn login_start : {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    *state.device_auth.auth_state.lock().unwrap() = Some(auth_state);
    Ok(Json(rcr))
}

pub async fn login_finish(
    State(state): State<AppState>,
    Json(cred): Json<PublicKeyCredential>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let auth_state = state
        .device_auth
        .auth_state
        .lock()
        .unwrap()
        .take()
        .ok_or(StatusCode::BAD_REQUEST)?;

    let result = state
        .device_auth
        .webauthn
        .finish_passkey_authentication(&cred, &auth_state)
        .map_err(|e| {
            tracing::warn!("webauthn login_finish : {e}");
            StatusCode::UNAUTHORIZED
        })?;

    // Met à jour le compteur anti-clonage de l'appareil qui a répondu
    // (détection de credential dupliqué, recommandation standard WebAuthn).
    {
        let mut devices = state.device_auth.devices.lock().unwrap();
        for d in devices.iter_mut() {
            if d.passkey.cred_id() == result.cred_id() {
                d.passkey.update_credential(&result);
                break;
            }
        }
    }
    state.device_auth.persist_devices();

    let token = state.device_auth.create_session();
    Ok(Json(json!({ "sessionToken": token })))
}

pub async fn list_devices(State(state): State<AppState>) -> Json<serde_json::Value> {
    let devices = state.device_auth.devices.lock().unwrap();
    let list: Vec<_> = devices
        .iter()
        .map(|d| {
            json!({
                "credentialId": URL_SAFE_NO_PAD.encode(d.passkey.cred_id().as_ref()),
                "label": d.label,
            })
        })
        .collect();
    Json(json!(list))
}

/// Retire un appareil autorisé. Bloqué s'il ne reste qu'un seul appareil
/// (sinon verrouillage total du serveur, sans échappatoire côté client —
/// même garde que le retrait de la dernière YubiKey d'un coffre, PRD §6.4).
pub async fn remove_device(
    State(state): State<AppState>,
    Path(cred_id_b64): Path<String>,
) -> StatusCode {
    let Ok(cred_id_bytes) = URL_SAFE_NO_PAD.decode(cred_id_b64) else {
        return StatusCode::BAD_REQUEST;
    };

    let mut devices = state.device_auth.devices.lock().unwrap();
    if devices.len() <= 1 {
        return StatusCode::BAD_REQUEST;
    }
    let before = devices.len();
    devices.retain(|d| d.passkey.cred_id().as_ref() != cred_id_bytes.as_slice());
    if devices.len() == before {
        return StatusCode::NOT_FOUND;
    }
    drop(devices);
    state.device_auth.persist_devices();
    StatusCode::OK
}
