use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::messages::error;
use crate::middleware::auth::AuthUser;
use crate::services::crypto;
use crate::services::health_check::discover_oauth_endpoints;
use crate::AppState;

const SQL_SELECT_SERVER_ID: &str = "SELECT id FROM servers WHERE name = $1 AND org_id = $2";

const SQL_SELECT_SERVER_OAUTH_CONFIG: &str =
    "SELECT id, url, oauth_client_id, oauth_token_url FROM servers WHERE name = $1 AND org_id = $2";

const SQL_PIN_TOKEN_URL: &str = "UPDATE servers SET oauth_token_url = $1 WHERE id = $2";

const SQL_SELECT_CLIENT_SECRET: &str =
    "SELECT encrypted_value FROM credentials WHERE server_id = $1 AND credential_type = 'oauth_client_secret'";

const SQL_UPSERT_OAUTH_TOKENS: &str = r#"
    INSERT INTO oauth_tokens (server_id, org_id, access_token_encrypted, refresh_token_encrypted, token_type, expires_at, scope, dynamic_client_id)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    ON CONFLICT (server_id, org_id) 
    DO UPDATE SET 
        access_token_encrypted = $3,
        refresh_token_encrypted = $4,
        token_type = $5,
        expires_at = $6,
        scope = $7,
        dynamic_client_id = $8,
        oauth_state = NULL,
        updated_at = NOW()
"#;

const SQL_SELECT_OAUTH_STATUS: &str =
    "SELECT COALESCE(access_token_encrypted, ''), expires_at FROM oauth_tokens WHERE server_id = $1 AND org_id = $2";

const SQL_DELETE_OAUTH_TOKENS: &str =
    "DELETE FROM oauth_tokens WHERE server_id = $1 AND org_id = $2";

#[derive(Debug, Deserialize)]
pub struct StoreTokensRequest {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_type: Option<String>,
    pub expires_in: Option<i64>,
    pub scope: Option<String>,
    pub client_id: Option<String>, // Dynamic client_id from OAuth registration
}

#[derive(Debug, Serialize)]
pub struct OAuthStatusResponse {
    pub connected: bool,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct ExchangeCodeRequest {
    pub code: String,
    pub code_verifier: String,
    pub redirect_uri: String,
}

pub async fn store_oauth_tokens(
    State(state): State<Arc<AppState>>,
    Path(server_name): Path<String>,
    auth_user: AuthUser,
    Json(tokens): Json<StoreTokensRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let server_id: Option<Uuid> = sqlx::query_scalar(SQL_SELECT_SERVER_ID)
        .bind(&server_name)
        .bind(auth_user.org_id)
        .fetch_optional(&state.db.pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("{}: {}", error::DATABASE_ERROR, e),
            )
        })?;

    let server_id =
        server_id.ok_or((StatusCode::NOT_FOUND, error::SERVER_NOT_FOUND.to_string()))?;

    save_tokens(&state, server_id, auth_user.org_id, tokens).await?;

    Ok(StatusCode::CREATED)
}

/// Exchange an authorization code for tokens using the server's pre-registered
/// client. Done server-side so the client secret never reaches the browser.
pub async fn exchange_oauth_code(
    State(state): State<Arc<AppState>>,
    Path(server_name): Path<String>,
    auth_user: AuthUser,
    Json(req): Json<ExchangeCodeRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let row: Option<(Uuid, String, Option<String>, Option<String>)> =
        sqlx::query_as(SQL_SELECT_SERVER_OAUTH_CONFIG)
            .bind(&server_name)
            .bind(auth_user.org_id)
            .fetch_optional(&state.db.pool)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("{}: {}", error::DATABASE_ERROR, e),
                )
            })?;

    let (server_id, server_url, client_id, token_url) =
        row.ok_or((StatusCode::NOT_FOUND, error::SERVER_NOT_FOUND.to_string()))?;

    let client_id = client_id.filter(|id| !id.is_empty()).ok_or((
        StatusCode::BAD_REQUEST,
        "Server has no OAuth client ID configured".to_string(),
    ))?;

    let pinned_token_url = token_url.filter(|url| !url.is_empty());
    let token_url = match pinned_token_url {
        Some(ref url) => url.clone(),
        None => discover_oauth_endpoints(&server_url)
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, e))?
            .0,
    };

    let key = crypto::derive_key(&state.config.encryption_key);

    let client_secret: Option<String> = sqlx::query_scalar(SQL_SELECT_CLIENT_SECRET)
        .bind(server_id)
        .fetch_optional(&state.db.pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("{}: {}", error::DATABASE_ERROR, e),
            )
        })?
        .and_then(|encrypted: String| crypto::decrypt(&encrypted, &key).ok());

    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", req.code.as_str()),
        ("redirect_uri", req.redirect_uri.as_str()),
        ("code_verifier", req.code_verifier.as_str()),
        ("client_id", client_id.as_str()),
    ];
    if let Some(ref secret) = client_secret {
        form.push(("client_secret", secret.as_str()));
    }

    let response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .post(&token_url)
        .form(&form)
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("Failed to call token endpoint: {}", e),
            )
        })?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        tracing::warn!(
            "Token exchange failed for {}: status={}, body={}",
            server_name,
            status,
            body.chars().take(500).collect::<String>()
        );

        // Only surface the standard OAuth error fields, never the raw upstream body
        #[derive(Deserialize)]
        struct OAuthError {
            error: String,
            error_description: Option<String>,
        }
        let detail = match serde_json::from_str::<OAuthError>(&body) {
            Ok(e) => match e.error_description {
                Some(desc) => format!(": {} ({})", e.error, desc),
                None => format!(": {}", e.error),
            },
            Err(_) => String::new(),
        };
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("Token endpoint returned {}{}", status, detail),
        ));
    }

    #[derive(Deserialize)]
    struct TokenResponse {
        access_token: String,
        refresh_token: Option<String>,
        token_type: Option<String>,
        expires_in: Option<i64>,
        scope: Option<String>,
    }

    let tokens: TokenResponse = response.json().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("Failed to parse token response: {}", e),
        )
    })?;

    save_tokens(
        &state,
        server_id,
        auth_user.org_id,
        StoreTokensRequest {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            token_type: tokens.token_type,
            expires_in: tokens.expires_in,
            scope: tokens.scope,
            client_id: Some(client_id),
        },
    )
    .await?;

    // Pin the endpoint that worked, so refreshes send the client secret only there
    // and never to an endpoint discovered at runtime.
    if pinned_token_url.is_none() {
        sqlx::query(SQL_PIN_TOKEN_URL)
            .bind(&token_url)
            .bind(server_id)
            .execute(&state.db.pool)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("{}: {}", error::DATABASE_ERROR, e),
                )
            })?;
    }

    tracing::info!("OAuth code exchanged and tokens stored for {}", server_name);

    Ok(StatusCode::CREATED)
}

async fn save_tokens(
    state: &AppState,
    server_id: Uuid,
    org_id: Uuid,
    tokens: StoreTokensRequest,
) -> Result<(), (StatusCode, String)> {
    let key = crypto::derive_key(&state.config.encryption_key);

    let access_encrypted = crypto::encrypt(&tokens.access_token, &key).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("{}: {}", error::ENCRYPTION_ERROR, e),
        )
    })?;

    let refresh_encrypted = match &tokens.refresh_token {
        Some(rt) => Some(crypto::encrypt(rt, &key).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("{}: {}", error::ENCRYPTION_ERROR, e),
            )
        })?),
        None => None,
    };

    let expires_at = tokens
        .expires_in
        .map(|secs| Utc::now() + Duration::seconds(secs));

    sqlx::query(SQL_UPSERT_OAUTH_TOKENS)
        .bind(server_id)
        .bind(org_id)
        .bind(&access_encrypted)
        .bind(&refresh_encrypted)
        .bind(tokens.token_type.unwrap_or_else(|| "Bearer".to_string()))
        .bind(expires_at)
        .bind(&tokens.scope)
        .bind(&tokens.client_id) // $8: dynamic_client_id
        .execute(&state.db.pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("{}: {}", error::DATABASE_ERROR, e),
            )
        })?;

    Ok(())
}

pub async fn oauth_status(
    State(state): State<Arc<AppState>>,
    Path(server_name): Path<String>,
    auth_user: AuthUser,
) -> Result<Json<OAuthStatusResponse>, (StatusCode, String)> {
    let server_id: Option<Uuid> = sqlx::query_scalar(SQL_SELECT_SERVER_ID)
        .bind(&server_name)
        .bind(auth_user.org_id)
        .fetch_optional(&state.db.pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("{}: {}", error::DATABASE_ERROR, e),
            )
        })?;

    let server_id =
        server_id.ok_or((StatusCode::NOT_FOUND, error::SERVER_NOT_FOUND.to_string()))?;

    let row: Option<(String, Option<chrono::DateTime<chrono::Utc>>)> =
        sqlx::query_as(SQL_SELECT_OAUTH_STATUS)
            .bind(server_id)
            .bind(auth_user.org_id)
            .fetch_optional(&state.db.pool)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("{}: {}", error::DATABASE_ERROR, e),
                )
            })?;

    match row {
        Some((token, expires_at)) if !token.is_empty() => Ok(Json(OAuthStatusResponse {
            connected: true,
            expires_at,
        })),
        _ => Ok(Json(OAuthStatusResponse {
            connected: false,
            expires_at: None,
        })),
    }
}

pub async fn revoke_oauth(
    State(state): State<Arc<AppState>>,
    Path(server_name): Path<String>,
    auth_user: AuthUser,
) -> Result<StatusCode, (StatusCode, String)> {
    let server_id: Option<Uuid> = sqlx::query_scalar(SQL_SELECT_SERVER_ID)
        .bind(&server_name)
        .bind(auth_user.org_id)
        .fetch_optional(&state.db.pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("{}: {}", error::DATABASE_ERROR, e),
            )
        })?;

    let server_id =
        server_id.ok_or((StatusCode::NOT_FOUND, error::SERVER_NOT_FOUND.to_string()))?;

    sqlx::query(SQL_DELETE_OAUTH_TOKENS)
        .bind(server_id)
        .bind(auth_user.org_id)
        .execute(&state.db.pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("{}: {}", error::DATABASE_ERROR, e),
            )
        })?;

    Ok(StatusCode::NO_CONTENT)
}
