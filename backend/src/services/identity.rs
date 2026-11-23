//! Forwarded caller identity.
//!
//! A server can opt in (`servers.forward_identity`) to learn who is calling it. MCPx then adds a
//! short-lived HS256 JWT to every request it forwards to that server, in the `X-MCPX-Identity`
//! header, signed with a secret that belongs to that server alone. The server verifies the
//! signature, issuer, audience (its MCPx server name) and expiry, then applies its own access rules.
//!
//! Callers never supply this header: MCPx builds each upstream request from scratch.
//!
//! With `TRUSTED_PROXY_HOPS` set, the identity also carries the caller's IP address (`ip`), so a
//! server can limit access by network. It is read from the right-hand end of X-Forwarded-For,
//! the entries appended by MCPx's own proxies, which a caller can't forge.

use axum::http::HeaderMap;
use chrono::Utc;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::net::IpAddr;
use uuid::Uuid;

use crate::messages::error;
use crate::services::crypto;

pub const IDENTITY_HEADER: &str = "X-MCPX-Identity";
pub const IDENTITY_SECRET_CREDENTIAL: &str = "identity_secret";
pub const ISSUER: &str = "mcpx";
pub const TOKEN_TTL_SECONDS: i64 = 60;

const SQL_SELECT_IDENTITY_SECRET: &str =
    "SELECT encrypted_value FROM credentials WHERE server_id = $1 AND credential_type = 'identity_secret'";

const SQL_SELECT_USER_IN_ORG: &str = r#"
    SELECT u.email, m.role
    FROM users u
    JOIN org_members m ON m.user_id = u.id AND m.org_id = $2
    WHERE u.id = $1
"#;

const SQL_DELETE_IDENTITY_SECRET: &str =
    "DELETE FROM credentials WHERE server_id = $1 AND credential_type = 'identity_secret'";

const SQL_INSERT_IDENTITY_SECRET: &str = "INSERT INTO credentials (server_id, credential_type, encrypted_value, name) VALUES ($1, 'identity_secret', $2, 'Identity signing secret')";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallerKind {
    User,
    ServiceAccount,
}

/// Who is making a proxied call, as established by the proxy's authentication.
#[derive(Debug, Clone)]
pub struct Caller {
    pub id: Uuid,
    pub org_id: Uuid,
    pub kind: CallerKind,
    pub ip: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentityClaims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub kind: CallerKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    pub org: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
}

pub fn build_claims(
    caller: &Caller,
    server_name: &str,
    email: Option<String>,
    role: Option<String>,
    now: i64,
) -> IdentityClaims {
    let mut jti = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut jti);
    IdentityClaims {
        iss: ISSUER.to_string(),
        aud: server_name.to_string(),
        sub: caller.id.to_string(),
        kind: caller.kind,
        email: email.map(|e| e.trim().to_lowercase()),
        role,
        org: caller.org_id.to_string(),
        ip: caller.ip.clone(),
        iat: now,
        exp: now + TOKEN_TTL_SECONDS,
        jti: hex_encode(&jti),
    }
}

pub fn sign(claims: &IdentityClaims, secret: &str) -> Result<String, String> {
    encode(
        &Header::new(Algorithm::HS256),
        claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| format!("{}: {}", error::JWT_ERROR, e))
}

/// The caller's IP address as seen by the outermost of `trusted_hops` proxies in front of MCPx.
///
/// Each proxy appends the address it received the request from to X-Forwarded-For, so the
/// client's address is the `trusted_hops`-th entry from the right. Anything further left was
/// supplied by the client and is ignored. Returns None when not configured or not present.
pub fn client_ip(headers: &HeaderMap, trusted_hops: usize) -> Option<String> {
    if trusted_hops == 0 {
        return None;
    }
    let entries: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .collect();
    let entry = entries
        .len()
        .checked_sub(trusted_hops)
        .map(|i| entries[i])?;
    entry.parse::<IpAddr>().ok().map(|ip| ip.to_string())
}

/// A new random signing secret for one server (256 bits, URL-safe base64).
pub fn generate_secret() -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Replaces the server's signing secret and returns the new one. It is shown to the admin once.
pub async fn rotate_secret(
    pool: &PgPool,
    encryption_key: &str,
    server_id: Uuid,
) -> Result<String, String> {
    let secret = generate_secret();
    let encrypted = crypto::encrypt(&secret, &crypto::derive_key(encryption_key))?;
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    sqlx::query(SQL_DELETE_IDENTITY_SECRET)
        .bind(server_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    sqlx::query(SQL_INSERT_IDENTITY_SECRET)
        .bind(server_id)
        .bind(&encrypted)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(secret)
}

pub async fn delete_secret(pool: &PgPool, server_id: Uuid) -> Result<(), String> {
    sqlx::query(SQL_DELETE_IDENTITY_SECRET)
        .bind(server_id)
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

pub async fn has_secret(pool: &PgPool, server_id: Uuid) -> Result<bool, String> {
    let row: Option<(String,)> = sqlx::query_as(SQL_SELECT_IDENTITY_SECRET)
        .bind(server_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| e.to_string())?;
    Ok(row.is_some())
}

/// The `X-MCPX-Identity` header for one call to an opted-in server.
///
/// Fails rather than sending the call without an identity: a server that opted in relies on it.
pub async fn identity_header(
    pool: &PgPool,
    encryption_key: &str,
    server_id: Uuid,
    server_name: &str,
    caller: &Caller,
) -> Result<(String, String), String> {
    let row: Option<(String,)> = sqlx::query_as(SQL_SELECT_IDENTITY_SECRET)
        .bind(server_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| format!("{}: {}", error::DATABASE_ERROR, e))?;
    let encrypted = row
        .ok_or_else(|| error::IDENTITY_SECRET_MISSING.to_string())?
        .0;
    let secret = crypto::decrypt(&encrypted, &crypto::derive_key(encryption_key))?;

    let (email, role) = match caller.kind {
        CallerKind::User => {
            let row: Option<(String, String)> = sqlx::query_as(SQL_SELECT_USER_IN_ORG)
                .bind(caller.id)
                .bind(caller.org_id)
                .fetch_optional(pool)
                .await
                .map_err(|e| format!("{}: {}", error::DATABASE_ERROR, e))?;
            let (email, role) = row.ok_or_else(|| error::USER_NOT_FOUND.to_string())?;
            (Some(email), Some(role))
        }
        CallerKind::ServiceAccount => (None, None),
    };

    let claims = build_claims(caller, server_name, email, role, Utc::now().timestamp());
    Ok((IDENTITY_HEADER.to_string(), sign(&claims, &secret)?))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{decode, DecodingKey, Validation};

    fn user() -> Caller {
        Caller {
            id: Uuid::new_v4(),
            org_id: Uuid::new_v4(),
            kind: CallerKind::User,
            ip: None,
        }
    }

    fn xff(values: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append("x-forwarded-for", v.parse().unwrap());
        }
        h
    }

    #[test]
    fn client_ip_comes_from_the_trusted_end_of_x_forwarded_for() {
        assert_eq!(
            client_ip(&xff(&["203.0.113.9"]), 1).as_deref(),
            Some("203.0.113.9")
        );
        // A client-supplied entry on the left is ignored.
        assert_eq!(
            client_ip(&xff(&["6.6.6.6, 203.0.113.9"]), 1).as_deref(),
            Some("203.0.113.9")
        );
        assert_eq!(
            client_ip(&xff(&["6.6.6.6", "203.0.113.9"]), 1).as_deref(),
            Some("203.0.113.9")
        );
        // Two proxies (e.g. CDN + load balancer): the client is second from the right.
        assert_eq!(
            client_ip(&xff(&["6.6.6.6, 203.0.113.9, 10.0.0.5"]), 2).as_deref(),
            Some("203.0.113.9")
        );
        assert_eq!(
            client_ip(&xff(&["2001:db8::1"]), 1).as_deref(),
            Some("2001:db8::1")
        );
    }

    #[test]
    fn client_ip_is_absent_when_not_configured_missing_or_invalid() {
        assert_eq!(client_ip(&xff(&["203.0.113.9"]), 0), None);
        assert_eq!(client_ip(&HeaderMap::new(), 1), None);
        assert_eq!(client_ip(&xff(&["203.0.113.9"]), 2), None);
        assert_eq!(client_ip(&xff(&["not-an-ip"]), 1), None);
    }

    #[test]
    fn identity_carries_the_caller_ip_only_when_known() {
        let now = Utc::now().timestamp();
        let with_ip = Caller {
            ip: Some("203.0.113.9".into()),
            ..user()
        };
        let token = sign(&build_claims(&with_ip, "reports", None, None, now), "s").unwrap();
        assert_eq!(
            verify(&token, "s", "reports").unwrap().ip.as_deref(),
            Some("203.0.113.9")
        );

        let token = sign(&build_claims(&user(), "reports", None, None, now), "s").unwrap();
        assert!(verify(&token, "s", "reports").unwrap().ip.is_none());
    }

    fn verify(token: &str, secret: &str, audience: &str) -> Result<IdentityClaims, String> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&[audience]);
        validation.set_issuer(&[ISSUER]);
        decode::<IdentityClaims>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        )
        .map(|d| d.claims)
        .map_err(|e| e.to_string())
    }

    #[test]
    fn signed_identity_verifies_with_the_server_secret() {
        let caller = user();
        let now = Utc::now().timestamp();
        let claims = build_claims(
            &caller,
            "reports",
            Some(" Manager@Example.com ".into()),
            Some("member".into()),
            now,
        );
        let token = sign(&claims, "server-secret").unwrap();

        let got = verify(&token, "server-secret", "reports").unwrap();
        assert_eq!(got.sub, caller.id.to_string());
        assert_eq!(got.org, caller.org_id.to_string());
        assert_eq!(got.email.as_deref(), Some("manager@example.com"));
        assert_eq!(got.role.as_deref(), Some("member"));
        assert_eq!(got.kind, CallerKind::User);
        assert_eq!(got.exp - got.iat, TOKEN_TTL_SECONDS);
    }

    #[test]
    fn another_servers_secret_or_audience_is_rejected() {
        let claims = build_claims(
            &user(),
            "reports",
            Some("a@example.com".into()),
            None,
            Utc::now().timestamp(),
        );
        let token = sign(&claims, "reports-secret").unwrap();
        assert!(verify(&token, "other-secret", "reports").is_err());
        assert!(verify(&token, "reports-secret", "other-server").is_err());
    }

    #[test]
    fn expired_identity_is_rejected() {
        let old = Utc::now().timestamp() - 3600;
        let claims = build_claims(&user(), "reports", Some("a@example.com".into()), None, old);
        let token = sign(&claims, "s").unwrap();
        assert!(verify(&token, "s", "reports").is_err());
    }

    #[test]
    fn service_accounts_carry_no_email_or_role() {
        let caller = Caller {
            kind: CallerKind::ServiceAccount,
            ..user()
        };
        let claims = build_claims(&caller, "reports", None, None, Utc::now().timestamp());
        let token = sign(&claims, "s").unwrap();
        let got = verify(&token, "s", "reports").unwrap();
        assert_eq!(got.kind, CallerKind::ServiceAccount);
        assert!(got.email.is_none() && got.role.is_none());
        let payload = token.split('.').nth(1).unwrap();
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let json = String::from_utf8(URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
        assert!(!json.contains("email") && json.contains("\"service_account\""));
    }

    #[test]
    fn each_token_and_secret_is_unique() {
        let caller = user();
        let now = Utc::now().timestamp();
        let a = build_claims(&caller, "reports", None, None, now);
        let b = build_claims(&caller, "reports", None, None, now);
        assert_ne!(a.jti, b.jti);
        let (s1, s2) = (generate_secret(), generate_secret());
        assert_ne!(s1, s2);
        assert_eq!(s1.len(), 43);
    }
}
