//! Axum middleware for JWT authentication.
//!
//! Extracts JWT from the `Authorization: Bearer <token>` header
//! or the `?token=<token>` query parameter.

use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use tracing::debug;

use crate::user_context::UserContext;

/// Axum extractor that validates a JWT and produces a [`UserContext`].
///
/// Usage in a handler:
/// ```ignore
/// async fn handler(AuthUser(ctx): AuthUser) -> impl IntoResponse {
///     // ctx is a validated UserContext
/// }
/// ```
///
/// The JWT is extracted from (in order):
/// 1. `Authorization: Bearer <token>` header
/// 2. `?token=<token>` query parameter
///
/// Requires `AuthState` to be present in the axum app state.
#[derive(Debug, Clone)]
pub struct AuthUser(pub UserContext);

/// State required by the auth middleware.
///
/// Must be added to the axum app state for `AuthUser` extraction to work.
pub trait AuthState: Send + Sync + 'static {
    /// Get the PEM-encoded public key for a campaign.
    /// Returns None if the campaign is not registered.
    fn get_public_key_pem(&self, campaign_id_hint: Option<&str>) -> Option<Vec<u8>>;

    /// Get the revocation list.
    fn get_revocation_list(&self) -> Option<&crate::revocation::RevocationList>;

    /// Get the global PEM key (for single-campaign deployments).
    /// Override `get_public_key_pem` for multi-campaign support.
    fn get_default_public_key_pem(&self) -> Option<&[u8]>;
}

/// Query parameter for token-based auth.
#[derive(Deserialize)]
struct TokenQuery {
    token: Option<String>,
}

/// Extract the JWT string from the request.
///
/// Checks Authorization header first, then query parameter.
fn extract_token(parts: &Parts) -> Option<String> {
    // Try Authorization: Bearer <token>
    if let Some(auth_header) = parts.headers.get("authorization") {
        if let Ok(value) = auth_header.to_str() {
            if let Some(token) = value.strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
        }
    }

    // Try ?token=<token> query parameter
    let query_str = parts.uri.query().unwrap_or("");
    if let Ok(query) = serde_urlencoded::from_str::<TokenQuery>(query_str) {
        if let Some(token) = query.token {
            return Some(token);
        }
    }

    None
}

/// Auth rejection response — always returns 401 with a generic message.
///
/// Specific failure reasons are logged at debug level but never sent to clients.
pub struct AuthRejection;

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        (StatusCode::UNAUTHORIZED, "authentication required").into_response()
    }
}

impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync + 'static,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract the token
        let token = extract_token(parts).ok_or_else(|| {
            debug!("No JWT token found in request");
            AuthRejection
        })?;

        // Look for the public key in extensions (set by app state layer)
        let public_key_pem = parts
            .extensions
            .get::<PublicKeyPem>()
            .ok_or_else(|| {
                debug!("No public key configured for auth");
                AuthRejection
            })?;

        // Look for optional revocation list
        let revocation = parts.extensions.get::<SharedRevocationList>();

        let ctx = crate::validation::validate_jwt(
            &token,
            &public_key_pem.0,
            revocation.map(|r| &*r.0),
        )
        .map_err(|e| {
            debug!("JWT validation failed: {e}");
            AuthRejection
        })?;

        Ok(AuthUser(ctx))
    }
}

/// Extension type for the public key PEM bytes.
#[derive(Clone)]
pub struct PublicKeyPem(pub Vec<u8>);

/// Extension type for a shared revocation list.
#[derive(Clone)]
pub struct SharedRevocationList(pub std::sync::Arc<crate::revocation::RevocationList>);

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    #[test]
    fn extract_token_from_bearer_header() {
        let req = Request::builder()
            .header("authorization", "Bearer my.jwt.token")
            .body(())
            .expect("build request");
        let (parts, _) = req.into_parts();
        assert_eq!(extract_token(&parts), Some("my.jwt.token".to_string()));
    }

    #[test]
    fn extract_token_from_query_param() {
        let req = Request::builder()
            .uri("/sync?token=my.jwt.token")
            .body(())
            .expect("build request");
        let (parts, _) = req.into_parts();
        assert_eq!(extract_token(&parts), Some("my.jwt.token".to_string()));
    }

    #[test]
    fn extract_token_prefers_header() {
        let req = Request::builder()
            .uri("/sync?token=query-token")
            .header("authorization", "Bearer header-token")
            .body(())
            .expect("build request");
        let (parts, _) = req.into_parts();
        assert_eq!(extract_token(&parts), Some("header-token".to_string()));
    }

    #[test]
    fn extract_token_returns_none_when_missing() {
        let req = Request::builder()
            .uri("/sync")
            .body(())
            .expect("build request");
        let (parts, _) = req.into_parts();
        assert_eq!(extract_token(&parts), None);
    }

    #[test]
    fn extract_token_ignores_non_bearer_auth() {
        let req = Request::builder()
            .header("authorization", "Basic dXNlcjpwYXNz")
            .body(())
            .expect("build request");
        let (parts, _) = req.into_parts();
        assert_eq!(extract_token(&parts), None);
    }
}
