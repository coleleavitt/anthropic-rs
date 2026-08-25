//! Turning a resolved [`Credential`] into concrete request-header mutations.
//!
//! This is the reusable Anthropic auth header contract: the bearer token (or
//! api key), the `anthropic-beta: oauth-2025-04-20` opt-in, and
//! `anthropic-version`. It is deliberately transport-agnostic — the
//! `reqwest`-specific application lives behind the `client` feature so an
//! auth-only consumer never links an HTTP stack.

use crate::endpoints::{ANTHROPIC_VERSION, OAUTH_BETA};
use crate::token::{AuthHeader, Credential};

/// The header changes a credential requires on an outgoing Anthropic request.
///
/// `set` overwrites, `remove` deletes, and `ensure_beta` names beta tokens that
/// must be present in the (comma-joined) `anthropic-beta` header — the caller
/// merges these with any betas it already sends rather than overwriting them.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct HeaderMutation {
    /// Headers to set outright.
    set: Vec<(String, String)>,
    /// Header names to remove.
    remove: Vec<String>,
    /// Beta tokens that must appear in `anthropic-beta` (merge, don't clobber).
    ensure_beta: Vec<String>,
}

impl std::fmt::Debug for HeaderMutation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let set = self
            .set
            .iter()
            .map(|(name, value)| {
                if name.eq_ignore_ascii_case("authorization")
                    || name.eq_ignore_ascii_case("x-api-key")
                {
                    (name.as_str(), "***")
                } else {
                    (name.as_str(), value.as_str())
                }
            })
            .collect::<Vec<_>>();
        formatter
            .debug_struct("HeaderMutation")
            .field("set", &set)
            .field("remove", &self.remove)
            .field("ensure_beta", &self.ensure_beta)
            .finish()
    }
}

impl HeaderMutation {
    /// Header name/value pairs to set. Reading this slice deliberately exposes
    /// authentication values; prefer [`Self::apply_to_header_map`] when using
    /// the reqwest client feature.
    pub fn set_headers(&self) -> &[(String, String)] {
        &self.set
    }

    /// Header names that must be removed before applying the sets.
    pub fn removed_headers(&self) -> &[String] {
        &self.remove
    }

    /// Beta tokens that must be merged into `anthropic-beta`.
    pub fn required_betas(&self) -> &[String] {
        &self.ensure_beta
    }

    /// The mutation for a resolved credential. OAuth and API-key auth are
    /// mutually exclusive, so each removes the other's header.
    pub fn for_credential(credential: &Credential) -> Self {
        let mut set = vec![("anthropic-version".to_owned(), ANTHROPIC_VERSION.to_owned())];
        let mut remove = Vec::new();
        let mut ensure_beta = Vec::new();
        match credential.auth_header() {
            AuthHeader::Bearer(token) => {
                set.push(("authorization".to_owned(), format!("Bearer {token}")));
                ensure_beta.push(OAUTH_BETA.to_owned());
                remove.push("x-api-key".to_owned());
            }
            AuthHeader::ApiKey(key) => {
                set.push(("x-api-key".to_owned(), key));
                remove.push("authorization".to_owned());
            }
        }
        Self {
            set,
            remove,
            ensure_beta,
        }
    }

    /// Build standard first-party request headers for a short-lived Workload
    /// Identity Federation token. WIF uses bearer auth but is not Claude
    /// subscription OAuth, so it adds no OAuth beta or Claude Code identity.
    #[cfg(feature = "federation")]
    pub fn for_federated_token(token: &crate::federation::FederatedToken) -> Self {
        Self {
            set: vec![
                ("anthropic-version".to_owned(), ANTHROPIC_VERSION.to_owned()),
                (
                    "authorization".to_owned(),
                    format!("Bearer {}", token.access.expose()),
                ),
            ],
            remove: vec!["x-api-key".to_owned()],
            ensure_beta: Vec::new(),
        }
    }

    /// Merge [`HeaderMutation::ensure_beta`] into an existing `anthropic-beta`
    /// value (comma-separated), preserving order and dropping duplicates.
    pub fn merge_beta(&self, existing: &str) -> String {
        let mut betas: Vec<&str> = existing
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        for want in &self.ensure_beta {
            if !betas.contains(&want.as_str()) {
                betas.push(want);
            }
        }
        betas.join(",")
    }

    /// Non-auth header sets (skips `authorization` / `x-api-key`) for folding
    /// into construction-time extra headers. Includes a merged `anthropic-beta`
    /// when [`Self::ensure_beta`] is non-empty.
    pub fn non_auth_headers(&self, existing_beta: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for (key, value) in &self.set {
            if key.eq_ignore_ascii_case("authorization") || key.eq_ignore_ascii_case("x-api-key") {
                continue;
            }
            out.push((key.clone(), value.clone()));
        }
        if !self.ensure_beta.is_empty() {
            out.push(("anthropic-beta".to_owned(), self.merge_beta(existing_beta)));
        }
        out
    }

    /// Apply this mutation to a `reqwest` header map: removals first, then
    /// sets, then merge `ensure_beta` into `anthropic-beta`.
    #[cfg(feature = "client")]
    pub fn apply_to_header_map(&self, headers: &mut reqwest::header::HeaderMap) {
        use reqwest::header::{HeaderName, HeaderValue};

        for name in &self.remove {
            if let Ok(n) = HeaderName::try_from(name.as_str()) {
                headers.remove(n);
            }
        }
        for (key, value) in &self.set {
            let Ok(name) = HeaderName::try_from(key.as_str()) else {
                continue;
            };
            let Ok(value) = HeaderValue::from_str(value) else {
                continue;
            };
            headers.insert(name, value);
        }
        if !self.ensure_beta.is_empty() {
            let existing = headers
                .get("anthropic-beta")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let merged = self.merge_beta(existing);
            if let Ok(value) = HeaderValue::from_str(&merged)
                && let Ok(name) = HeaderName::try_from("anthropic-beta")
            {
                headers.insert(name, value);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::*;
    use crate::token::{AccessToken, ApiKey, OAuthTokens, RefreshToken};

    fn oauth_credential() -> Credential {
        Credential::Oauth(OAuthTokens {
            access: AccessToken::new("sk-ant-oat01-access"),
            refresh: RefreshToken::new("sk-ant-ort01-refresh"),
            expires_at: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            refresh_expires_at: None,
            scopes: vec!["user:inference".into()],
            account: None,
            organization: None,
        })
    }

    #[test]
    fn oauth_sets_bearer_and_removes_api_key() {
        let mutation = HeaderMutation::for_credential(&oauth_credential());
        assert!(
            mutation
                .set_headers()
                .contains(&("authorization".into(), "Bearer sk-ant-oat01-access".into()))
        );
        assert!(mutation.removed_headers().contains(&"x-api-key".to_owned()));
        assert_eq!(mutation.required_betas(), vec![OAUTH_BETA.to_owned()]);
        assert!(!format!("{mutation:?}").contains("sk-ant-oat01-access"));
    }

    #[test]
    fn api_key_sets_x_api_key_and_removes_authorization() {
        let cred = Credential::ApiKey {
            key: ApiKey::new("sk-ant-api01-static"),
        };
        let mutation = HeaderMutation::for_credential(&cred);
        assert!(
            mutation
                .set_headers()
                .contains(&("x-api-key".into(), "sk-ant-api01-static".into()))
        );
        assert!(
            mutation
                .removed_headers()
                .contains(&"authorization".to_owned())
        );
        assert!(mutation.required_betas().is_empty());
    }

    #[cfg(feature = "federation")]
    #[test]
    fn workload_identity_uses_plain_bearer_without_oauth_beta() {
        let token = crate::federation::FederatedToken {
            access: AccessToken::new("federated-access"),
            expires_at: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            scope: None,
        };
        let mutation = HeaderMutation::for_federated_token(&token);
        assert!(
            mutation
                .set_headers()
                .contains(&("authorization".into(), "Bearer federated-access".into()))
        );
        assert!(mutation.removed_headers().contains(&"x-api-key".into()));
        assert!(mutation.required_betas().is_empty());
    }

    #[test]
    fn merge_beta_adds_without_clobbering_or_duplicating() {
        let mutation = HeaderMutation::for_credential(&oauth_credential());
        assert_eq!(
            mutation.merge_beta("prompt-caching-2024-07-31"),
            format!("prompt-caching-2024-07-31,{OAUTH_BETA}")
        );
        // Already present → no duplicate.
        assert_eq!(mutation.merge_beta(OAUTH_BETA), OAUTH_BETA);
        // Empty existing.
        assert_eq!(mutation.merge_beta(""), OAUTH_BETA);
    }

    #[test]
    fn non_auth_headers_never_leak_the_secret() {
        let mutation = HeaderMutation::for_credential(&oauth_credential());
        let headers = mutation.non_auth_headers("");
        assert!(
            headers
                .iter()
                .all(|(k, _)| !k.eq_ignore_ascii_case("authorization")),
            "auth header leaked into non-auth set: {headers:?}"
        );
        assert!(
            headers
                .iter()
                .any(|(k, v)| k == "anthropic-version" && v == crate::endpoints::ANTHROPIC_VERSION)
        );
        assert!(
            headers
                .iter()
                .any(|(k, v)| k == "anthropic-beta" && v == OAUTH_BETA)
        );
    }

    #[cfg(feature = "client")]
    #[test]
    fn apply_to_header_map_swaps_auth_modes() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-api-key", "stale".parse().unwrap());
        headers.insert(
            "anthropic-beta",
            "prompt-caching-2024-07-31".parse().unwrap(),
        );

        HeaderMutation::for_credential(&oauth_credential()).apply_to_header_map(&mut headers);

        assert!(headers.get("x-api-key").is_none(), "stale api key survived");
        assert_eq!(
            headers.get("authorization").unwrap(),
            "Bearer sk-ant-oat01-access"
        );
        let beta = headers.get("anthropic-beta").unwrap().to_str().unwrap();
        assert!(beta.contains("prompt-caching-2024-07-31"));
        assert!(beta.contains(OAUTH_BETA));
    }
}
