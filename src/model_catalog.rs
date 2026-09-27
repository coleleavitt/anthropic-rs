//! The live Anthropic model catalog (`GET /v1/models`): entry normalization,
//! pagination, and local pricing.
//!
//! Anthropic does not expose pricing on `/v1/models`, so cost stays local
//! ([`crate::models::resolve_model_cost`]). Degraded entries that omit
//! `max_input_tokens` are rejected so they cannot collapse a cached catalog
//! to 200k/64k defaults. Pagination follows `after_id = last_id` until
//! `has_more` is false, bounded to [`MAX_CATALOG_PAGES`] pages.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::models::{CLAUDE_MYTHOS_5_MODEL_ID, ModelCost, resolve_model_cost};

/// `https://api.anthropic.com/v1/models`
pub const ANTHROPIC_MODELS_ENDPOINT: &str = "https://api.anthropic.com/v1/models";
/// Page size requested.
pub const MODEL_CATALOG_PAGE_LIMIT: u32 = 1_000;
/// Hard bound on pages followed.
pub const MAX_CATALOG_PAGES: usize = 100;
/// Bound on the live fetch.
pub const MODEL_CATALOG_FETCH_TIMEOUT_SECS: u64 = 3;
/// Effort levels the API may report.
pub const EFFORT_LEVELS: [&str; 5] = ["low", "medium", "high", "xhigh", "max"];
/// How long a cached catalog is served without a refresh (six hours).
pub const MODEL_CATALOG_MAX_AGE_MS: i64 = 6 * 60 * 60 * 1000;

/// A cached catalog, keyed on the Claude Code version it was fetched under.
///
/// New models ship with a Claude Code release and Anthropic gates them on the
/// declared version, so a version change invalidates the cache regardless of
/// its age — otherwise a launch-day model (Opus 5.5 with 2.1.280) stays
/// invisible for up to [`MODEL_CATALOG_MAX_AGE_MS`]. A cache written before the
/// version field existed (`claude_code_version: None`) is invalidated once.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelCatalogSnapshot {
    /// Normalized entries.
    pub models: Vec<CatalogModel>,
    /// Fetch time, epoch milliseconds.
    pub fetched_at: i64,
    /// Claude Code version declared when the catalog was fetched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claude_code_version: Option<String>,
}

impl ModelCatalogSnapshot {
    /// Whether the snapshot may be served without waiting for a refresh:
    /// fetched under `claude_code_version` and younger than `max_age_ms`.
    pub fn is_fresh(&self, now_ms: i64, max_age_ms: i64, claude_code_version: &str) -> bool {
        !self.version_changed(claude_code_version)
            && now_ms.saturating_sub(self.fetched_at) < max_age_ms
    }

    /// Whether the snapshot was fetched under a different Claude Code version
    /// than `claude_code_version` — known wrong rather than merely old, so the
    /// caller should wait for the refresh (falling back to this snapshot only
    /// if the refresh fails).
    pub fn version_changed(&self, claude_code_version: &str) -> bool {
        self.claude_code_version.as_deref() != Some(claude_code_version)
    }
}

/// One normalized catalog entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CatalogModel {
    /// Model id.
    pub id: String,
    /// Display name (falls back to the id).
    pub name: String,
    /// `capabilities.thinking.supported`
    pub reasoning: bool,
    /// Accepts image input.
    pub image_input: bool,
    /// Local per-million-token cost.
    pub cost: ModelCost,
    /// `max_input_tokens`
    pub context_window: u64,
    /// `max_tokens` (defaults to 64 000 when absent).
    pub max_tokens: u64,
    /// Effort levels the API reports as usable; empty when unsupported.
    pub effort_levels: Vec<String>,
    /// `thinking.types.adaptive.supported`
    pub adaptive_thinking: bool,
    /// `thinking.types.enabled.supported`
    pub budget_thinking: bool,
    /// Restricted-access model (Mythos), for display only.
    pub limited: bool,
}

impl Serialize for ModelCost {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("ModelCost", 4)?;
        s.serialize_field("input", &self.input)?;
        s.serialize_field("output", &self.output)?;
        s.serialize_field("cacheRead", &self.cache_read)?;
        s.serialize_field("cacheWrite", &self.cache_write)?;
        s.end()
    }
}

impl<'de> Deserialize<'de> for ModelCost {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Raw {
            input: f64,
            output: f64,
            cache_read: f64,
            cache_write: f64,
        }
        let raw = Raw::deserialize(deserializer)?;
        Ok(ModelCost {
            input: raw.input,
            output: raw.output,
            cache_read: raw.cache_read,
            cache_write: raw.cache_write,
        })
    }
}

fn is_supported(flag: Option<&serde_json::Value>) -> bool {
    flag.and_then(|f| f.get("supported"))
        .and_then(|s| s.as_bool())
        == Some(true)
}

fn positive_int(value: Option<&serde_json::Value>) -> Option<u64> {
    value.and_then(|v| v.as_u64()).filter(|v| *v > 0)
}

/// Anthropic occasionally lists non-Claude entries; filter like Claude Code
/// so the catalog never offers a model this provider cannot serve.
pub fn is_usable_model_id(id: &str) -> bool {
    let lower = id.to_ascii_lowercase();
    lower.starts_with("claude") || lower.starts_with("anthropic")
}

/// Normalize one raw `/v1/models` entry. Returns `None` for non-objects,
/// non-Claude ids, and degraded entries without a positive `max_input_tokens`.
pub fn normalize_catalog_model(raw: &serde_json::Value) -> Option<CatalogModel> {
    let id = raw.get("id")?.as_str()?.trim();
    if id.is_empty() || !is_usable_model_id(id) {
        return None;
    }
    let context_window = positive_int(raw.get("max_input_tokens"))?;
    let capabilities = raw.get("capabilities");
    let thinking = capabilities.and_then(|c| c.get("thinking"));
    let thinking_types = thinking.and_then(|t| t.get("types"));
    let effort = capabilities.and_then(|c| c.get("effort"));
    let effort_levels = if is_supported(effort) {
        EFFORT_LEVELS
            .iter()
            .filter(|level| is_supported(effort.and_then(|e| e.get(**level))))
            .map(|level| (*level).to_owned())
            .collect()
    } else {
        Vec::new()
    };
    Some(CatalogModel {
        id: id.to_owned(),
        name: raw
            .get("display_name")
            .and_then(|n| n.as_str())
            .unwrap_or(id)
            .to_owned(),
        reasoning: is_supported(thinking),
        image_input: is_supported(capabilities.and_then(|c| c.get("image_input"))),
        cost: resolve_model_cost(id),
        context_window,
        max_tokens: positive_int(raw.get("max_tokens")).unwrap_or(64_000),
        effort_levels,
        adaptive_thinking: is_supported(thinking_types.and_then(|t| t.get("adaptive"))),
        budget_thinking: is_supported(thinking_types.and_then(|t| t.get("enabled"))),
        limited: id.starts_with(CLAUDE_MYTHOS_5_MODEL_ID),
    })
}

/// One page of `/v1/models`.
#[derive(Debug, Clone, Deserialize)]
pub struct ModelsPage {
    /// Raw entries.
    #[serde(default)]
    pub data: Vec<serde_json::Value>,
    /// Whether another page follows.
    #[serde(default)]
    pub has_more: bool,
    /// Cursor for `after_id`.
    #[serde(default)]
    pub last_id: Option<String>,
}

/// Cursor state while walking pages. Pure, so the pagination contract is
/// testable without a network: feed each page in and ask for the next
/// `after_id`.
#[derive(Debug, Default)]
pub struct CatalogPager {
    models: Vec<CatalogModel>,
    after_id: Option<String>,
    pages: usize,
}

impl CatalogPager {
    /// A fresh walk.
    pub fn new() -> Self {
        Self::default()
    }

    /// Query parameters for the next request.
    pub fn query(&self) -> Vec<(String, String)> {
        let mut query = vec![("limit".to_owned(), MODEL_CATALOG_PAGE_LIMIT.to_string())];
        if let Some(after) = &self.after_id {
            query.push(("after_id".to_owned(), after.clone()));
        }
        query
    }

    /// Absorb a page. Returns `Ok(true)` when another page must be fetched,
    /// `Ok(false)` when the walk is complete, and an error for an invalid or
    /// looping cursor or when the page bound is exceeded.
    pub fn absorb(&mut self, page: &ModelsPage) -> Result<bool> {
        self.pages += 1;
        for entry in &page.data {
            if let Some(model) = normalize_catalog_model(entry) {
                match self.models.iter_mut().find(|m| m.id == model.id) {
                    Some(slot) => *slot = model,
                    None => self.models.push(model),
                }
            }
        }
        if !page.has_more {
            return Ok(false);
        }
        match page.last_id.as_deref().filter(|id| !id.is_empty()) {
            Some(last) if Some(last) != self.after_id.as_deref() => {
                self.after_id = Some(last.to_owned())
            }
            _ => {
                return Err(Error::Protocol(
                    "anthropic model list returned an invalid pagination cursor".into(),
                ));
            }
        }
        if self.pages >= MAX_CATALOG_PAGES {
            return Err(Error::Protocol(
                "anthropic model list exceeded the pagination limit".into(),
            ));
        }
        Ok(true)
    }

    /// The models collected so far; an empty catalog is an error.
    pub fn finish(self) -> Result<Vec<CatalogModel>> {
        if self.models.is_empty() {
            return Err(Error::Protocol(
                "anthropic model list returned no usable models".into(),
            ));
        }
        Ok(self.models)
    }
}

/// Fetch and paginate the live catalog with an OAuth access token.
#[cfg(feature = "client")]
pub async fn fetch_model_catalog(
    http: &reqwest::Client,
    access_token: &str,
    user_agent: &str,
) -> Result<Vec<CatalogModel>> {
    fetch_model_catalog_from(http, ANTHROPIC_MODELS_ENDPOINT, access_token, user_agent).await
}

/// [`fetch_model_catalog`] against an explicit endpoint (tests).
#[cfg(feature = "client")]
pub async fn fetch_model_catalog_from(
    http: &reqwest::Client,
    endpoint: &str,
    access_token: &str,
    user_agent: &str,
) -> Result<Vec<CatalogModel>> {
    let mut pager = CatalogPager::new();
    loop {
        let mut url = url::Url::parse(endpoint)?;
        url.query_pairs_mut().extend_pairs(pager.query());
        let response = http
            .get(url)
            .header("accept", "application/json")
            .header("authorization", format!("Bearer {access_token}"))
            .header("anthropic-version", crate::endpoints::ANTHROPIC_VERSION)
            .header("anthropic-beta", crate::endpoints::OAUTH_BETA)
            .header("user-agent", user_agent)
            .timeout(std::time::Duration::from_secs(
                MODEL_CATALOG_FETCH_TIMEOUT_SECS,
            ))
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            let retry_after_ms = crate::oauth::parse_retry_after_ms(response.headers());
            let body = crate::error::redacted_response_body(response, &[access_token]).await;
            return Err(Error::Endpoint {
                status: status.as_u16(),
                permanent: status.as_u16() == 401 || status.as_u16() == 403,
                error_code: None,
                retry_after_ms,
                body,
            });
        }
        let page: ModelsPage = response.json().await?;
        if !pager.absorb(&page)? {
            break;
        }
    }
    pager.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(fetched_at: i64, version: Option<&str>) -> ModelCatalogSnapshot {
        ModelCatalogSnapshot {
            models: vec![],
            fetched_at,
            claude_code_version: version.map(str::to_owned),
        }
    }

    #[test]
    fn catalog_freshness_is_keyed_on_age_and_claude_code_version() {
        let now = 10_000_000;
        let v = crate::claude_version::CLAUDE_CODE_VERSION;
        assert!(snapshot(now, Some(v)).is_fresh(now, 1000, v));
        assert!(!snapshot(now - 5000, Some(v)).is_fresh(now, 1000, v));
        // A Claude Code version change invalidates an otherwise fresh cache.
        let old = snapshot(now, Some("2.1.278"));
        assert!(!old.is_fresh(now, 1000, "2.1.280"));
        assert!(old.is_fresh(now, 1000, "2.1.278"));
        assert!(old.version_changed("2.1.280"));
        assert!(!old.version_changed("2.1.278"));
        // A cache written before the version field existed is invalidated once.
        assert!(!snapshot(now, None).is_fresh(now, 1000, v));
        assert!(snapshot(now, None).version_changed(v));
    }

    #[test]
    fn catalog_snapshot_round_trips_the_ts_cache_shape() {
        let parsed: ModelCatalogSnapshot =
            serde_json::from_str(r#"{"models":[],"fetchedAt":5,"claudeCodeVersion":"2.1.280"}"#)
                .unwrap();
        assert_eq!(parsed, snapshot(5, Some("2.1.280")));
        let legacy: ModelCatalogSnapshot =
            serde_json::from_str(r#"{"models":[],"fetchedAt":5}"#).unwrap();
        assert_eq!(legacy.claude_code_version, None);
        assert_eq!(
            serde_json::to_string(&legacy).unwrap(),
            r#"{"models":[],"fetchedAt":5}"#
        );
    }

    fn entry(id: &str, max_input: Option<u64>) -> serde_json::Value {
        let mut value = serde_json::json!({
            "id": id,
            "display_name": format!("Display {id}"),
            "max_tokens": 128000,
            "capabilities": {
                "image_input": {"supported": true},
                "effort": {"supported": true, "low": {"supported": true}, "medium": {"supported": true}, "high": {"supported": true}, "xhigh": {"supported": false}, "max": {"supported": true}},
                "thinking": {"supported": true, "types": {"enabled": {"supported": false}, "adaptive": {"supported": true}}}
            }
        });
        if let Some(max_input) = max_input {
            value["max_input_tokens"] = serde_json::json!(max_input);
        }
        value
    }

    #[test]
    fn normalizes_capabilities_and_rejects_degraded_entries() {
        let model = normalize_catalog_model(&entry("claude-opus-5", Some(1_000_000))).unwrap();
        assert_eq!(model.name, "Display claude-opus-5");
        assert!(
            model.reasoning
                && model.image_input
                && model.adaptive_thinking
                && !model.budget_thinking
        );
        assert_eq!(model.effort_levels, vec!["low", "medium", "high", "max"]);
        assert_eq!(model.context_window, 1_000_000);
        assert_eq!(model.max_tokens, 128_000);
        assert_eq!(model.cost.input, 5.0);
        assert!(!model.limited);
        assert!(
            normalize_catalog_model(&entry("claude-opus-5", None)).is_none(),
            "degraded entry"
        );
        assert!(normalize_catalog_model(&entry("gpt-5", Some(1))).is_none());
        assert!(normalize_catalog_model(&serde_json::json!({"id":"claude-x"})).is_none());
        let mythos = normalize_catalog_model(&entry("claude-mythos-5", Some(1_000_000))).unwrap();
        assert!(mythos.limited);
        assert_eq!(mythos.cost.cache_read, 1.0);
        let text_only = normalize_catalog_model(
            &serde_json::json!({"id":"claude-3-haiku","max_input_tokens":200000}),
        )
        .unwrap();
        assert!(!text_only.image_input && !text_only.reasoning);
        assert!(text_only.effort_levels.is_empty());
        assert_eq!(text_only.max_tokens, 64_000);
        // Round-trips through the on-disk shape.
        let json = serde_json::to_string(&model).unwrap();
        assert!(json.contains("\"cacheRead\":0.5"));
        assert_eq!(serde_json::from_str::<CatalogModel>(&json).unwrap(), model);
    }

    #[test]
    fn follows_pagination_until_has_more_is_false() {
        let mut pager = CatalogPager::new();
        assert_eq!(pager.query(), vec![("limit".to_owned(), "1000".to_owned())]);
        let first: ModelsPage = serde_json::from_value(serde_json::json!({
            "data": [entry("claude-opus-5", Some(1000000)), entry("gpt-5", Some(1))],
            "has_more": true, "first_id": "claude-opus-5", "last_id": "claude-opus-5"
        }))
        .unwrap();
        assert!(pager.absorb(&first).unwrap());
        assert_eq!(
            pager.query()[1],
            ("after_id".to_owned(), "claude-opus-5".to_owned())
        );
        let second: ModelsPage = serde_json::from_value(serde_json::json!({
            "data": [entry("claude-sonnet-5", Some(1000000)), entry("claude-opus-5", Some(500000))],
            "has_more": false
        }))
        .unwrap();
        assert!(!pager.absorb(&second).unwrap());
        let models = pager.finish().unwrap();
        let ids: Vec<&str> = models.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(ids, vec!["claude-opus-5", "claude-sonnet-5"]);
        assert_eq!(
            models[0].context_window, 500_000,
            "later pages win on duplicate ids"
        );
    }

    #[test]
    fn rejects_invalid_or_looping_cursors_and_empty_catalogs() {
        let mut pager = CatalogPager::new();
        let looping: ModelsPage = serde_json::from_value(
            serde_json::json!({"data": [], "has_more": true, "last_id": "x"}),
        )
        .unwrap();
        assert!(pager.absorb(&looping).unwrap());
        assert!(pager.absorb(&looping).is_err(), "same cursor twice");
        let missing: ModelsPage =
            serde_json::from_value(serde_json::json!({"data": [], "has_more": true})).unwrap();
        assert!(CatalogPager::new().absorb(&missing).is_err());
        let done: ModelsPage =
            serde_json::from_value(serde_json::json!({"data": [], "has_more": false})).unwrap();
        let mut empty = CatalogPager::new();
        assert!(!empty.absorb(&done).unwrap());
        assert!(empty.finish().is_err());
        // Page bound.
        let mut bounded = CatalogPager::new();
        for i in 0..(MAX_CATALOG_PAGES - 1) {
            let page: ModelsPage = serde_json::from_value(
                serde_json::json!({"data": [], "has_more": true, "last_id": format!("id-{i}")}),
            )
            .unwrap();
            assert!(bounded.absorb(&page).unwrap(), "page {i}");
        }
        let page: ModelsPage = serde_json::from_value(
            serde_json::json!({"data": [], "has_more": true, "last_id": "final"}),
        )
        .unwrap();
        assert!(bounded.absorb(&page).is_err());
    }

    /// Serves two pages keyed on `after_id`, recording each request line.
    #[cfg(feature = "client")]
    async fn paginated_server() -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut buf = vec![0u8; 8192];
                let Ok(read) = stream.read(&mut buf).await else {
                    continue;
                };
                let request = String::from_utf8_lossy(&buf[..read]).to_string();
                let line = request.lines().next().unwrap_or_default().to_owned();
                let body = if line.contains("after_id=claude-opus-5") {
                    serde_json::json!({"data":[entry("claude-sonnet-5", Some(1000000))],"has_more":false}).to_string()
                } else {
                    serde_json::json!({"data":[entry("claude-opus-5", Some(1000000))],"has_more":true,"last_id":"claude-opus-5"}).to_string()
                };
                log.lock().unwrap().push(request);
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        (format!("http://{address}/v1/models"), seen)
    }

    #[cfg(feature = "client")]
    #[tokio::test]
    async fn live_fetch_sends_bearer_and_follows_pages() {
        let (endpoint, seen) = paginated_server().await;
        let models = fetch_model_catalog_from(
            &reqwest::Client::new(),
            &endpoint,
            "sk-ant-oat01-catalog-token",
            "claude-cli/2.1.260 (external, cli)",
        )
        .await
        .unwrap();
        let ids: Vec<&str> = models.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(ids, vec!["claude-opus-5", "claude-sonnet-5"]);
        let requests = seen.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].contains("limit=1000"));
        assert!(!requests[0].contains("after_id"));
        assert!(requests[1].contains("after_id=claude-opus-5"));
        for request in requests.iter() {
            let lower = request.to_ascii_lowercase();
            assert!(lower.contains("authorization: bearer sk-ant-oat01-catalog-token"));
            assert!(lower.contains("anthropic-beta: oauth-2025-04-20"));
            assert!(lower.contains("user-agent: claude-cli/2.1.260"));
        }
    }
}
