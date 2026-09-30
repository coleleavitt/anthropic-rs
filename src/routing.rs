//! Pure account selection over an [`AccountStore`], with an admission log
//! that says why each account was admitted to or dropped from the pool.
//!
//! The rules ported from the fork:
//! - never route on an access token that has already expired (every such
//!   request ships its full body to earn a guaranteed 401);
//! - never route on an account the store knows is spent (a fresh quota
//!   reading at 100%), in the fallback pool as well as the main pick;
//! - when every access token is expired, the store is usually one rotation
//!   away from healthy: try refreshing accounts in turn, skipping a refresh
//!   token that is itself expired or already known-dead;
//! - prefer an account that can actually serve over the bare `current` pin.

use chrono::{DateTime, Duration, Utc};

use crate::account::{Account, Unavailable};
use crate::store::AccountStore;
use crate::token::{OAuthTokens, RefreshToken};

/// Why an account was left out of the routing pool.
#[derive(Debug, Clone, PartialEq)]
pub enum ExclusionReason {
    /// Disabled by the user or a permanent auth failure.
    Disabled,
    /// Not an OAuth account (API keys are routed separately).
    NotOauth,
    /// The access token is past its expiry; a bearer would 401.
    AccessTokenExpired,
    /// In a rate-limit cooldown until the given instant.
    RateLimited(DateTime<Utc>),
    /// A fresh quota reading shows no headroom.
    QuotaExhausted {
        /// Five-hour window utilisation.
        five_hour_percent: Option<f64>,
        /// Seven-day window utilisation.
        seven_day_percent: Option<f64>,
    },
    /// The refresh token is past its own expiry; a refresh is a guaranteed
    /// rejection.
    RefreshTokenExpired,
    /// The refresh token was already rejected with `invalid_grant`.
    DeadRefreshToken,
}

/// One admission verdict.
#[derive(Debug, Clone, PartialEq)]
pub struct AdmissionVerdict {
    /// Store id of the account.
    pub id: String,
    /// `None` when admitted; otherwise why it was dropped.
    pub excluded: Option<ExclusionReason>,
}

/// The accounts able to send a bearer right now, plus the reason for every
/// verdict so a log can explain why a request went where it did.
#[derive(Debug, Clone)]
pub struct RoutingPool<'a> {
    /// Admitted accounts in routing order (pinned `current` first).
    pub admitted: Vec<&'a Account>,
    /// One verdict per account considered, in store order.
    pub verdicts: Vec<AdmissionVerdict>,
}

fn routing_exclusion(account: &Account, now: DateTime<Utc>) -> Option<ExclusionReason> {
    match account.unavailable_reason(now) {
        Some(Unavailable::Disabled) => return Some(ExclusionReason::Disabled),
        Some(Unavailable::RateLimited(until)) => return Some(ExclusionReason::RateLimited(until)),
        Some(Unavailable::QuotaExhausted(quota)) => {
            return Some(ExclusionReason::QuotaExhausted {
                five_hour_percent: quota.five_hour_percent,
                seven_day_percent: quota.seven_day_percent,
            });
        }
        None => {}
    }
    let Some(tokens) = account.oauth() else {
        return Some(ExclusionReason::NotOauth);
    };
    if tokens.access.expose().is_empty() || tokens.is_expired(now) {
        return Some(ExclusionReason::AccessTokenExpired);
    }
    None
}

/// Build the pool of OAuth accounts that can serve a request at `now`
/// without a refresh, with a verdict for every account.
pub fn build_routing_pool(store: &AccountStore, now: DateTime<Utc>) -> RoutingPool<'_> {
    let mut admitted = Vec::new();
    let mut verdicts = Vec::with_capacity(store.accounts.len());
    for account in &store.accounts {
        let excluded = routing_exclusion(account, now);
        if excluded.is_none() {
            admitted.push(account);
        }
        verdicts.push(AdmissionVerdict {
            id: account.id.clone(),
            excluded,
        });
    }
    if let Some(current) = store.current.as_deref()
        && let Some(pos) = admitted.iter().position(|a| a.id == current)
    {
        admitted.swap(0, pos);
    }
    RoutingPool { admitted, verdicts }
}

/// The result of choosing an access token from the shared store.
#[derive(Debug, Clone)]
pub enum AccessSelection<'a> {
    /// Route on this account's current access token.
    Selected(&'a Account),
    /// No access token is live, but these accounts hold refresh tokens
    /// worth spending (in order). Refresh one before giving up.
    AllExpired(Vec<&'a Account>),
    /// Nothing can serve and nothing can be refreshed.
    None,
}

/// Choose the account whose bearer a request should use at `now`: the
/// store's pick when its access token is live, else the next account with a
/// live token, else the refresh candidates.
pub fn select_live_access_account(store: &AccountStore, now: DateTime<Utc>) -> AccessSelection<'_> {
    let pool = build_routing_pool(store, now);
    if let Some(first) = pool.admitted.first() {
        return AccessSelection::Selected(first);
    }
    let candidates = refresh_candidates(store, now);
    if candidates.is_empty() {
        AccessSelection::None
    } else {
        AccessSelection::AllExpired(candidates)
    }
}

/// Why an account cannot be refreshed, or `None` when a refresh is worth
/// attempting.
pub fn refresh_exclusion(account: &Account, now: DateTime<Utc>) -> Option<ExclusionReason> {
    if !account.enabled {
        return Some(ExclusionReason::Disabled);
    }
    let Some(tokens) = account.oauth() else {
        return Some(ExclusionReason::NotOauth);
    };
    if tokens.refresh.expose().is_empty() || tokens.is_refresh_expired(now) {
        return Some(ExclusionReason::RefreshTokenExpired);
    }
    if account.refresh_token_is_dead() {
        return Some(ExclusionReason::DeadRefreshToken);
    }
    None
}

/// Accounts worth spending a refresh token on, in store order: enabled OAuth
/// rows whose refresh token is present, not expired, and not known-dead. One
/// revoked login must not strand the healthy ones, so callers try these in
/// turn rather than stopping at the first failure.
pub fn refresh_candidates(store: &AccountStore, now: DateTime<Utc>) -> Vec<&Account> {
    store
        .accounts
        .iter()
        .filter(|account| refresh_exclusion(account, now).is_none())
        .collect()
}

/// The account a peer process would consider "current": the pinned one when
/// its credential is live, else the first enabled account with a live
/// credential, else the pinned one regardless. The old fallback took the
/// first enabled account regardless of health, which picked an account whose
/// access token had expired 35 hours earlier.
pub fn current_shared_account(store: &AccountStore, now: DateTime<Utc>) -> Option<&Account> {
    let enabled: Vec<&Account> = store.accounts.iter().filter(|a| a.enabled).collect();
    let named = store
        .current
        .as_deref()
        .and_then(|id| enabled.iter().copied().find(|a| a.id == id));
    if let Some(named) = named
        && named.oauth_credential_is_live(now)
    {
        return Some(named);
    }
    enabled
        .into_iter()
        .find(|a| a.oauth_credential_is_live(now))
        .or(named)
}

/// Minimum remaining lifetime for a peer-rotated credential to be adopted
/// instead of spending our own refresh token.
pub const SHARED_CREDENTIAL_ADOPTION_SKEW_SECS: i64 = 60;

/// A peer-rotated credential to adopt in place of `presented_refresh`.
///
/// Anthropic rotates the refresh token on every refresh, so a peer that
/// refreshed first leaves this caller holding a superseded token whose
/// failure invalidates the whole login. An unrotated match means no peer
/// refreshed and this caller still has to; a credential expiring within the
/// skew is not worth adopting.
pub fn adoptable_shared_credential<'a>(
    store: &'a AccountStore,
    presented_refresh: &RefreshToken,
    now: DateTime<Utc>,
) -> Option<&'a OAuthTokens> {
    let tokens = current_shared_account(store, now)?.oauth()?;
    if &tokens.refresh == presented_refresh {
        return None;
    }
    if tokens.expires_at <= now + Duration::seconds(SHARED_CREDENTIAL_ADOPTION_SKEW_SECS) {
        return None;
    }
    Some(tokens)
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::account::QuotaObservation;
    use crate::token::{AccessToken, ApiKey, Credential};

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000 + secs, 0).unwrap()
    }

    fn oauth(id: &str, expires_at: DateTime<Utc>) -> Account {
        Account::new(
            id,
            Credential::Oauth(OAuthTokens {
                access: AccessToken::new(format!("sk-ant-oat01-{id}-aaaaaaaaaaaaaaaaaaaaaa")),
                refresh: RefreshToken::new(format!("sk-ant-ort01-{id}-aaaaaaaaaaaaaaaaaaaaaa")),
                expires_at,
                refresh_expires_at: Some(at(86_400 * 20)),
                scopes: vec!["user:inference".into()],
                account: None,
                organization: None,
            }),
        )
    }

    fn store(accounts: Vec<Account>) -> AccountStore {
        AccountStore {
            version: 1,
            accounts,
            current: None,
            ..AccountStore::default()
        }
    }

    #[test]
    fn never_routes_on_an_expired_access_token() {
        // `current` expired 35 hours ago; a live neighbour must be used.
        let mut s = store(vec![
            oauth("expired", at(-35 * 3600)),
            oauth("live", at(3600)),
        ]);
        s.current = Some("expired".into());
        let AccessSelection::Selected(picked) = select_live_access_account(&s, at(0)) else {
            panic!("a live account exists");
        };
        assert_eq!(picked.id, "live");
        let pool = build_routing_pool(&s, at(0));
        assert_eq!(
            pool.verdicts[0].excluded,
            Some(ExclusionReason::AccessTokenExpired)
        );
        assert_eq!(pool.verdicts[1].excluded, None);
    }

    #[test]
    fn all_expired_yields_refresh_candidates_in_order_and_skips_dead_or_expired_refresh() {
        let mut dead = oauth("dead", at(-10));
        let dead_refresh = dead.oauth().unwrap().refresh.clone();
        dead.dead_refresh_fingerprint =
            Some(crate::token::token_fingerprint(dead_refresh.expose()));
        let mut stale = oauth("stale-refresh", at(-10));
        if let Credential::Oauth(t) = &mut stale.credential {
            t.refresh_expires_at = Some(at(-1));
        }
        let mut disabled = oauth("disabled", at(-10));
        disabled.disable("x");
        let s = store(vec![
            dead,
            stale,
            disabled,
            oauth("a", at(-10)),
            oauth("b", at(-5)),
        ]);
        let AccessSelection::AllExpired(candidates) = select_live_access_account(&s, at(0)) else {
            panic!("everything is expired");
        };
        let ids: Vec<&str> = candidates.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, vec!["a", "b"]);
        assert_eq!(
            refresh_exclusion(&s.accounts[0], at(0)),
            Some(ExclusionReason::DeadRefreshToken)
        );
        assert_eq!(
            refresh_exclusion(&s.accounts[1], at(0)),
            Some(ExclusionReason::RefreshTokenExpired)
        );
        assert_eq!(
            refresh_exclusion(&s.accounts[2], at(0)),
            Some(ExclusionReason::Disabled)
        );
        let empty = store(vec![Account::new(
            "key",
            Credential::ApiKey {
                key: ApiKey::new("sk-ant-api01-aaaaaaaaaaaaaaaaaaaaaa"),
            },
        )]);
        assert!(matches!(
            select_live_access_account(&empty, at(0)),
            AccessSelection::None
        ));
        assert_eq!(
            build_routing_pool(&empty, at(0)).verdicts[0].excluded,
            Some(ExclusionReason::NotOauth)
        );
    }

    #[test]
    fn spent_accounts_are_excluded_from_the_pool_with_their_percentages() {
        let mut spent = oauth("spent", at(3600));
        spent.quota = Some(QuotaObservation {
            five_hour_percent: Some(4.0),
            seven_day_percent: Some(100.0),
            checked_at: Some(at(-60)),
        });
        let mut stale = oauth("stale-reading", at(3600));
        stale.quota = Some(QuotaObservation {
            five_hour_percent: Some(100.0),
            seven_day_percent: Some(100.0),
            checked_at: Some(at(-3600)),
        });
        let mut cooling = oauth("cooling", at(3600));
        cooling.mark_rate_limited(at(500));
        let mut s = store(vec![spent, stale, cooling, oauth("healthy", at(3600))]);
        s.current = Some("spent".into());
        let pool = build_routing_pool(&s, at(0));
        let ids: Vec<&str> = pool.admitted.iter().map(|a| a.id.as_str()).collect();
        // Fails open on the stale reading; the pinned spent account is dropped.
        assert_eq!(ids, vec!["stale-reading", "healthy"]);
        assert_eq!(
            pool.verdicts[0].excluded,
            Some(ExclusionReason::QuotaExhausted {
                five_hour_percent: Some(4.0),
                seven_day_percent: Some(100.0)
            })
        );
        assert_eq!(
            pool.verdicts[2].excluded,
            Some(ExclusionReason::RateLimited(at(500)))
        );
        // A pinned healthy account leads the pool.
        s.current = Some("healthy".into());
        assert_eq!(build_routing_pool(&s, at(0)).admitted[0].id, "healthy");
    }

    #[test]
    fn current_shared_account_prefers_one_that_can_serve() {
        let mut s = store(vec![oauth("expired", at(-10)), oauth("live", at(3600))]);
        s.current = Some("expired".into());
        assert_eq!(current_shared_account(&s, at(0)).unwrap().id, "live");
        s.current = Some("live".into());
        assert_eq!(current_shared_account(&s, at(0)).unwrap().id, "live");
        let all_dead = store(vec![oauth("x", at(-10))]);
        assert_eq!(
            current_shared_account(&all_dead, at(0)).map(|a| a.id.as_str()),
            None
        );
        let mut pinned_dead = store(vec![oauth("x", at(-10))]);
        pinned_dead.current = Some("x".into());
        assert_eq!(current_shared_account(&pinned_dead, at(0)).unwrap().id, "x");
    }

    #[test]
    fn adoption_requires_a_rotated_live_peer_credential() {
        let s = store(vec![oauth("peer", at(3600))]);
        let peer_refresh = s.accounts[0].oauth().unwrap().refresh.clone();
        let mine = RefreshToken::new("sk-ant-ort01-mine-aaaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(adoptable_shared_credential(&s, &mine, at(0)).is_some());
        // Unrotated match: no peer refreshed, this caller must.
        assert!(adoptable_shared_credential(&s, &peer_refresh, at(0)).is_none());
        // Expiring within the skew is not worth adopting.
        assert!(adoptable_shared_credential(&s, &mine, at(3600 - 30)).is_none());
    }
}
