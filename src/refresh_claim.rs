//! Cross-process refresh serialization and dead-token records on the shared
//! store, plus quota attribution.
//!
//! Anthropic revokes the whole token family when a refresh token is
//! presented twice, so two processes must never POST the same one. Claude
//! Code guards this with a lock it re-reads under before deciding to refresh
//! at all; the equivalent here is a short lease recorded *in the store row*
//! so it works across processes without holding a file lock over a network
//! call. The lease id is random — PIDs are recycled — and the holder PID is
//! recorded purely as diagnostics.
//!
//! Every method here has an in-memory form on [`AccountStore`] (pure, for
//! tests and for callers already inside [`AccountStore::mutate`]) and a
//! path-level form that runs it under the store's inter-process lock.

use std::path::Path;

use chrono::{DateTime, Duration, Utc};

use crate::account::{Account, RefreshLease};
use crate::error::Result;
use crate::store::AccountStore;
use crate::token::{Credential, OAuthTokens, RefreshToken, token_fingerprint};

/// How long a refresh claim stays valid before another process may take it.
pub const REFRESH_LEASE_TTL_SECS: i64 = 30;

/// Outcome of trying to claim the right to refresh an account.
#[derive(Debug, Clone)]
pub enum RefreshClaim {
    /// This caller now holds the claim and may present the token.
    Claimed {
        /// The lease id to release or commit with.
        lease_id: String,
    },
    /// Another process already rotated the token; use `tokens` as-is and do
    /// not present the one you were handed (it is spent).
    AlreadyRefreshed(OAuthTokens),
    /// Another process holds a live claim; wait and re-read.
    Held {
        /// When the claim lapses.
        until: DateTime<Utc>,
        /// The holder's PID, when it recorded one.
        holder_pid: Option<u32>,
    },
    /// Anthropic already rejected this token; presenting it again is pointless.
    DeadToken,
    /// No OAuth account with that id.
    UnknownAccount,
}

fn oauth_mut(account: &mut Account) -> Option<&mut OAuthTokens> {
    match &mut account.credential {
        Credential::Oauth(tokens) => Some(tokens),
        Credential::ApiKey { .. } => None,
    }
}

impl AccountStore {
    /// Claim the exclusive right to refresh `account_id` with `refresh_token`
    /// (in-memory form; persist with [`AccountStore::mutate`]).
    pub fn claim_refresh(
        &mut self,
        account_id: &str,
        refresh_token: &RefreshToken,
        now: DateTime<Utc>,
        ttl: Duration,
        holder_pid: Option<u32>,
    ) -> RefreshClaim {
        let Some(account) = self.accounts.iter_mut().find(|a| a.id == account_id) else {
            return RefreshClaim::UnknownAccount;
        };
        let Credential::Oauth(tokens) = &account.credential else {
            return RefreshClaim::UnknownAccount;
        };
        // Someone already rotated it while we were getting here: the token we
        // were handed is spent, and presenting it would revoke the family.
        if &tokens.refresh != refresh_token {
            return RefreshClaim::AlreadyRefreshed(tokens.clone());
        }
        let fingerprint = token_fingerprint(refresh_token.expose());
        // Already rejected once. The family does not come back, so
        // short-circuit rather than spend another round trip to be told so.
        if account.dead_refresh_fingerprint.as_deref() == Some(fingerprint.as_str()) {
            return RefreshClaim::DeadToken;
        }
        if let Some(lease) = &account.refresh_lease
            && lease.until > now
        {
            return RefreshClaim::Held {
                until: lease.until,
                holder_pid: lease.holder_pid,
            };
        }
        let lease_id = uuid::Uuid::new_v4().to_string();
        account.refresh_lease = Some(RefreshLease {
            id: lease_id.clone(),
            until: now + ttl,
            token_fingerprint: fingerprint,
            holder_pid,
            claimed_at: Some(now),
        });
        RefreshClaim::Claimed { lease_id }
    }

    /// [`AccountStore::claim_refresh`] under the store lock at `path`, with
    /// the default TTL and this process's PID.
    pub fn claim_refresh_at(
        path: &Path,
        account_id: &str,
        refresh_token: &RefreshToken,
        now: DateTime<Utc>,
    ) -> Result<RefreshClaim> {
        Self::mutate(path, |store| {
            Ok(store.claim_refresh(
                account_id,
                refresh_token,
                now,
                Duration::seconds(REFRESH_LEASE_TTL_SECS),
                Some(std::process::id()),
            ))
        })
    }

    /// Record that Anthropic rejected `refresh_token` with `invalid_grant`.
    /// Only the token the account still holds is marked, so a later rotation
    /// never inherits a predecessor's verdict. Clears any claim the dead
    /// attempt was holding. Returns whether anything changed.
    pub fn mark_refresh_token_dead(
        &mut self,
        account_id: &str,
        refresh_token: &RefreshToken,
    ) -> bool {
        let Some(account) = self.accounts.iter_mut().find(|a| a.id == account_id) else {
            return false;
        };
        let Credential::Oauth(tokens) = &account.credential else {
            return false;
        };
        if &tokens.refresh != refresh_token {
            return false;
        }
        account.dead_refresh_fingerprint = Some(token_fingerprint(refresh_token.expose()));
        account.last_error = Some("invalid_grant".into());
        account.refresh_lease = None;
        true
    }

    /// [`AccountStore::mark_refresh_token_dead`] under the store lock.
    pub fn mark_refresh_token_dead_at(
        path: &Path,
        account_id: &str,
        refresh_token: &RefreshToken,
    ) -> Result<bool> {
        Self::mutate(path, |store| {
            Ok(store.mark_refresh_token_dead(account_id, refresh_token))
        })
    }

    /// Release a claim without altering the credential. A stale or foreign
    /// lease id cannot release the live holder.
    pub fn release_refresh_claim(&mut self, account_id: &str, lease_id: &str) -> bool {
        let Some(account) = self.accounts.iter_mut().find(|a| a.id == account_id) else {
            return false;
        };
        if account.refresh_lease.as_ref().map(|l| l.id.as_str()) != Some(lease_id) {
            return false;
        }
        account.refresh_lease = None;
        true
    }

    /// [`AccountStore::release_refresh_claim`] under the store lock.
    pub fn release_refresh_claim_at(path: &Path, account_id: &str, lease_id: &str) -> Result<bool> {
        Self::mutate(path, |store| {
            Ok(store.release_refresh_claim(account_id, lease_id))
        })
    }

    /// Commit a refresh result: compare-and-swap on the refresh token that was
    /// presented (`expected_refresh`), optionally fenced on `lease_id`, then
    /// install `refreshed`, clear the dead-token record, last error and
    /// lease, and pin the account as `current`. Returns `false` (leaving the
    /// newer stored session untouched) when another process already rotated
    /// the token or the lease was taken over.
    pub fn commit_refresh(
        &mut self,
        account_id: &str,
        expected_refresh: &RefreshToken,
        lease_id: Option<&str>,
        refreshed: OAuthTokens,
    ) -> bool {
        let Some(account) = self.accounts.iter_mut().find(|a| a.id == account_id) else {
            return false;
        };
        let Some(current) = oauth_mut(account) else {
            return false;
        };
        if &current.refresh != expected_refresh {
            return false;
        }
        if let Some(lease_id) = lease_id
            && account.refresh_lease.as_ref().map(|l| l.id.as_str()) != Some(lease_id)
        {
            return false;
        }
        let mut next = refreshed;
        let Some(current) = oauth_mut(account) else {
            return false;
        };
        if next.refresh_expires_at.is_none() {
            next.refresh_expires_at = current.refresh_expires_at;
        }
        if next.account.is_none() {
            next.account = current.account.clone();
        }
        if next.organization.is_none() {
            next.organization = current.organization.clone();
        }
        if next.scopes.is_empty() {
            next.scopes = current.scopes.clone();
        }
        if account.replace_oauth_tokens(next).is_err() {
            return false;
        }
        account.dead_refresh_fingerprint = None;
        account.last_error = None;
        account.refresh_lease = None;
        self.current = Some(account_id.to_owned());
        true
    }

    /// [`AccountStore::commit_refresh`] under the store lock.
    pub fn commit_refresh_at(
        path: &Path,
        account_id: &str,
        expected_refresh: &RefreshToken,
        lease_id: Option<&str>,
        refreshed: OAuthTokens,
    ) -> Result<bool> {
        Self::mutate(path, |store| {
            Ok(store.commit_refresh(account_id, expected_refresh, lease_id, refreshed))
        })
    }

    /// The OAuth account holding `refresh_token`.
    pub fn find_by_refresh_token(&self, refresh_token: &RefreshToken) -> Option<&Account> {
        self.accounts
            .iter()
            .find(|a| a.oauth().is_some_and(|t| &t.refresh == refresh_token))
    }

    /// The OAuth account whose current access token is `access_token`.
    pub fn find_by_access_token(&self, access_token: &str) -> Option<&Account> {
        self.accounts
            .iter()
            .find(|a| a.oauth().is_some_and(|t| t.access.expose() == access_token))
    }

    /// Record a quota reading against `account_id`. Returns `false` when the
    /// account is unknown or the reading carries no percentage. An exhausted
    /// `current` pin is cleared: leaving it set makes every caller start on an
    /// account that can only fail.
    pub fn record_quota(
        &mut self,
        account_id: &str,
        five_hour_percent: Option<f64>,
        seven_day_percent: Option<f64>,
        checked_at: DateTime<Utc>,
    ) -> bool {
        let five = five_hour_percent.filter(|p| p.is_finite());
        let seven = seven_day_percent.filter(|p| p.is_finite());
        if five.is_none() && seven.is_none() {
            return false;
        }
        let Some(account) = self.accounts.iter_mut().find(|a| a.id == account_id) else {
            return false;
        };
        account.quota = Some(crate::account::QuotaObservation {
            five_hour_percent: five,
            seven_day_percent: seven,
            checked_at: Some(checked_at),
        });
        if self.current.as_deref() == Some(account_id) && !account.is_available(checked_at) {
            self.current = None;
        }
        true
    }

    /// Attribute a quota reading to the account whose access token it was
    /// read with. A reading with no matching account is dropped rather than
    /// stamped onto whichever account selection currently favours. Returns
    /// the account id the reading landed on.
    pub fn record_quota_for_access_token(
        &mut self,
        access_token: &str,
        five_hour_percent: Option<f64>,
        seven_day_percent: Option<f64>,
        checked_at: DateTime<Utc>,
    ) -> Option<String> {
        let id = self.find_by_access_token(access_token)?.id.clone();
        self.record_quota(&id, five_hour_percent, seven_day_percent, checked_at)
            .then_some(id)
    }

    /// The store id a new login should take. `preferred` is the label, else
    /// the profile email, else the grant email. An email is not unique on its
    /// own — one person can hold a grant in several organizations — so when
    /// the plain id is already held by a *different* organization the new
    /// row is qualified as `<email> (<organization name or uuid prefix>)`
    /// instead of overwriting it. An explicit label is never qualified.
    pub fn login_account_id(
        &self,
        preferred: Option<&str>,
        explicit_label: bool,
        organization_uuid: Option<&str>,
        organization_name: Option<&str>,
    ) -> Option<String> {
        let preferred = preferred.map(str::trim).filter(|p| !p.is_empty())?;
        let collides = !explicit_label
            && self.accounts.iter().any(|candidate| {
                candidate.id == preferred
                    && candidate.oauth().is_some_and(|t| {
                        t.organization.as_ref().map(|o| o.uuid.as_str()) != organization_uuid
                    })
            });
        let suffix = organization_name
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .map(str::to_owned)
            .or_else(|| organization_uuid.map(|u| u.chars().take(8).collect()));
        match (collides, suffix) {
            (true, Some(suffix)) => Some(format!("{preferred} ({suffix})")),
            _ => Some(preferred.to_owned()),
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::token::{AccessToken, TokenOrganization};

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000 + secs, 0).unwrap()
    }

    fn tokens(refresh: &str, access: &str) -> OAuthTokens {
        OAuthTokens {
            access: AccessToken::new(access),
            refresh: RefreshToken::new(refresh),
            expires_at: at(3600),
            refresh_expires_at: Some(at(86_400 * 30)),
            scopes: vec!["user:inference".into()],
            account: None,
            organization: None,
        }
    }

    fn oauth_account(id: &str, refresh: &str) -> Account {
        Account::new(
            id,
            Credential::Oauth(tokens(
                refresh,
                &format!("sk-ant-oat01-{id}-access-aaaaaaaaaaaaaa"),
            )),
        )
    }

    fn store(ids: &[&str]) -> AccountStore {
        AccountStore {
            version: 1,
            accounts: ids
                .iter()
                .map(|id| oauth_account(id, &format!("sk-ant-ort01-{id}-refresh-aaaaaaaaaaaaaa")))
                .collect(),
            current: None,
            migrated_from: Vec::new(),
        }
    }

    fn refresh_of(store: &AccountStore, id: &str) -> RefreshToken {
        store.get(id).unwrap().oauth().unwrap().refresh.clone()
    }

    fn tmp_store_path(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "anthropic-claim-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("accounts.json")
    }

    #[test]
    fn first_caller_claims_and_second_is_told_to_wait() {
        let mut s = store(&["a"]);
        let refresh = refresh_of(&s, "a");
        let RefreshClaim::Claimed { lease_id } =
            s.claim_refresh("a", &refresh, at(0), Duration::seconds(30), Some(4242))
        else {
            panic!("first claim must win");
        };
        match s.claim_refresh("a", &refresh, at(1), Duration::seconds(30), Some(4243)) {
            RefreshClaim::Held { until, holder_pid } => {
                assert_eq!(until, at(30));
                assert_eq!(holder_pid, Some(4242));
            }
            other => panic!("expected held, got {other:?}"),
        }
        // The lease records a fingerprint, never the token.
        let lease = s.get("a").unwrap().refresh_lease.clone().unwrap();
        assert_eq!(lease.id, lease_id);
        assert_eq!(lease.token_fingerprint, token_fingerprint(refresh.expose()));
        assert!(
            !serde_json::to_string(&lease)
                .unwrap()
                .contains(refresh.expose())
        );
        // Claims on different accounts do not block each other.
        let mut two = store(&["a", "b"]);
        let ra = refresh_of(&two, "a");
        let rb = refresh_of(&two, "b");
        assert!(matches!(
            two.claim_refresh("a", &ra, at(0), Duration::seconds(30), None),
            RefreshClaim::Claimed { .. }
        ));
        assert!(matches!(
            two.claim_refresh("b", &rb, at(0), Duration::seconds(30), None),
            RefreshClaim::Claimed { .. }
        ));
    }

    #[test]
    fn spent_token_is_handed_the_winner_and_expired_claim_can_be_taken_over() {
        let mut s = store(&["a"]);
        let old = refresh_of(&s, "a");
        assert!(matches!(
            s.claim_refresh("a", &old, at(0), Duration::seconds(30), None),
            RefreshClaim::Claimed { .. }
        ));
        // A crashed holder does not wedge the account forever.
        assert!(matches!(
            s.claim_refresh("a", &old, at(31), Duration::seconds(30), None),
            RefreshClaim::Claimed { .. }
        ));
        let lease_id = s.get("a").unwrap().refresh_lease.clone().unwrap().id;
        let rotated = tokens(
            "sk-ant-ort01-rotated-refresh-aaaaaaaaaaaaaa",
            "sk-ant-oat01-rotated-access-aaaaaaaaaaaaaa",
        );
        assert!(s.commit_refresh("a", &old, Some(&lease_id), rotated.clone()));
        assert_eq!(s.current.as_deref(), Some("a"));
        assert!(s.get("a").unwrap().refresh_lease.is_none());
        match s.claim_refresh("a", &old, at(40), Duration::seconds(30), None) {
            RefreshClaim::AlreadyRefreshed(winner) => assert_eq!(winner.refresh, rotated.refresh),
            other => panic!("expected the winner, got {other:?}"),
        }
        assert!(matches!(
            s.claim_refresh("zzz", &old, at(0), Duration::seconds(30), None),
            RefreshClaim::UnknownAccount
        ));
    }

    #[test]
    fn release_requires_the_live_lease_id() {
        let mut s = store(&["a"]);
        let refresh = refresh_of(&s, "a");
        let RefreshClaim::Claimed { lease_id } =
            s.claim_refresh("a", &refresh, at(0), Duration::seconds(30), None)
        else {
            panic!()
        };
        assert!(!s.release_refresh_claim("a", "stale-lease"));
        assert!(matches!(
            s.claim_refresh("a", &refresh, at(1), Duration::seconds(30), None),
            RefreshClaim::Held { .. }
        ));
        assert!(s.release_refresh_claim("a", &lease_id));
        assert!(matches!(
            s.claim_refresh("a", &refresh, at(2), Duration::seconds(30), None),
            RefreshClaim::Claimed { .. }
        ));
    }

    #[test]
    fn commit_is_fenced_on_the_lease_and_the_presented_token() {
        let mut s = store(&["a"]);
        let old = refresh_of(&s, "a");
        let RefreshClaim::Claimed { lease_id } =
            s.claim_refresh("a", &old, at(0), Duration::seconds(30), None)
        else {
            panic!()
        };
        let rotated = tokens(
            "sk-ant-ort01-rotated-refresh-aaaaaaaaaaaaaa",
            "sk-ant-oat01-rotated-access-aaaaaaaaaaaaaa",
        );
        // A stale holder cannot clobber a newer rotation.
        assert!(!s.commit_refresh("a", &old, Some("someone-else"), rotated.clone()));
        assert!(s.commit_refresh("a", &old, Some(&lease_id), rotated.clone()));
        let newer = tokens(
            "sk-ant-ort01-newer-refresh-aaaaaaaaaaaaaaaa",
            "sk-ant-oat01-newer-access-aaaaaaaaaaaaaaaa",
        );
        assert!(
            !s.commit_refresh("a", &old, None, newer),
            "the presented token is no longer current"
        );
        // Metadata carried forward when the response omits it.
        assert_eq!(
            s.get("a").unwrap().oauth().unwrap().refresh_expires_at,
            Some(at(86_400 * 30))
        );
    }

    #[test]
    fn dead_token_short_circuits_and_is_scoped_to_the_token() {
        let mut s = store(&["a"]);
        let dead = refresh_of(&s, "a");
        assert!(s.mark_refresh_token_dead("a", &dead));
        assert!(s.get("a").unwrap().refresh_token_is_dead());
        assert_eq!(
            s.get("a").unwrap().last_error.as_deref(),
            Some("invalid_grant")
        );
        assert!(matches!(
            s.claim_refresh("a", &dead, at(0), Duration::seconds(30), None),
            RefreshClaim::DeadToken
        ));
        // The verdict survives a reload.
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains(&format!(
            "\"dead_refresh_fingerprint\":\"{}\"",
            token_fingerprint(dead.expose())
        )));
        let back: AccountStore = serde_json::from_str(&json).unwrap();
        assert!(back.get("a").unwrap().refresh_token_is_dead());
        // Marking only applies to the token the account still holds.
        let other = RefreshToken::new("sk-ant-ort01-other-refresh-aaaaaaaaaaaaaaaa");
        assert!(!s.mark_refresh_token_dead("a", &other));
        // A later rotation does not inherit the predecessor's verdict.
        let rotated = tokens(
            "sk-ant-ort01-rotated-refresh-aaaaaaaaaaaaaa",
            "sk-ant-oat01-rotated-access-aaaaaaaaaaaaaa",
        );
        assert!(s.commit_refresh("a", &dead, None, rotated.clone()));
        assert!(!s.get("a").unwrap().refresh_token_is_dead());
        assert!(matches!(
            s.claim_refresh("a", &rotated.refresh, at(0), Duration::seconds(30), None),
            RefreshClaim::Claimed { .. }
        ));
    }

    #[test]
    fn marking_dead_clears_the_claim_it_was_holding() {
        let mut s = store(&["a"]);
        let dead = refresh_of(&s, "a");
        assert!(matches!(
            s.claim_refresh("a", &dead, at(0), Duration::seconds(30), None),
            RefreshClaim::Claimed { .. }
        ));
        assert!(s.mark_refresh_token_dead("a", &dead));
        assert!(s.get("a").unwrap().refresh_lease.is_none());
    }

    #[test]
    fn quota_lands_only_on_the_account_it_was_taken_from() {
        let mut s = store(&["a", "b"]);
        s.current = Some("a".into());
        let access_a = s
            .get("a")
            .unwrap()
            .oauth()
            .unwrap()
            .access
            .expose()
            .to_owned();
        assert_eq!(
            s.record_quota_for_access_token(&access_a, Some(0.0), Some(100.0), at(0))
                .as_deref(),
            Some("a")
        );
        assert_eq!(
            s.record_quota_for_access_token(
                "sk-ant-oat01-unknown",
                Some(100.0),
                Some(100.0),
                at(0)
            ),
            None
        );
        assert!(
            s.get("b").unwrap().quota.is_none(),
            "a neighbour must never be stamped"
        );
        // An exhausted pin is cleared; the neighbour stays selectable.
        assert_eq!(s.current, None);
        assert!(!s.get("a").unwrap().is_available(at(1)));
        assert!(s.get("b").unwrap().is_available(at(1)));
        assert_eq!(s.pick(at(1)).unwrap().id, "b");
        // Stale readings fail open.
        assert!(s.get("a").unwrap().is_available(at(31 * 60)));
        assert!(!s.record_quota("a", None, None, at(0)));
        assert!(!s.record_quota("nope", Some(1.0), None, at(0)));
    }

    #[test]
    fn claim_survives_a_write_so_another_process_sees_it() {
        let path = tmp_store_path("claim");
        store(&["a"]).save(&path).unwrap();
        let refresh = refresh_of(&AccountStore::load(&path).unwrap(), "a");
        let RefreshClaim::Claimed { lease_id } =
            AccountStore::claim_refresh_at(&path, "a", &refresh, Utc::now()).unwrap()
        else {
            panic!()
        };
        assert!(matches!(
            AccountStore::claim_refresh_at(&path, "a", &refresh, Utc::now()).unwrap(),
            RefreshClaim::Held { .. }
        ));
        assert!(AccountStore::release_refresh_claim_at(&path, "a", &lease_id).unwrap());
        let rotated = tokens(
            "sk-ant-ort01-rotated-refresh-aaaaaaaaaaaaaa",
            "sk-ant-oat01-rotated-access-aaaaaaaaaaaaaa",
        );
        assert!(
            AccountStore::commit_refresh_at(&path, "a", &refresh, None, rotated.clone()).unwrap()
        );
        assert!(AccountStore::mark_refresh_token_dead_at(&path, "a", &rotated.refresh).unwrap());
        assert!(
            AccountStore::load(&path)
                .unwrap()
                .get("a")
                .unwrap()
                .refresh_token_is_dead()
        );
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn login_id_is_qualified_only_on_a_cross_organization_collision() {
        let mut s = store(&["me@example.com"]);
        if let Credential::Oauth(t) = &mut s.accounts[0].credential {
            t.organization = Some(TokenOrganization {
                uuid: "org-a".into(),
            });
        }
        assert_eq!(
            s.login_account_id(Some("me@example.com"), false, Some("org-a"), None)
                .as_deref(),
            Some("me@example.com")
        );
        assert_eq!(
            s.login_account_id(
                Some("me@example.com"),
                false,
                Some("org-b-uuid-long"),
                Some("Acme")
            )
            .as_deref(),
            Some("me@example.com (Acme)")
        );
        assert_eq!(
            s.login_account_id(Some("me@example.com"), false, Some("org-b-uuid-long"), None)
                .as_deref(),
            Some("me@example.com (org-b-uu)")
        );
        // An explicit label is never qualified; a missing preferred id yields None.
        assert_eq!(
            s.login_account_id(Some("me@example.com"), true, Some("org-b"), Some("Acme"))
                .as_deref(),
            Some("me@example.com")
        );
        assert_eq!(s.login_account_id(None, false, Some("org-b"), None), None);
        assert_eq!(
            s.login_account_id(Some("new@example.com"), false, Some("org-b"), Some("Acme"))
                .as_deref(),
            Some("new@example.com")
        );
    }
}
