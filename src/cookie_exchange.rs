//! Exchanges an approved cookie-flow token for a session without losing the approval to a pkarr blip.
//!
//! `PubkyCookieAuthFlow::await_approval` reads the token off the relay — ACKing it, so the relay
//! forgets it — and then resolves the homeserver and POSTs the token in one go. When both pkarr
//! relays time out at that moment, pubky's transport resolver finds no endpoint, falls back to
//! sending the request to the `_pubky.<key>` name itself, and the approval is gone: that name means
//! nothing to DNS or to a proxy (loopky#389). So the two halves are split here, as the SDK
//! documents for `CookieCredential::from_auth_token`: the token is held, the homeserver is resolved
//! with retries first, and only then is the token spent. The token stays valid for 180s after Ring
//! signs it, which is the budget all of this has to fit inside.

use std::time::{Duration, Instant};

use pubky::errors::RequestError;
use pubky::pkarr::ResolvePolicy;
#[allow(deprecated)]
use pubky::{AuthToken, CookieCredential, Error, PubkyHttpClient, PublicKey};

use crate::full_error_chain;

/// Every error that means "the homeserver's address could not be found" starts with this, and
/// Loopky classifies on it. Changing the wording is a breaking change for the apps and the CLI.
pub(crate) const UNRESOLVED: &str = "Homeserver could not be resolved";

pub(crate) const RESOLVE_ATTEMPTS: u32 = 4;
/// Well inside the token's 180s window, leaving room for the time Ring took to deliver it and for
/// the exchange itself.
pub(crate) const RESOLVE_BUDGET: Duration = Duration::from_secs(90);
pub(crate) const EXCHANGE_ATTEMPTS: u32 = 3;

/// The name pubky's transport resolver will look up for this exchange: the homeserver itself when
/// the flow names one (signup), otherwise the user's `_pubky` record.
pub(crate) fn exchange_qname(user: &PublicKey, homeserver: Option<&PublicKey>) -> String {
    match homeserver {
        Some(homeserver) => homeserver.z32(),
        None => format!("_pubky.{}", user.z32()),
    }
}

/// 1s, 2s, 4s…, or `None` once the attempts or the budget are spent.
pub(crate) fn retry_delay(attempt: u32, attempts: u32, elapsed: Duration) -> Option<Duration> {
    if attempt >= attempts {
        return None;
    }
    let delay = Duration::from_secs(1 << (attempt - 1).min(3));
    (elapsed + delay < RESOLVE_BUDGET).then_some(delay)
}

/// Did the exchange fail before the request could have reached the homeserver?
///
/// Only then is the token certainly unspent. A timeout or a dropped response may come after the
/// homeserver consumed it, and a retry would turn a network failure into a confusing 401.
pub(crate) fn never_sent(error: &Error) -> bool {
    matches!(error, Error::Request(RequestError::Transport(transport)) if transport.is_connect())
}

/// Resolve `qname` to at least one HTTPS endpoint, filling pkarr's cache so the exchange's own
/// lookup is answered from it.
async fn resolve_endpoint(client: &PubkyHttpClient, qname: &str) -> Result<(), String> {
    let pkarr = client.pkarr();
    let key = qname.trim_start_matches("_pubky.");
    let key = PublicKey::try_from_z32(key).map_err(|e| format!("invalid key {key}: {e}"))?;
    // Resolved separately first only for its error: the endpoint stream reports nothing but
    // "no endpoint", and "both relays timed out" is what tells a caller this is worth retrying.
    pkarr
        .resolve(key.as_inner(), ResolvePolicy::CacheFirst)
        .await
        .map_err(|e| full_error_chain(&e))?;
    pkarr
        .resolve_https_endpoint(qname)
        .await
        .map(|_| ())
        .map_err(|_| format!("no HTTPS endpoint resolved for {qname}"))
}

async fn resolve_with_retries(client: &PubkyHttpClient, qname: &str) -> Result<(), String> {
    let started = Instant::now();
    let mut attempt = 1;
    loop {
        let error = match resolve_endpoint(client, qname).await {
            Ok(()) => return Ok(()),
            Err(error) => error,
        };
        let Some(delay) = retry_delay(attempt, RESOLVE_ATTEMPTS, started.elapsed()) else {
            return Err(format!(
                "{UNRESOLVED}: pkarr found no endpoint for {qname} after {attempt} attempts over {}s \
                 ({error}). Ring's approval was received but expires unused; start a new sign-in \
                 and approve it again.",
                started.elapsed().as_secs()
            ));
        };
        tracing::warn!(
            "Resolving {qname} before the session exchange failed ({error}); retrying in {delay:?}"
        );
        tokio::time::sleep(delay).await;
        attempt += 1;
    }
}

/// Resolve the homeserver, then spend `token` on a session, retrying the parts that cannot have
/// consumed it.
#[allow(deprecated)]
pub(crate) async fn exchange(
    client: &PubkyHttpClient,
    token: &AuthToken,
    homeserver: Option<PublicKey>,
) -> Result<CookieCredential, String> {
    let qname = exchange_qname(token.public_key(), homeserver.as_ref());
    resolve_with_retries(client, &qname).await?;

    let started = Instant::now();
    let mut attempt = 1;
    loop {
        let error = match CookieCredential::from_auth_token(token, client, homeserver.clone()).await
        {
            Ok(credential) => return Ok(credential),
            Err(error) => error,
        };
        let delay = never_sent(&error)
            .then(|| retry_delay(attempt, EXCHANGE_ATTEMPTS, started.elapsed()))
            .flatten();
        let Some(delay) = delay else {
            return Err(full_error_chain(&error));
        };
        tracing::warn!(
            "Session exchange could not connect ({}); retrying in {delay:?}",
            full_error_chain(&error)
        );
        tokio::time::sleep(delay).await;
        attempt += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubky::Keypair;

    #[test]
    fn signin_resolves_the_users_record_and_signup_the_named_homeserver() {
        let user = Keypair::random().public_key();
        let homeserver = Keypair::random().public_key();

        assert_eq!(
            exchange_qname(&user, None),
            format!("_pubky.{}", user.z32())
        );
        assert_eq!(exchange_qname(&user, Some(&homeserver)), homeserver.z32());
    }

    #[test]
    fn retries_back_off_and_stop_at_the_attempt_limit() {
        let start = Duration::ZERO;
        assert_eq!(retry_delay(1, 4, start), Some(Duration::from_secs(1)));
        assert_eq!(retry_delay(2, 4, start), Some(Duration::from_secs(2)));
        assert_eq!(retry_delay(3, 4, start), Some(Duration::from_secs(4)));
        assert_eq!(retry_delay(4, 4, start), None);
    }

    #[test]
    fn retries_stop_before_the_budget_runs_past_the_tokens_window() {
        assert_eq!(
            retry_delay(1, 4, RESOLVE_BUDGET - Duration::from_millis(500)),
            None
        );
        assert!(RESOLVE_BUDGET < Duration::from_secs(180));
    }

    #[tokio::test]
    async fn only_a_refused_connection_leaves_the_token_unspent() {
        // Nothing listens on port 1, so the request fails at connect time.
        let refused = reqwest::Client::new()
            .get("http://127.0.0.1:1/session")
            .send()
            .await
            .expect_err("connect should fail");
        assert!(never_sent(&Error::Request(RequestError::Transport(
            refused
        ))));

        let answered = Error::Request(RequestError::Server {
            status: reqwest::StatusCode::UNAUTHORIZED,
            message: "token already used".into(),
        });
        assert!(!never_sent(&answered));
    }

    /// Live: publishes a throwaway `_pubky` record at the production homeserver, then spends a
    /// token that key signed. The homeserver has no account for it, so the exchange must come back
    /// as the homeserver's own answer, reached through its ICANN name. Run with `--ignored`.
    #[tokio::test]
    #[ignore = "needs the network: pkarr relays and homeserver.pubky.app"]
    #[allow(deprecated)]
    async fn live_a_resolved_exchange_reaches_the_real_homeserver() {
        const PRODUCTION: &str = "8um71us3fyw6h8wbcxb5ar3rwusy1a6u49956ikzojg3gcwd1dty";
        let client = crate::get_pubky_client();
        let user = Keypair::random();
        client
            .signer(user.clone())
            .pkdns()
            .publish_homeserver_force(Some(&PublicKey::try_from(PRODUCTION).unwrap()))
            .await
            .expect("publish");

        let token = AuthToken::sign(&user, pubky::Capabilities::default());
        let error = exchange(client.client(), &token, None)
            .await
            .expect_err("no account");

        assert!(!error.contains(UNRESOLVED), "{error}");
        assert!(
            !error.contains("_pubky."),
            "went to the pseudo-host: {error}"
        );
        assert!(error.contains("Server responded with an error"), "{error}");
    }

    /// Live: a key that never published a record fails as unresolved, without a request to its
    /// `_pubky` name.
    #[tokio::test]
    #[ignore = "needs the network: pkarr relays"]
    #[allow(deprecated)]
    async fn live_an_unpublished_key_is_reported_unresolved() {
        let client = crate::get_pubky_client();
        let token = AuthToken::sign(&Keypair::random(), pubky::Capabilities::default());

        let error = exchange(client.client(), &token, None)
            .await
            .expect_err("unresolvable");

        assert!(error.starts_with(UNRESOLVED), "{error}");
        assert!(error.contains("start a new sign-in"), "{error}");
    }
}
