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

use tokio::time::timeout;

use pubky::errors::RequestError;
use pubky::pkarr::errors::ResolveError;
use pubky::pkarr::ResolvePolicy;
#[allow(deprecated)]
use pubky::{AuthToken, CookieCredential, Error, PubkyHttpClient, PublicKey};

use crate::full_error_chain;

/// Every error that means "the homeserver's address could not be found" starts with this, and
/// Loopky classifies on it. Changing the wording is a breaking change for the apps and the CLI.
pub(crate) const UNRESOLVED: &str = "Homeserver could not be resolved";
/// pkarr answered, and the key has no record: no retry will help. Worded like `get_homeserver`'s
/// `Ok(None)`, which Loopky already reads as "this key has no account".
pub(crate) const NO_RECORD: &str = "No homeserver found for";

pub(crate) const RESOLVE_ATTEMPTS: u32 = 4;
pub(crate) const EXCHANGE_ATTEMPTS: u32 = 3;
/// From the token's arrival to the last possible exchange, attempts included. Ring signs the token
/// before delivering it and the homeserver honours it for 180s, so this leaves a minute for the
/// relay leg — and nothing here can run past it, because an attempt only starts if its own bound
/// still fits.
pub(crate) const BUDGET: Duration = Duration::from_secs(120);
/// Two network lookups at the relays-only 10s timeout, and a little over.
pub(crate) const RESOLVE_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(25);
/// The SDK's client sets no connect or request timeout, so a black-holed connection would
/// otherwise hold the token until the OS gives up.
pub(crate) const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

/// The name pubky's transport resolver will look up for this exchange: the homeserver itself when
/// the flow names one (signup), otherwise the user's `_pubky` record.
pub(crate) fn exchange_qname(user: &PublicKey, homeserver: Option<&PublicKey>) -> String {
    match homeserver {
        Some(homeserver) => homeserver.z32(),
        None => format!("_pubky.{}", user.z32()),
    }
}

/// 1s, 2s, 4s…, or `None` once the attempts are spent or the next attempt — its delay plus
/// `reserve`, the longest everything after the sleep can take — would overrun [`BUDGET`].
pub(crate) fn retry_delay(
    attempt: u32,
    attempts: u32,
    elapsed: Duration,
    reserve: Duration,
) -> Option<Duration> {
    if attempt >= attempts {
        return None;
    }
    let delay = Duration::from_secs(1 << (attempt - 1).min(3));
    (elapsed + delay + reserve <= BUDGET).then_some(delay)
}

/// Did the exchange fail before the request could have reached the homeserver?
///
/// Only then is the token certainly unspent. A timeout or a dropped response may come after the
/// homeserver consumed it, and a retry would turn a network failure into a confusing 401.
pub(crate) fn never_sent(error: &Error) -> bool {
    matches!(error, Error::Request(RequestError::Transport(transport)) if transport.is_connect())
}

enum Unresolved {
    /// pkarr answered that the key has published nothing.
    NoRecord,
    Failed(String),
}

/// Resolve `qname` to at least one HTTPS endpoint, filling pkarr's cache so the exchange's own
/// lookup is answered from it.
async fn resolve_endpoint(client: &PubkyHttpClient, qname: &str) -> Result<(), Unresolved> {
    let pkarr = client.pkarr();
    let key = qname.trim_start_matches("_pubky.");
    let key = PublicKey::try_from_z32(key)
        .map_err(|e| Unresolved::Failed(format!("invalid key {key}: {e}")))?;
    // Resolved separately first only for its error: the endpoint stream reports nothing but
    // "no endpoint", and "both relays timed out" is what tells a caller this is worth retrying.
    match pkarr
        .resolve(key.as_inner(), ResolvePolicy::CacheFirst)
        .await
    {
        Ok(_) => {}
        Err(ResolveError::NotFound) => return Err(Unresolved::NoRecord),
        Err(error) => return Err(Unresolved::Failed(full_error_chain(&error))),
    }
    pkarr
        .resolve_https_endpoint(qname)
        .await
        .map(|_| ())
        .map_err(|_| Unresolved::Failed(format!("no HTTPS endpoint resolved for {qname}")))
}

async fn resolve_with_retries(
    client: &PubkyHttpClient,
    qname: &str,
    started: Instant,
) -> Result<(), String> {
    let mut attempt = 1;
    loop {
        let error = match timeout(RESOLVE_ATTEMPT_TIMEOUT, resolve_endpoint(client, qname)).await {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(error)) => error,
            Err(_) => Unresolved::Failed(format!("lookup took over {RESOLVE_ATTEMPT_TIMEOUT:?}")),
        };
        let reserve = RESOLVE_ATTEMPT_TIMEOUT + EXCHANGE_TIMEOUT;
        let Some(delay) = retry_delay(attempt, RESOLVE_ATTEMPTS, started.elapsed(), reserve) else {
            let spent = started.elapsed().as_secs();
            return Err(match error {
                Unresolved::NoRecord => format!(
                    "{NO_RECORD} {qname}: pkarr has no record for it after {attempt} attempts over \
                     {spent}s. Ring's approval was received but expires unused."
                ),
                Unresolved::Failed(error) => format!(
                    "{UNRESOLVED}: pkarr found no endpoint for {qname} after {attempt} attempts \
                     over {spent}s ({error}). Ring's approval was received but expires unused; \
                     start a new sign-in and approve it again."
                ),
            });
        };
        let detail = match &error {
            Unresolved::NoRecord => "no record",
            Unresolved::Failed(error) => error,
        };
        tracing::warn!(
            "Resolving {qname} before the session exchange failed ({detail}); retrying in {delay:?}"
        );
        tokio::time::sleep(delay).await;
        attempt += 1;
    }
}

/// Resolve the homeserver, then spend `token` on a session, retrying the parts that cannot have
/// consumed it. Everything runs inside one [`BUDGET`] from the token's arrival.
#[allow(deprecated)]
pub(crate) async fn exchange(
    client: &PubkyHttpClient,
    token: &AuthToken,
    homeserver: Option<PublicKey>,
) -> Result<CookieCredential, String> {
    let started = Instant::now();
    let qname = exchange_qname(token.public_key(), homeserver.as_ref());
    resolve_with_retries(client, &qname, started).await?;

    let mut attempt = 1;
    loop {
        let spend = CookieCredential::from_auth_token(token, client, homeserver.clone());
        let error = match timeout(EXCHANGE_TIMEOUT, spend).await {
            Ok(Ok(credential)) => return Ok(credential),
            Ok(Err(error)) => error,
            Err(_) => {
                return Err(format!(
                    "Session exchange timed out after {EXCHANGE_TIMEOUT:?}; start a new sign-in"
                ))
            }
        };
        let delay = never_sent(&error)
            .then(|| {
                retry_delay(
                    attempt,
                    EXCHANGE_ATTEMPTS,
                    started.elapsed(),
                    EXCHANGE_TIMEOUT,
                )
            })
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
        let reserve = Duration::ZERO;
        assert_eq!(
            retry_delay(1, 4, start, reserve),
            Some(Duration::from_secs(1))
        );
        assert_eq!(
            retry_delay(2, 4, start, reserve),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            retry_delay(3, 4, start, reserve),
            Some(Duration::from_secs(4))
        );
        assert_eq!(retry_delay(4, 4, start, reserve), None);
    }

    #[test]
    fn no_attempt_starts_that_could_finish_past_the_budget() {
        let reserve = RESOLVE_ATTEMPT_TIMEOUT + EXCHANGE_TIMEOUT;
        let last_start = BUDGET - reserve - Duration::from_secs(1);
        assert_eq!(
            retry_delay(1, 4, last_start, reserve),
            Some(Duration::from_secs(1))
        );
        assert_eq!(
            retry_delay(1, 4, last_start + Duration::from_millis(1), reserve),
            None
        );
    }

    #[test]
    fn the_budget_leaves_the_relay_leg_a_minute_of_the_tokens_window() {
        assert!(BUDGET + Duration::from_secs(60) <= Duration::from_secs(180));
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

    /// Live: a key that never published a record is reported as having none — a verdict, not a
    /// blip to retry — without a request to its `_pubky` name.
    #[tokio::test]
    #[ignore = "needs the network: pkarr relays"]
    #[allow(deprecated)]
    async fn live_an_unpublished_key_is_reported_as_having_no_record() {
        let client = crate::get_pubky_client();
        let token = AuthToken::sign(&Keypair::random(), pubky::Capabilities::default());

        let error = exchange(client.client(), &token, None)
            .await
            .expect_err("unresolvable");

        assert!(error.starts_with(NO_RECORD), "{error}");
    }
}
