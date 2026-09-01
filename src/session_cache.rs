//! Reuse of imported sessions across authenticated calls.
//!
//! Every `*_with_session` entry point used to begin with `Pubky::restore_session`, and a cookie
//! restore ends in a full `/session` round trip to revalidate the cookie (`import_secret` in the
//! SDK). That made **one record write cost two HTTP requests**: a revalidation nobody asked for,
//! then the write itself. Deleting a 9,263-card deck is ~100 records, so ~200 requests, half of
//! them pure overhead — and the overhead did double damage, because it was also what saturated
//! the homeserver's rate limiter and forced callers down to a concurrency of 2, which serialized
//! the run. See pubky/loopky#105.
//!
//! A `PubkySession` is a cheap, thread-safe clone over a shared HTTP client, so the fix is simply
//! to keep the imported one and hand out clones: the `/session` round trip is paid **once** per
//! secret instead of once per write.
//!
//! ## Why this stays correct
//!
//! Revalidating before every write was never what made the write safe — the homeserver checks the
//! cookie on the write itself, and answers `401` when it will not accept it. So an expiry is
//! *detected either way*; the only difference is where. On a rejection [`with_session`] drops the
//! cached session, re-imports (paying the round trip that was skipped), and runs the operation
//! once more. When the re-import fails, the caller gets the same `"Failed to import session: …"`
//! string it has always seen for an expired session — consumers classify on that wording.
//!
//! A grant restore mints a fresh short-lived bearer rather than revalidating a cookie. Caching one
//! is the same trade and the same recovery: the bearer eventually expires, the homeserver says so,
//! and the retry mints another.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Mutex, MutexGuard};

use once_cell::sync::Lazy;
use pubky::errors::RequestError;
use pubky::{Error, PubkySession, StatusCode};

use crate::get_pubky_client;

static SESSIONS: Lazy<Mutex<HashMap<String, PubkySession>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Sessions kept at once. One signed-in identity is the normal case; the cap only exists so that
/// an app signing in and out repeatedly — each sign-in mints a **new** secret, so a new key — does
/// not grow the map for the life of the process. Overflow drops the lot, which costs one import
/// per surviving session and nothing else.
const MAX_CACHED_SESSIONS: usize = 4;

/// What went wrong in [`with_session`].
pub enum SessionOpError {
    /// The session could not be imported at all. Already formatted with the wording every
    /// `*_with_session` entry point has always returned, because callers match on it.
    Import(String),
    /// The operation itself failed. The caller formats this with its own verb ("Failed to put",
    /// "Failed to delete") so the FFI's error surface is unchanged.
    Op(Error),
}

/// A poisoned cache is a cache, not a dead one: a panic elsewhere must not turn every subsequent
/// write into a failure. The worst a stale entry can do is cost one rejected request and a retry.
fn sessions() -> MutexGuard<'static, HashMap<String, PubkySession>> {
    SESSIONS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn cached(secret: &str) -> Option<PubkySession> {
    sessions().get(secret).cloned()
}

fn remember(secret: &str, session: &PubkySession) {
    let mut sessions = sessions();
    if sessions.len() >= MAX_CACHED_SESSIONS && !sessions.contains_key(secret) {
        sessions.clear();
    }
    sessions.insert(secret.to_string(), session.clone());
}

/// Drop one session, so the next call re-imports it.
pub fn forget(secret: &str) {
    sessions().remove(secret);
}

/// Drop every session. Called when the network is switched: those sessions belong to the previous
/// network's homeservers and hold a client that no longer resolves them.
pub fn clear() {
    sessions().clear();
}

/// Import `secret` and cache the result. Always a `/session` round trip.
///
/// The error is the formatted message rather than the failure, because there is only one way to
/// report it and every caller has always reported it identically.
async fn import(secret: &str) -> Result<PubkySession, String> {
    match get_pubky_client().restore_session(secret).await {
        Ok(session) => {
            remember(secret, &session);
            Ok(session)
        }
        Err(error) => Err(format!("Failed to import session: {}", error)),
    }
}

/// The session for `secret`, imported only if one is not already cached.
pub async fn session_for(secret: &str) -> Result<PubkySession, String> {
    match cached(secret) {
        Some(session) => Ok(session),
        None => import(secret).await,
    }
}

/// A freshly imported session, replacing whatever was cached. For callers whose whole purpose is
/// to ask the homeserver — `revalidate_session` — where a cached answer would be no answer.
pub async fn refreshed_session(secret: &str) -> Result<PubkySession, String> {
    forget(secret);
    import(secret).await
}

/// Run `operation` as the identity behind `secret`, reusing a cached session when there is one.
///
/// `operation` is a `Fn` and may run twice: once against the cached session, and once more against
/// a freshly imported one if the homeserver rejected the first. Give it a body it can rebuild —
/// clone the payload inside the closure rather than moving it in.
pub async fn with_session<T, F, Fut>(secret: &str, operation: F) -> Result<T, SessionOpError>
where
    F: Fn(PubkySession) -> Fut,
    Fut: Future<Output = pubky::Result<T>>,
{
    let Some(session) = cached(secret) else {
        // Cold: the import just revalidated the session, so a rejection here is real and there is
        // nothing a retry could learn.
        let session = import(secret).await.map_err(SessionOpError::Import)?;
        return operation(session).await.map_err(SessionOpError::Op);
    };

    match operation(session).await {
        Ok(value) => Ok(value),
        Err(error) if is_session_rejected(&error) => {
            let fresh = refreshed_session(secret)
                .await
                .map_err(SessionOpError::Import)?;
            operation(fresh).await.map_err(SessionOpError::Op)
        }
        Err(error) => Err(SessionOpError::Op(error)),
    }
}

/// Did the homeserver refuse the *session*, as opposed to the request?
///
/// Deliberately narrow. Anything wider retries writes that failed for reasons a new session cannot
/// fix — a `429` retried here would double the load that caused it, and a `507` would spend a
/// second request arriving at the same full disk.
fn is_session_rejected(error: &Error) -> bool {
    match error {
        Error::Authentication(_) => true,
        Error::Request(RequestError::Server { status, .. }) => {
            *status == StatusCode::UNAUTHORIZED || *status == StatusCode::FORBIDDEN
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::is_session_rejected;
    use pubky::errors::{AuthError, RequestError};
    use pubky::{Error, StatusCode};

    fn server(status: StatusCode) -> Error {
        Error::Request(RequestError::Server {
            status,
            message: String::new(),
        })
    }

    #[test]
    fn rejects_are_the_statuses_a_new_session_could_fix() {
        assert!(is_session_rejected(&server(StatusCode::UNAUTHORIZED)));
        assert!(is_session_rejected(&server(StatusCode::FORBIDDEN)));
        assert!(is_session_rejected(&Error::Authentication(
            AuthError::RequestExpired
        )));
    }

    /// The retry in [`super::with_session`] re-imports and *re-sends the write*. Widening this
    /// predicate therefore doubles the load behind a 429, and spends a second request arriving at
    /// the same full disk behind a 507 — the two failures the Kotlin side handles by backing off
    /// and by giving up respectively.
    #[test]
    fn a_busy_or_full_homeserver_is_not_a_rejected_session() {
        assert!(!is_session_rejected(&server(StatusCode::TOO_MANY_REQUESTS)));
        assert!(!is_session_rejected(&server(
            StatusCode::INSUFFICIENT_STORAGE
        )));
        assert!(!is_session_rejected(&server(StatusCode::NOT_FOUND)));
        assert!(!is_session_rejected(&server(
            StatusCode::INTERNAL_SERVER_ERROR
        )));
    }

    /// Offline is not an expiry: the request never reached the homeserver, so nothing can be
    /// concluded about the session. Re-importing would only fail the same way, one round trip later.
    #[test]
    fn a_transport_failure_is_not_a_rejected_session() {
        assert!(!is_session_rejected(&Error::Parse(
            url::ParseError::EmptyHost
        )));
    }
}
