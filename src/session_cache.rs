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
//!
//! ## Why the wording is part of the contract
//!
//! Every failure here leaves as a `String` — the FFI has no typed error surface — and for a long
//! time every one of them left as the *same* string, `"Failed to import session: …"`. A consumer
//! could not tell a homeserver that refused the session from a homeserver having a bad minute, so
//! it had to guess from prose, and the guess is not symmetric: reading a refusal as trouble costs a
//! retry, while reading trouble as a refusal costs the credential. Loopky signs the user out on
//! that verdict, and signing out revokes the session and clears the local key with it — so one
//! transient `500` destroyed a session that was working (pubky/loopky#283).
//!
//! The typed error is right here, and [`is_session_rejected`] already knows the answer. So a
//! refusal now says so: [`SESSION_REJECTED`] prefixes exactly the failures a new sign-in fixes, and
//! nothing else. It is deliberately worded to still contain "session" and "invalid", because a
//! consumer built against an older binary matches on those and must keep working.

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

/// The one wording that means "this session is finished — sign in again".
///
/// Produced only where the *typed* error says the homeserver refused the session, never from
/// reading a message back. Everything else the session path can fail with is a reason to retry, and
/// says so by not carrying this.
///
/// The rest of the sentence keeps the words "session" and "invalid" on purpose: a consumer built
/// against a binary that predates this classifies on those, and must not stop recognising the one
/// failure it most needs to.
pub const SESSION_REJECTED: &str = "Session rejected";

fn rejected(error: &Error, detail: impl std::fmt::Display) -> String {
    format!("{SESSION_REJECTED}: the homeserver refused this session as invalid: {detail}")
        + if matches!(error, Error::Authentication(_)) {
            " (authentication)"
        } else {
            ""
        }
}

/// What went wrong in [`with_session`].
pub enum SessionOpError {
    /// The session could not be imported at all. Already formatted — [`SESSION_REJECTED`] when the
    /// homeserver refused it, otherwise the wording every `*_with_session` entry point has always
    /// returned, because callers match on it.
    Import(String),
    /// The operation itself failed. Formatted by [`SessionOpError::into_message`] with the caller's
    /// own verb, so the FFI's error surface is unchanged apart from the rejection marker.
    Op(Error),
}

impl SessionOpError {
    /// The FFI error payload for this failure, under the caller's own `verb` ("Failed to put").
    ///
    /// The verb matters less than the marker. A rejection that survives [`with_session`]'s retry
    /// arrives here rather than as an [`SessionOpError::Import`] — the cold path runs the operation
    /// against a session it has just imported, so a `401` on the write is reported under the
    /// *write's* wording and mentions no session at all. That is the shape a consumer cannot
    /// classify and the reason this is a method rather than three `format!`s at the call sites.
    pub fn into_message(self, verb: &str) -> String {
        match self {
            SessionOpError::Import(message) => message,
            SessionOpError::Op(error) if is_session_rejected(&error) => {
                rejected(&error, format_args!("{verb}: {error}"))
            }
            SessionOpError::Op(error) => format!("{verb}: {error}"),
        }
    }
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
        // Classified here, where the typed error still exists. Downstream this is prose.
        Err(error) if is_session_rejected(&error) => Err(rejected(&error, &error)),
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
    use super::{is_session_rejected, SessionOpError, SESSION_REJECTED};
    use pubky::errors::{AuthError, RequestError};
    use pubky::{Error, StatusCode};

    fn server(status: StatusCode) -> Error {
        Error::Request(RequestError::Server {
            status,
            message: String::new(),
        })
    }

    /// The whole point of the marker: the caller must be able to tell the one failure a new
    /// sign-in fixes from the ones a retry fixes, without reading prose. Reading a refusal as
    /// trouble costs a retry; reading trouble as a refusal costs the credential.
    #[test]
    fn only_a_refused_session_is_marked() {
        let refused =
            SessionOpError::Op(server(StatusCode::UNAUTHORIZED)).into_message("Failed to put");
        assert!(refused.starts_with(SESSION_REJECTED), "{refused}");
        assert!(refused.contains("Failed to put"), "{refused}");

        for busy in [
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::INSUFFICIENT_STORAGE,
        ] {
            let message = SessionOpError::Op(server(busy)).into_message("Failed to put");
            assert!(!message.contains(SESSION_REJECTED), "{busy}: {message}");
            assert!(message.starts_with("Failed to put"), "{busy}: {message}");
        }
    }

    /// A rejection surviving `with_session`'s retry arrives as an `Op`, under the *write's*
    /// wording — the cold path runs the operation against a session it has just imported, so the
    /// message mentions no session at all. That is the shape a consumer used to classify as
    /// "unknown" and the reason the verb is formatted here rather than at the call site.
    #[test]
    fn a_rejection_reported_under_the_writes_own_verb_is_still_marked() {
        let message = SessionOpError::Op(Error::Authentication(AuthError::RequestExpired))
            .into_message("Failed to delete");

        assert!(message.starts_with(SESSION_REJECTED), "{message}");
        assert!(message.contains("(authentication)"), "{message}");
    }

    /// A consumer built against a binary that predates the marker classifies on the words
    /// "session" and "invalid"/"expired". Losing those would make the one failure it most needs to
    /// recognise the one failure it silently stops recognising, so they stay in the sentence.
    #[test]
    fn the_marker_still_reads_as_an_expiry_to_an_older_consumer() {
        let message =
            SessionOpError::Op(server(StatusCode::FORBIDDEN)).into_message("Failed to put");
        let lowered = message.to_lowercase();

        assert!(lowered.contains("session"), "{message}");
        assert!(lowered.contains("invalid"), "{message}");
    }

    /// An import failure is passed through untouched: it was classified at the source, where the
    /// typed error still existed, and re-deciding it from the string here is the mistake this
    /// whole change exists to remove.
    #[test]
    fn an_import_message_is_never_reclassified() {
        let message = SessionOpError::Import("Failed to import session: whatever".to_string())
            .into_message("Failed to put");

        assert_eq!(message, "Failed to import session: whatever");
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
