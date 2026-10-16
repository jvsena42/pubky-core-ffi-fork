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
//! ## Many identities in one process
//!
//! A hosted server holds a session per user, so the cache is a real LRU (loopky#214): overflow
//! evicts the one entry used longest ago, never the whole map, and the capacity is set with
//! [`configure`]. The default stays small because a phone has one identity.
//!
//! Minting is **single-flight per secret**. Two writes that find no cached session, or two that
//! were both answered `401` by the same expired bearer, must not each exchange the grant: every
//! exchange replaces the bearer the other just minted, and the two callers then invalidate each
//! other's session in turn. So the second caller waits for the first mint and reuses it, and a
//! re-mint only happens when nobody has replaced the session that failed since the caller last
//! saw it ([`SessionStore::remint`]). The minting function is a parameter of the store, which is
//! how the tests exercise this without a homeserver.
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
use std::sync::{Arc, Mutex, MutexGuard};

use once_cell::sync::Lazy;
use pubky::errors::RequestError;
use pubky::{Error, PubkySession, StatusCode};

use crate::get_pubky_client;

/// Sessions kept at once unless [`configure`] says otherwise. One signed-in identity is the
/// normal case on a phone; the cap only exists so that an app signing in and out repeatedly —
/// each sign-in mints a **new** secret, so a new key — does not grow the map for the life of the
/// process.
pub const DEFAULT_CAPACITY: usize = 4;

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

struct Entry<S> {
    value: S,
    /// Bumped on every hit; the smallest one is the eviction candidate.
    last_used: u64,
    /// Which mint produced this entry. A caller that was answered `401` by mint `n` asks for a
    /// session minted *after* `n`, and gets the one a concurrent caller already minted rather
    /// than minting a third.
    minted: u64,
}

struct Lru<S> {
    capacity: usize,
    clock: u64,
    entries: HashMap<String, Entry<S>>,
}

impl<S: Clone> Lru<S> {
    fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            clock: 0,
            entries: HashMap::new(),
        }
    }

    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    fn get(&mut self, secret: &str) -> Option<(S, u64)> {
        let now = self.tick();
        let entry = self.entries.get_mut(secret)?;
        entry.last_used = now;
        Some((entry.value.clone(), entry.minted))
    }

    fn minted_after(&mut self, secret: &str, minted: u64) -> Option<S> {
        let (value, stamp) = self.get(secret)?;
        (stamp > minted).then_some(value)
    }

    fn insert(&mut self, secret: &str, value: S) {
        if !self.entries.contains_key(secret) {
            self.trim_to(self.capacity - 1);
        }
        let now = self.tick();
        self.entries.insert(
            secret.to_string(),
            Entry {
                value,
                last_used: now,
                minted: now,
            },
        );
    }

    /// Evict least-recently-used entries until at most `len` remain.
    fn trim_to(&mut self, len: usize) {
        while self.entries.len() > len {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(secret, _)| secret.clone())
            else {
                break;
            };
            self.entries.remove(&oldest);
        }
    }

    fn set_capacity(&mut self, capacity: usize) {
        self.capacity = capacity.max(1);
        self.trim_to(self.capacity);
    }
}

/// An LRU of sessions keyed by secret, with one mint in flight per secret at a time.
///
/// Generic over the session type so the eviction and single-flight rules can be tested with a
/// counter standing in for a homeserver round trip.
pub(crate) struct SessionStore<S> {
    lru: Mutex<Lru<S>>,
    /// One async lock per secret currently being minted. Entries are dropped by the last holder,
    /// so the map does not grow with every secret the process has ever seen.
    minting: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl<S: Clone> SessionStore<S> {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            lru: Mutex::new(Lru::new(capacity)),
            minting: Mutex::new(HashMap::new()),
        }
    }

    /// A poisoned cache is a cache, not a dead one: a panic elsewhere must not turn every
    /// subsequent write into a failure. The worst a stale entry can do is cost one rejected
    /// request and a retry.
    fn lru(&self) -> MutexGuard<'_, Lru<S>> {
        self.lru
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn minting(&self) -> MutexGuard<'_, HashMap<String, Arc<tokio::sync::Mutex<()>>>> {
        self.minting
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn cached(&self, secret: &str) -> Option<(S, u64)> {
        self.lru().get(secret)
    }

    pub(crate) fn remember(&self, secret: &str, value: S) {
        self.lru().insert(secret, value);
    }

    pub(crate) fn forget(&self, secret: &str) {
        self.lru().entries.remove(secret);
    }

    pub(crate) fn clear(&self) {
        self.lru().entries.clear();
    }

    pub(crate) fn set_capacity(&self, capacity: usize) {
        self.lru().set_capacity(capacity);
    }

    pub(crate) fn capacity(&self) -> usize {
        self.lru().capacity
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.lru().entries.len()
    }

    /// Every cached session, for callers that need to look inside them.
    pub(crate) fn values(&self) -> Vec<(String, S)> {
        self.lru()
            .entries
            .iter()
            .map(|(secret, entry)| (secret.clone(), entry.value.clone()))
            .collect()
    }

    /// Run `body` holding this secret's mint lock. Concurrent callers for the same secret queue
    /// here; callers for other secrets do not.
    async fn single_flight<T, F, Fut>(&self, secret: &str, body: F) -> T
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = T>,
    {
        let lock = self
            .minting()
            .entry(secret.to_string())
            .or_default()
            .clone();
        let result = {
            let _held = lock.lock().await;
            body().await
        };
        let mut minting = self.minting();
        // Two references: the map's and ours. Anyone else interested cloned it under the map
        // lock before we took it, so the count cannot drop between the check and the removal.
        if Arc::strong_count(&lock) == 2 {
            minting.remove(secret);
        }
        result
    }

    /// The cached session for `secret`, or the one `mint` produces — shared with every caller
    /// that asks while the mint is in flight.
    pub(crate) async fn get_or_mint<F, Fut>(&self, secret: &str, mint: F) -> Result<S, String>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<S, String>>,
    {
        if let Some((value, _)) = self.cached(secret) {
            return Ok(value);
        }
        self.single_flight(secret, || async {
            // Minted by whoever held the lock before us.
            if let Some((value, _)) = self.cached(secret) {
                return Ok(value);
            }
            let value = mint().await?;
            self.remember(secret, value.clone());
            Ok(value)
        })
        .await
    }

    /// A session newer than the one stamped `stale` — minted here unless a concurrent caller
    /// already replaced it, in which case theirs is returned and no second exchange happens.
    ///
    /// `stale` is the stamp the caller saw fail (`None` when it saw nothing cached, which treats
    /// anything minted since as fresh enough).
    pub(crate) async fn remint<F, Fut>(
        &self,
        secret: &str,
        stale: Option<u64>,
        mint: F,
    ) -> Result<S, String>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<S, String>>,
    {
        self.single_flight(secret, || async {
            if let Some(value) = self.lru().minted_after(secret, stale.unwrap_or(0)) {
                return Ok(value);
            }
            // Before the round trip, not after: nothing may be handed the failed session while
            // its replacement is minted.
            self.forget(secret);
            let value = mint().await?;
            self.remember(secret, value.clone());
            Ok(value)
        })
        .await
    }
}

static SESSIONS: Lazy<SessionStore<PubkySession>> =
    Lazy::new(|| SessionStore::new(DEFAULT_CAPACITY));

/// How many sessions to keep. Anything below one is one; shrinking evicts the least recently
/// used down to the new size.
pub fn configure(capacity: usize) -> usize {
    SESSIONS.set_capacity(capacity);
    SESSIONS.capacity()
}

/// Drop one session, so the next call re-imports it.
pub fn forget(secret: &str) {
    SESSIONS.forget(secret);
}

/// Drop every cached session minted from `grant_id`. A revoked grant's sessions would otherwise
/// sit in the cache until their first `401`.
pub async fn forget_grant(grant_id: &str) {
    for (secret, session) in SESSIONS.values() {
        let Some(grant) = session.as_grant() else {
            continue;
        };
        if grant.grant_id().await.as_str() == grant_id {
            SESSIONS.forget(&secret);
        }
    }
}

/// Drop every session. Called when the network is switched: those sessions belong to the previous
/// network's homeservers and hold a client that no longer resolves them.
pub fn clear() {
    SESSIONS.clear();
}

/// Import `secret`. Always a `/session` round trip (or a grant exchange).
///
/// The error is the formatted message rather than the failure, because there is only one way to
/// report it and every caller has always reported it identically.
async fn import(secret: &str) -> Result<PubkySession, String> {
    match get_pubky_client().restore_session(secret).await {
        Ok(session) => Ok(session),
        // Classified here, where the typed error still exists. Downstream this is prose.
        Err(error) if is_session_rejected(&error) => Err(rejected(&error, &error)),
        // Every `*_with_session` call imports first, so this is where a proxy refusing the
        // homeserver surfaces for a write — its cause is only in the source chain.
        Err(error) => Err(format!(
            "Failed to import session: {}",
            crate::full_error_chain(&error)
        )),
    }
}

/// The session for `secret`, imported only if one is not already cached.
pub async fn session_for(secret: &str) -> Result<PubkySession, String> {
    SESSIONS.get_or_mint(secret, || import(secret)).await
}

/// A freshly imported session, replacing whatever was cached. For callers whose whole purpose is
/// to ask the homeserver — `revalidate_session` — where a cached answer would be no answer.
///
/// Two of these for the same secret at once share one import: the second finds a session minted
/// since it looked and takes that, rather than exchanging the grant a second time.
pub async fn refreshed_session(secret: &str) -> Result<PubkySession, String> {
    let seen = SESSIONS.cached(secret).map(|(_, minted)| minted);
    SESSIONS.remint(secret, seen, || import(secret)).await
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
    let Some((session, minted)) = SESSIONS.cached(secret) else {
        // Cold: the import just revalidated the session, so a rejection here is real and there is
        // nothing a retry could learn.
        let session = session_for(secret).await.map_err(SessionOpError::Import)?;
        return operation(session).await.map_err(SessionOpError::Op);
    };

    match operation(session).await {
        Ok(value) => Ok(value),
        Err(error) if is_session_rejected(&error) => {
            let fresh = SESSIONS
                .remint(secret, Some(minted), || import(secret))
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
pub(crate) fn is_session_rejected(error: &Error) -> bool {
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
    use super::{is_session_rejected, SessionOpError, SessionStore, SESSION_REJECTED};
    use pubky::errors::{AuthError, RequestError};
    use pubky::{Error, StatusCode};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use tokio::sync::Notify;

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

    // --- the store, with a counter standing in for the homeserver -----------------------------

    /// A mint that returns a fresh number each time and counts how often it ran.
    struct Minter(AtomicU32);

    impl Minter {
        fn new() -> Arc<Self> {
            Arc::new(Self(AtomicU32::new(0)))
        }
        async fn mint(&self) -> Result<u32, String> {
            Ok(self.0.fetch_add(1, Ordering::SeqCst) + 1)
        }
        fn mints(&self) -> u32 {
            self.0.load(Ordering::SeqCst)
        }
    }

    /// Overflow used to `clear()` the map, which cost every other identity its session the
    /// moment a fifth one signed in. Only the entry used longest ago goes now.
    #[tokio::test]
    async fn overflow_evicts_only_the_least_recently_used() {
        let store = SessionStore::<u32>::new(2);
        let minter = Minter::new();
        for secret in ["a", "b"] {
            store.get_or_mint(secret, || minter.mint()).await.unwrap();
        }
        // Touch `a`, so `b` is the oldest.
        assert!(store.cached("a").is_some());
        store.get_or_mint("c", || minter.mint()).await.unwrap();

        assert!(
            store.cached("a").is_some(),
            "a was used more recently than b"
        );
        assert!(store.cached("b").is_none(), "b is the one evicted");
        assert!(store.cached("c").is_some());
        assert_eq!(store.len(), 2);
    }

    #[tokio::test]
    async fn a_cached_session_costs_no_mint() {
        let store = SessionStore::<u32>::new(4);
        let minter = Minter::new();
        let first = store.get_or_mint("s", || minter.mint()).await.unwrap();
        let again = store.get_or_mint("s", || minter.mint()).await.unwrap();
        assert_eq!(first, again);
        assert_eq!(minter.mints(), 1);
    }

    #[tokio::test]
    async fn shrinking_the_capacity_trims_the_oldest_first() {
        let store = SessionStore::<u32>::new(4);
        let minter = Minter::new();
        for secret in ["a", "b", "c", "d"] {
            store.get_or_mint(secret, || minter.mint()).await.unwrap();
        }
        store.set_capacity(2);
        assert_eq!(store.capacity(), 2);
        assert!(store.cached("a").is_none());
        assert!(store.cached("b").is_none());
        assert!(store.cached("c").is_some());
        assert!(store.cached("d").is_some());

        store.set_capacity(0);
        assert_eq!(
            store.capacity(),
            1,
            "zero would cache nothing and mint on every call"
        );
    }

    /// Two cold callers for the same secret: one exchange, both get its result.
    #[tokio::test]
    async fn concurrent_cold_callers_share_one_mint() {
        let store = Arc::new(SessionStore::<u32>::new(4));
        let minter = Minter::new();
        let release = Arc::new(Notify::new());

        let first = {
            let (store, minter, release) = (store.clone(), minter.clone(), release.clone());
            tokio::spawn(async move {
                store
                    .get_or_mint("s", || async {
                        // Hold the mint open until the second caller is queued behind it.
                        release.notified().await;
                        minter.mint().await
                    })
                    .await
            })
        };
        tokio::task::yield_now().await;
        let second = {
            let (store, minter) = (store.clone(), minter.clone());
            tokio::spawn(async move { store.get_or_mint("s", || minter.mint()).await })
        };
        tokio::task::yield_now().await;
        release.notify_one();

        let (first, second) = (
            first.await.unwrap().unwrap(),
            second.await.unwrap().unwrap(),
        );
        assert_eq!(first, second);
        assert_eq!(
            minter.mints(),
            1,
            "the second caller must reuse the first mint"
        );
    }

    /// Two writes answered `401` by the same bearer: the first re-mints, the second takes that
    /// mint rather than exchanging the grant again — which would replace the first's bearer and
    /// send both writes round the same loop (loopky#214).
    #[tokio::test]
    async fn a_remint_after_a_shared_rejection_happens_once() {
        let store = Arc::new(SessionStore::<u32>::new(4));
        let minter = Minter::new();
        store.get_or_mint("s", || minter.mint()).await.unwrap();
        let (_, stale) = store.cached("s").unwrap();
        let release = Arc::new(Notify::new());

        let first = {
            let (store, minter, release) = (store.clone(), minter.clone(), release.clone());
            tokio::spawn(async move {
                store
                    .remint("s", Some(stale), || async {
                        release.notified().await;
                        minter.mint().await
                    })
                    .await
            })
        };
        tokio::task::yield_now().await;
        let second = {
            let (store, minter) = (store.clone(), minter.clone());
            tokio::spawn(async move { store.remint("s", Some(stale), || minter.mint()).await })
        };
        tokio::task::yield_now().await;
        release.notify_one();

        let (first, second) = (
            first.await.unwrap().unwrap(),
            second.await.unwrap().unwrap(),
        );
        assert_eq!(first, second);
        assert_eq!(
            minter.mints(),
            2,
            "one mint, then one re-mint — never a third"
        );
    }

    /// A caller that saw the *replacement* fail must get another one: the stamp is what tells a
    /// second rejection from a stale view of the first.
    #[tokio::test]
    async fn a_rejection_of_the_replacement_mints_again() {
        let store = SessionStore::<u32>::new(4);
        let minter = Minter::new();
        store.get_or_mint("s", || minter.mint()).await.unwrap();
        let (_, first) = store.cached("s").unwrap();
        store
            .remint("s", Some(first), || minter.mint())
            .await
            .unwrap();
        let (_, second) = store.cached("s").unwrap();
        assert!(second > first);

        store
            .remint("s", Some(second), || minter.mint())
            .await
            .unwrap();
        assert_eq!(minter.mints(), 3);
    }

    /// `refreshed_session` with nothing cached: anything minted while waiting is fresh enough.
    #[tokio::test]
    async fn a_remint_with_no_prior_view_takes_whatever_was_minted_meanwhile() {
        let store = SessionStore::<u32>::new(4);
        let minter = Minter::new();
        store.get_or_mint("s", || minter.mint()).await.unwrap();
        let value = store.remint("s", None, || minter.mint()).await.unwrap();
        assert_eq!(
            value, 1,
            "the entry minted before the call is newer than 'nothing'"
        );
        assert_eq!(minter.mints(), 1);
    }

    #[tokio::test]
    async fn a_failed_mint_leaves_nothing_cached_and_no_lock_behind() {
        let store = SessionStore::<u32>::new(4);
        let result = store
            .get_or_mint("s", || async { Err::<u32, _>("boom".to_string()) })
            .await;
        assert_eq!(result, Err("boom".to_string()));
        assert!(store.cached("s").is_none());
        assert!(
            store.minting().is_empty(),
            "the per-secret lock is dropped with its last holder"
        );
    }

    #[tokio::test]
    async fn different_secrets_do_not_queue_behind_each_other() {
        let store = Arc::new(SessionStore::<u32>::new(4));
        let minter = Minter::new();
        let release = Arc::new(Notify::new());
        let blocked = {
            let (store, minter, release) = (store.clone(), minter.clone(), release.clone());
            tokio::spawn(async move {
                store
                    .get_or_mint("slow", || async {
                        release.notified().await;
                        minter.mint().await
                    })
                    .await
            })
        };
        tokio::task::yield_now().await;
        // Completes while `slow` is still held open.
        store.get_or_mint("fast", || minter.mint()).await.unwrap();
        assert_eq!(minter.mints(), 1);
        release.notify_one();
        blocked.await.unwrap().unwrap();
        assert_eq!(minter.mints(), 2);
    }
}
