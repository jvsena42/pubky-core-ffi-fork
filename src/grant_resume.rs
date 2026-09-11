//! Keeps a pending grant sign-in alive when its relay long-poll dies.
//!
//! The relay inbox is store-and-forward: an approval posted while nobody is polling stays there
//! for ~5 minutes, until the consumer ACKs it. pubky's poller gives up after three consecutive
//! transport failures. On the Android emulator the relay's name intermittently fails to resolve
//! through the system resolver — an ~18s lookup timeout, then instant failures from its cache —
//! so the flow died before the signer had approved, and the approval then landed in an inbox
//! nobody was reading. [`PubkyGrantAuthFlow::restore`] rejoins the *same* channel once the name
//! resolves again, which collects that approval without the user having to approve twice.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use pubky::errors::RequestError;
use pubky::{Error, GrantAuthFlowState, PubkyGrantAuthFlow, PubkySession};

use crate::{full_error_chain, get_pubky_client};

/// A listener that fails this soon after starting never held a long-poll open: that is an outage,
/// not a poll cut short.
pub(crate) const QUICK_FAILURE: Duration = Duration::from_secs(5);
/// How long an outage is waited out. Measured on the Android emulator: after a 20s network cut the
/// system resolver kept failing for another ~43s, which spent a 60s allowance with seconds to
/// spare. Still short enough that an offline device hears about it well before the caller gives up.
pub(crate) const MAX_OUTAGE: Duration = Duration::from_secs(90);
pub(crate) const MAX_BACKOFF: Duration = Duration::from_secs(8);
/// Just under Loopky's three-minute approval timeout, which cannot interrupt this blocking call:
/// finishing first lets the caller report the relay failure rather than "Ring never answered".
/// Well inside the inbox's ~5 minute hold.
pub(crate) const RESUME_WINDOW: Duration = Duration::from_secs(170);

/// What a restore needs. Holds the relay secret and the `PoP` client key, so it is dropped as soon
/// as its flow ends.
#[derive(Clone)]
pub(crate) struct PendingGrantFlow {
    pub generation: u64,
    pub state: GrantAuthFlowState,
    pub relay: String,
    pub started: Instant,
}

static GENERATION: AtomicU64 = AtomicU64::new(0);
static PENDING: Lazy<Mutex<Option<PendingGrantFlow>>> = Lazy::new(|| Mutex::new(None));

/// Record a just-started flow. Bumping the generation is what stops a resume loop still running
/// for an earlier sign-in: it checks [`is_current`] before every restore.
pub(crate) fn remember(flow: &PubkyGrantAuthFlow) {
    let generation = GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
    let relay = flow
        .authorization_url()
        .query_pairs()
        .find(|(key, _)| key == "relay")
        .map(|(_, value)| value.into_owned());
    let pending = match (flow.save_local(), relay) {
        (Some(state), Some(relay)) => Some(PendingGrantFlow {
            generation,
            state,
            relay,
            started: Instant::now(),
        }),
        _ => None,
    };
    *PENDING.lock().unwrap() = pending;
}

pub(crate) fn current() -> Option<PendingGrantFlow> {
    PENDING.lock().unwrap().clone()
}

pub(crate) fn is_current(generation: u64) -> bool {
    GENERATION.load(Ordering::SeqCst) == generation
}

/// Drop the saved state for `generation`, and only that one — a superseded loop must not wipe the
/// flow that replaced it.
pub(crate) fn forget(generation: u64) {
    let mut guard = PENDING.lock().unwrap();
    if guard.as_ref().is_some_and(|p| p.generation == generation) {
        *guard = None;
    }
}

pub(crate) fn restore(pending: &PendingGrantFlow) -> pubky::Result<PubkyGrantAuthFlow> {
    PubkyGrantAuthFlow::restore(pending.state.clone(), get_pubky_client().client().clone())
}

/// Did polling this flow's relay channel fail at the transport level?
///
/// Only then is a resume safe. `await_approval` also exchanges the grant at the homeserver once
/// the relay delivers it, and a transport failure *there* comes after the listener has ACKed —
/// deleted — the approval: a restored listener would wait on an empty inbox forever. The failing
/// URL is what tells the two apart.
pub(crate) fn is_relay_transport_failure(error: &Error, relay: &str) -> bool {
    let Error::Request(RequestError::Transport(transport)) = error else {
        return false;
    };
    let relay = relay.trim_end_matches('/');
    transport.url().is_some_and(|url| {
        let url = url.as_str();
        url == relay || url.starts_with(&format!("{relay}/"))
    })
}

/// How long to wait before the next restore, or `None` to give up.
///
/// `quick_failures` counts restores in a row that died on arrival; `outage` is how long that has
/// been going on.
pub(crate) fn resume_delay(
    quick_failures: u32,
    outage: Duration,
    since_start: Duration,
) -> Option<Duration> {
    if outage >= MAX_OUTAGE || since_start >= RESUME_WINDOW {
        return None;
    }
    Some(Duration::from_secs(1 << quick_failures.min(3)).min(MAX_BACKOFF))
}

/// [`PubkyGrantAuthFlow::await_approval`], rejoining the same relay channel whenever the poll dies
/// at the transport level.
pub(crate) async fn await_resuming(mut flow: PubkyGrantAuthFlow) -> pubky::Result<PubkySession> {
    // Resume only the flow we were handed: a remembered state for any other URL is not ours.
    let flow_url = flow.authorization_url().to_string();
    let pending = current().filter(|p| p.state.authorization_url == flow_url);
    let mut listening_since = pending.as_ref().map_or_else(Instant::now, |p| p.started);
    let mut quick_failures = 0;
    let mut outage_since: Option<Instant> = None;

    loop {
        let error = match flow.await_approval().await {
            Ok(session) => {
                if let Some(p) = &pending {
                    forget(p.generation);
                }
                return Ok(session);
            }
            Err(error) => error,
        };
        let Some(p) = pending.as_ref() else {
            return Err(error);
        };
        if !is_relay_transport_failure(&error, &p.relay) || !is_current(p.generation) {
            forget(p.generation);
            return Err(error);
        }

        if listening_since.elapsed() < QUICK_FAILURE {
            outage_since.get_or_insert(listening_since);
            quick_failures += 1;
        } else {
            outage_since = None;
            quick_failures = 0;
        }
        let outage = outage_since.map_or(Duration::ZERO, |since| since.elapsed());
        let Some(delay) = resume_delay(quick_failures, outage, p.started.elapsed()) else {
            forget(p.generation);
            return Err(error);
        };
        tracing::warn!(
            "Relay poll for the pending sign-in failed ({}); rejoining the same channel in {delay:?}",
            full_error_chain(&error)
        );
        tokio::time::sleep(delay).await;

        if !is_current(p.generation) {
            return Err(error);
        }
        flow = match restore(p) {
            Ok(restored) => restored,
            Err(restore_error) => {
                forget(p.generation);
                return Err(restore_error);
            }
        };
        listening_since = Instant::now();
    }
}
