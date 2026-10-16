//! Grant sign-in flows addressed by id, for a process that signs in many users at once.
//!
//! `start_grant_auth_flow`/`await_grant_auth_approval` keep **one** pending flow for the whole
//! process, which is right for a phone and wrong for a server: a second user starting to sign in
//! replaces the first user's flow, and the first approval lands in an inbox nobody is reading
//! (loopky#214). Here every flow has its own id, its own relay channel and its own lifetime, and
//! the global slot is untouched.
//!
//! A flow ends exactly one way — approved, failed, cancelled or expired — and is removed when it
//! does, so an approval is handed out **once**: the second poll for an approved id is told there
//! is no such flow. Pending flows are capped, because each one holds a relay channel and the PoP
//! key for a session that does not exist yet, and swept once they are older than the relay keeps
//! an approval for. The sweep runs on every entry point, not only `start`: with no new sign-ins
//! a `start`-only sweep never runs, and an abandoned flow would keep its listener long-polling
//! the relay and its key material in memory indefinitely. The cap is one budget for the whole
//! process, so a host serving many callers rate-limits `start` per caller itself.
//!
//! **Expired is not the same as gone.** The SDK's listener ACKs — deletes — an approval at the
//! relay the moment it receives it, and then holds it in its channel until someone polls; dropping
//! the flow drops the approval with it, and a user who approved in Ring is never signed in. So a
//! flow past its TTL is only answered `expired` by its own poll or await, after that call has
//! looked in the channel once; and the sweep, which cannot look, leaves an expired flow alone for
//! one more TTL ([`collectable_for`]) so its owner's next poll still finds what arrived in time.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use pubky::{AuthFlowKind, Capabilities, PubkyGrantAuthFlow, PubkySession};
use tokio::sync::Notify;
use url::Url;

use crate::grant_resume::{self, PendingGrantFlow};
use crate::{full_error_chain, get_pubky_http_client, parse_client_id};

pub const DEFAULT_MAX_FLOWS: usize = 64;
/// The relay inbox holds an approval for about five minutes. A flow older than that can no
/// longer be approved, so there is nothing left to keep.
pub const DEFAULT_TTL: Duration = Duration::from_secs(300);

struct Limits {
    max_flows: usize,
    ttl: Duration,
}

static LIMITS: Lazy<Mutex<Limits>> = Lazy::new(|| {
    Mutex::new(Limits {
        max_flows: DEFAULT_MAX_FLOWS,
        ttl: DEFAULT_TTL,
    })
});

struct FlowEntry {
    /// Taken out for the duration of a poll or an await, so the two cannot run the same listener
    /// twice; `None` means one is in progress.
    flow: Option<PubkyGrantAuthFlow>,
    /// What a restore needs, so a flow whose listener died can rejoin its channel. `None` for a
    /// flow with a non-exportable signer, which cannot be restored.
    pending: Option<PendingGrantFlow>,
    started: Instant,
    /// Wakes an await blocked on this flow when it is cancelled from another thread.
    cancelled: Arc<Notify>,
}

static FLOWS: Lazy<Mutex<HashMap<String, FlowEntry>>> = Lazy::new(|| Mutex::new(HashMap::new()));

fn flows() -> MutexGuard<'static, HashMap<String, FlowEntry>> {
    FLOWS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn limits() -> MutexGuard<'static, Limits> {
    LIMITS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// What a poll or a bounded await found.
pub enum Outcome {
    Pending,
    Approved(PubkySession),
    /// Older than the TTL, so no longer approvable; the flow is removed with this answer.
    Expired,
}

/// How often a bounded await looks at its listener's channel. The listener itself long-polls the
/// relay; this only decides how quickly an approval it received is noticed.
const AWAIT_POLL_INTERVAL: Duration = Duration::from_millis(200);

pub fn configure(max_flows: usize, ttl: Duration) -> (usize, Duration) {
    let mut limits = limits();
    limits.max_flows = max_flows.max(1);
    limits.ttl = ttl;
    (limits.max_flows, limits.ttl)
}

#[cfg(test)]
pub(crate) fn pending_count() -> usize {
    flows().len()
}

/// How long past `started` an entry is kept for its owner to collect: the TTL, and one more TTL
/// for an approval that reached the listener's channel before the TTL ran out. Bounds the map at
/// twice the cap, since only flows inside their TTL count against it.
fn collectable_for(ttl: Duration) -> Duration {
    ttl.saturating_mul(2)
}

/// Drop every flow past [`collectable_for`] that is not inside a poll or an await. One that is
/// is decided by that call, which looks in the channel before answering `expired`.
fn evict_expired(flows: &mut HashMap<String, FlowEntry>, ttl: Duration) {
    let keep_for = collectable_for(ttl);
    flows.retain(|_, entry| entry.flow.is_none() || entry.started.elapsed() <= keep_for);
}

/// Flows still inside their TTL: the ones the cap is about. An expired flow kept for collection
/// can no longer be approved, so it does not hold a place a new sign-in needs.
fn live_count(flows: &HashMap<String, FlowEntry>, ttl: Duration) -> usize {
    flows
        .values()
        .filter(|entry| entry.started.elapsed() <= ttl)
        .count()
}

fn sweep() {
    let ttl = limits().ttl;
    evict_expired(&mut flows(), ttl);
}

fn new_id() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

pub fn start(
    capabilities: &str,
    client_id: &str,
    relay: Option<&str>,
) -> Result<(String, String), String> {
    let caps = Capabilities::try_from(capabilities)
        .map_err(|error| format!("Invalid capabilities: {error}"))?;
    let client_id = parse_client_id(client_id)?;
    let relay = relay
        .map(Url::parse)
        .transpose()
        .map_err(|error| format!("Invalid relay URL: {error}"))?;

    let (max_flows, ttl) = {
        let limits = limits();
        (limits.max_flows, limits.ttl)
    };
    {
        let mut flows = flows();
        evict_expired(&mut flows, ttl);
        if live_count(&flows, ttl) >= max_flows {
            return Err(format!(
                "Too many pending auth flows: {max_flows} already waiting for approval"
            ));
        }
    }

    let mut builder = PubkyGrantAuthFlow::builder(&caps, AuthFlowKind::signin(), client_id)
        .client(get_pubky_http_client());
    if let Some(relay) = relay {
        builder = builder.relay(relay);
    }
    let flow = builder
        .start()
        .map_err(|error| format!("Failed to start auth flow: {}", full_error_chain(&error)))?;

    let authorization_url = flow.authorization_url().to_string();
    let started = Instant::now();
    let entry = FlowEntry {
        pending: grant_resume::pending_for(&flow, 0, started),
        flow: Some(flow),
        started,
        cancelled: Arc::new(Notify::new()),
    };
    let id = new_id();
    let mut flows = flows();
    // The cap was checked before the relay channel was opened; a start that raced past it here
    // still has to lose, or the cap is advisory.
    if live_count(&flows, ttl) >= max_flows {
        return Err(format!(
            "Too many pending auth flows: {max_flows} already waiting for approval"
        ));
    }
    flows.insert(id.clone(), entry);
    Ok((id, authorization_url))
}

/// The flow and what a poll or an await needs beside it.
pub(crate) enum Taken {
    Flow {
        flow: PubkyGrantAuthFlow,
        pending: Option<PendingGrantFlow>,
        cancelled: Arc<Notify>,
        started: Instant,
    },
    /// Another poll or await holds the flow right now — expired or not: that call decides it.
    Busy,
    Unknown,
}

/// Take `id`'s flow out of the map, sweeping expired flows on the way, so that every entry point
/// pays for the sweep and not only `start`.
///
/// An expired flow is handed out like any other: its caller looks in the channel once and only
/// then answers `expired` (see the module docs). Deciding it here, before that look, is how an
/// approval received at 4:59 and polled at 5:01 was lost.
pub(crate) fn take(id: &str) -> Taken {
    let ttl = limits().ttl;
    let mut flows = flows();
    // This id first, so a caller still polling an expired flow gets its look and its `Expired`
    // rather than finding it already swept; the others after.
    let taken = match flows.get_mut(id) {
        None => Taken::Unknown,
        Some(entry) => match entry.flow.take() {
            Some(flow) => Taken::Flow {
                flow,
                pending: entry.pending.clone(),
                cancelled: entry.cancelled.clone(),
                started: entry.started,
            },
            None => Taken::Busy,
        },
    };
    evict_expired(&mut flows, ttl);
    taken
}

fn unknown(id: &str) -> String {
    format!("No auth flow with id {id}")
}

/// Put a flow back, unless the entry was cancelled meanwhile — then the flow is dropped here,
/// which aborts its listener.
pub(crate) fn give_back(id: &str, flow: PubkyGrantAuthFlow) -> bool {
    let mut flows = flows();
    match flows.get_mut(id) {
        Some(entry) => {
            entry.flow = Some(flow);
            true
        }
        None => false,
    }
}

fn remove(id: &str) {
    flows().remove(id);
}

fn expired(started: Instant) -> bool {
    started.elapsed() > limits().ttl
}

#[cfg(test)]
pub(crate) static RESTORES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// A new listener on the same channel, for a flow whose previous one is gone.
fn restored(id: &str, pending: Option<&PendingGrantFlow>) -> Result<PubkyGrantAuthFlow, String> {
    let pending = pending.ok_or_else(|| format!("Auth flow {id} cannot be resumed"))?;
    if expired(pending.started) {
        return Err(format!("Auth flow {id} expired before it was approved"));
    }
    #[cfg(test)]
    RESTORES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    grant_resume::restore(pending).map_err(|error| {
        format!(
            "Failed to rejoin the relay channel for auth flow {id}: {}",
            full_error_chain(&error)
        )
    })
}

/// A restored flow put back as pending; a flow that cannot be restored is removed, one that
/// was cancelled meanwhile is dropped.
fn rejoined(id: &str, pending: Option<&PendingGrantFlow>) -> Result<Outcome, String> {
    match restored(id, pending) {
        Ok(flow) => {
            if give_back(id, flow) {
                Ok(Outcome::Pending)
            } else {
                Err(format!("Auth flow {id} was cancelled"))
            }
        }
        Err(message) => {
            remove(id);
            Err(message)
        }
    }
}

/// One non-blocking look at the relay. An approval ends the flow; anything else leaves it
/// pollable, a dead listener included — that one is rejoined on the spot.
///
/// A poll that finds the flow in another poll's or await's hands has nothing new to report and
/// says `Pending`: an approved poll is not short (the grant exchange is in it), the `[error, msg]`
/// contract cannot express "try again", and a host that reads any error as the sign-in failing
/// would drop a flow its other poll is about to complete (loopky#214).
pub async fn poll(id: &str) -> Result<Outcome, String> {
    let (flow, pending, started) = match take(id) {
        Taken::Flow {
            flow,
            pending,
            started,
            ..
        } => (flow, pending, started),
        Taken::Busy => return Ok(Outcome::Pending),
        Taken::Unknown => return Err(unknown(id)),
    };
    match flow.try_poll_once().await {
        Ok(Some(session)) => {
            remove(id);
            Ok(Outcome::Approved(session))
        }
        // Only after the look: an approval already in the channel is handed out, not expired.
        Ok(None) if expired(started) => {
            remove(id);
            Ok(Outcome::Expired)
        }
        Ok(None) => {
            if give_back(id, flow) {
                Ok(Outcome::Pending)
            } else {
                Err(format!("Auth flow {id} was cancelled"))
            }
        }
        Err(error)
            if pending
                .as_ref()
                .is_some_and(|p| grant_resume::is_relay_transport_failure(&error, &p.relay)) =>
        {
            if expired(started) {
                remove(id);
                return Ok(Outcome::Expired);
            }
            rejoined(id, pending.as_ref())
        }
        Err(error) => {
            remove(id);
            Err(format!(
                "Auth approval failed: {}",
                full_error_chain(&error)
            ))
        }
    }
}

/// Wait up to `timeout` for the approval, rejoining the relay channel if its listener dies the
/// way `await_grant_auth_approval` does. A timeout leaves the flow pending, so a caller may wait
/// again. Two awaits on one flow genuinely conflict, and the second is refused.
///
/// **The listener is never dropped on a timeout.** The SDK's listener acks the approval (a DELETE
/// on the relay inbox) before it hands it over, and dropping it aborts that task; a timeout that
/// lands between the two would leave a restored listener waiting on an inbox the relay has already
/// emptied, and a user who approved once never signed in. So the deadline is kept here, by
/// looking at the listener's channel until it passes, and the *same* flow goes back into the map.
pub async fn await_approval(id: &str, timeout: Duration) -> Result<Outcome, String> {
    let (mut flow, pending, cancelled, started) = match take(id) {
        Taken::Flow {
            flow,
            pending,
            cancelled,
            started,
        } => (flow, pending, cancelled, started),
        Taken::Busy => return Err(format!("Auth flow {id} is already being awaited")),
        Taken::Unknown => return Err(unknown(id)),
    };
    let deadline = Instant::now() + timeout;
    loop {
        match flow.try_poll_once().await {
            Ok(Some(session)) => {
                remove(id);
                return Ok(Outcome::Approved(session));
            }
            Ok(None) => {}
            Err(error)
                if pending.as_ref().is_some_and(|p| {
                    grant_resume::is_relay_transport_failure(&error, &p.relay)
                }) =>
            {
                if expired(started) {
                    remove(id);
                    return Ok(Outcome::Expired);
                }
                flow = match restored(id, pending.as_ref()) {
                    Ok(flow) => flow,
                    Err(message) => {
                        remove(id);
                        return Err(message);
                    }
                };
            }
            Err(error) => {
                remove(id);
                return Err(format!(
                    "Auth approval failed: {}",
                    full_error_chain(&error)
                ));
            }
        }
        if expired(started) {
            remove(id);
            return Ok(Outcome::Expired);
        }
        let now = Instant::now();
        if now >= deadline {
            return if give_back(id, flow) {
                Ok(Outcome::Pending)
            } else {
                Err(format!("Auth flow {id} was cancelled"))
            };
        }
        tokio::select! {
            () = tokio::time::sleep(AWAIT_POLL_INTERVAL.min(deadline - now)) => {}
            // `cancel` already removed the entry; returning drops the flow and its listener.
            () = cancelled.notified() => return Err(format!("Auth flow {id} was cancelled")),
        }
    }
}

/// Forget the flow and stop its listener. An await blocked on it returns cancelled.
pub fn cancel(id: &str) -> bool {
    sweep();
    let entry = flows().remove(id);
    match entry {
        Some(entry) => {
            entry.cancelled.notify_one();
            true
        }
        None => false,
    }
}

#[cfg(test)]
pub(crate) fn reset_for_tests() {
    flows().clear();
    configure(DEFAULT_MAX_FLOWS, DEFAULT_TTL);
}
