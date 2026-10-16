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
//! an approval for.

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
}

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

/// Drop every flow older than the TTL that is not inside an await. One that is gets its chance
/// when the await returns: the restore it attempts on timeout refuses an expired flow.
fn evict_expired(flows: &mut HashMap<String, FlowEntry>, ttl: Duration) {
    flows.retain(|_, entry| entry.flow.is_none() || entry.started.elapsed() <= ttl);
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
        if flows.len() >= max_flows {
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
    if flows.len() >= max_flows {
        return Err(format!(
            "Too many pending auth flows: {max_flows} already waiting for approval"
        ));
    }
    flows.insert(id.clone(), entry);
    Ok((id, authorization_url))
}

/// The flow and what an await needs beside it. Fails for an unknown id and for one whose flow
/// another call is currently holding.
fn take(id: &str) -> Result<(PubkyGrantAuthFlow, Option<PendingGrantFlow>, Arc<Notify>), String> {
    let mut flows = flows();
    let entry = flows
        .get_mut(id)
        .ok_or_else(|| format!("No auth flow with id {id}"))?;
    let flow = entry
        .flow
        .take()
        .ok_or_else(|| format!("Auth flow {id} is already being awaited"))?;
    Ok((flow, entry.pending.clone(), entry.cancelled.clone()))
}

/// Put a flow back, unless the entry was cancelled meanwhile — then the flow is dropped here,
/// which aborts its listener.
fn give_back(id: &str, flow: PubkyGrantAuthFlow) -> bool {
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

/// A new listener on the same channel, for a flow whose previous one is gone.
fn restored(id: &str, pending: Option<&PendingGrantFlow>) -> Result<PubkyGrantAuthFlow, String> {
    let pending = pending.ok_or_else(|| format!("Auth flow {id} cannot be resumed"))?;
    if expired(pending.started) {
        return Err(format!("Auth flow {id} expired before it was approved"));
    }
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
pub async fn poll(id: &str) -> Result<Outcome, String> {
    let (flow, pending, _) = take(id)?;
    match flow.try_poll_once().await {
        Ok(Some(session)) => {
            remove(id);
            Ok(Outcome::Approved(session))
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

/// Wait up to `timeout` for the approval, rejoining the relay channel if its poll dies the way
/// `await_grant_auth_approval` does. A timeout leaves the flow pending — it is restored from its
/// saved state, since dropping the future dropped the listener — so a caller may wait again.
pub async fn await_approval(id: &str, timeout: Duration) -> Result<Outcome, String> {
    let (flow, pending, cancelled) = take(id)?;
    let waiting = tokio::time::timeout(
        timeout,
        grant_resume::await_with(flow, pending.clone(), &|_| true, &|_| {}),
    );
    tokio::select! {
        result = waiting => match result {
            Ok(Ok(session)) => {
                remove(id);
                Ok(Outcome::Approved(session))
            }
            Ok(Err(error)) => {
                remove(id);
                Err(format!("Auth approval failed: {}", full_error_chain(&error)))
            }
            Err(_elapsed) => rejoined(id, pending.as_ref()),
        },
        // Dropping `waiting` aborts the listener; `cancel` already removed the entry.
        () = cancelled.notified() => Err(format!("Auth flow {id} was cancelled")),
    }
}

/// Forget the flow and stop its listener. An await blocked on it returns cancelled.
pub fn cancel(id: &str) -> bool {
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
