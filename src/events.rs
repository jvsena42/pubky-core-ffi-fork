use crate::{
    get_pubky_client, get_pubky_http_client, EventStreamConfig, PubkyCoreError, PubkyStorageEvent,
    TOKIO_RUNTIME,
};
use futures_util::{Stream, StreamExt};
use once_cell::sync::Lazy;
use pubky::{EventCursor, EventStreamBuilder, PublicKey};
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::task::JoinHandle;

static EVENT_STREAM_SEQUENCE: AtomicU64 = AtomicU64::new(1);
static EVENT_STREAM_TASKS: Lazy<Mutex<HashMap<String, JoinHandle<()>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[uniffi::export(callback_interface)]
pub trait PubkyEventStreamListener: Send + Sync {
    fn on_event(&self, event: PubkyStorageEvent);
    fn on_error(&self, message: String);
    fn on_complete(&self);
}

fn parse_public_key(value: &str, label: &str) -> Result<PublicKey, PubkyCoreError> {
    PublicKey::try_from(value).map_err(|error| PubkyCoreError::Validation {
        details: format!("invalid {label} public key: {error}"),
    })
}

/// Start a historical or live homeserver event subscription.
///
/// The returned ID owns the native stream task and must be passed to
/// `stop_event_stream` when the caller no longer wants events.
#[uniffi::export]
pub fn start_event_stream(
    config: EventStreamConfig,
    listener: Box<dyn PubkyEventStreamListener>,
) -> Result<String, PubkyCoreError> {
    TOKIO_RUNTIME.block_on(async {
        if config.users.is_empty() {
            return Err(PubkyCoreError::Validation {
                details: "at least one event-stream user is required".to_string(),
            });
        }

        let users = config
            .users
            .iter()
            .map(|user| {
                Ok((
                    parse_public_key(&user.public_key, "user")?,
                    user.cursor.map(EventCursor::new),
                ))
            })
            .collect::<Result<Vec<_>, PubkyCoreError>>()?;

        let mut builder = if let Some(homeserver) = config.homeserver.as_deref() {
            let homeserver = parse_public_key(homeserver, "homeserver")?;
            EventStreamBuilder::for_homeserver(get_pubky_http_client(), &homeserver)
                .add_users(users.iter().map(|(user, cursor)| (user, *cursor)))?
        } else {
            let (first_user, first_cursor) = &users[0];
            let builder =
                EventStreamBuilder::for_user(get_pubky_http_client(), first_user, *first_cursor);
            builder.add_users(users.iter().skip(1).map(|(user, cursor)| (user, *cursor)))?
        };

        for path in config.paths {
            builder = builder.path(path);
        }
        if let Some(limit) = config.limit {
            builder = builder.limit(limit);
        }
        if let Some(limit) = config.max_event_bytes {
            let limit = usize::try_from(limit).map_err(|_| PubkyCoreError::Validation {
                details: "max_event_bytes exceeds the platform limit".to_string(),
            })?;
            builder = builder.max_event_bytes(limit);
        }
        if config.live {
            builder = builder.live();
        }
        if config.reverse {
            builder = builder.reverse();
        }
        if let Some(secret) = config.session_secret {
            let session = get_pubky_client().restore_session(&secret).await?;
            builder = builder.session(&session);
        }

        let stream = builder.subscribe().await?.map(|result| {
            result
                .map(|event| PubkyStorageEvent {
                    event_type: event.event_type.as_str().to_string(),
                    resource: event.resource.to_pubky_url(),
                    cursor: event.cursor.id(),
                    content_hash: event
                        .event_type
                        .content_hash()
                        .map(|hash| hash.to_hex().to_string()),
                })
                .map_err(|error| error.to_string())
        });
        let listener: Arc<dyn PubkyEventStreamListener> = listener.into();
        let id = format!(
            "event-stream-{}",
            EVENT_STREAM_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let task_id = id.clone();
        let (start_tx, start_rx) = tokio::sync::oneshot::channel();
        let task = TOKIO_RUNTIME.spawn(async move {
            if start_rx.await.is_err() {
                return;
            }
            pump(stream, listener, task_id).await;
        });

        EVENT_STREAM_TASKS.lock().unwrap().insert(id.clone(), task);
        let _ = start_tx.send(());
        Ok(id)
    })
}

/// Drops the task's map entry however the task ends. With uniffi 0.25 a foreign listener that
/// throws *panics* the Rust side, and tokio swallows a panic in a spawned task — so without this
/// the finished `JoinHandle` stayed in the map and the host believed the stream was still live.
struct Registered(String);

impl Drop for Registered {
    fn drop(&mut self) {
        EVENT_STREAM_TASKS.lock().unwrap().remove(&self.0);
    }
}

/// Deliver `stream` to `listener` until it ends, then say so. A listener that throws ends the
/// stream — it is told why through `on_error`, if it will take that call — and never leaks the
/// entry under `id`.
pub(crate) async fn pump<S>(mut stream: S, listener: Arc<dyn PubkyEventStreamListener>, id: String)
where
    S: Stream<Item = Result<PubkyStorageEvent, String>> + Unpin,
{
    let _registered = Registered(id);
    while let Some(result) = stream.next().await {
        let delivery = match result {
            Ok(event) => catch_unwind(AssertUnwindSafe(|| listener.on_event(event))),
            Err(error) => {
                let _ = catch_unwind(AssertUnwindSafe(|| listener.on_error(error)));
                return;
            }
        };
        if delivery.is_err() {
            let _ = catch_unwind(AssertUnwindSafe(|| {
                listener.on_error("event listener threw; the stream is stopped".to_string())
            }));
            return;
        }
    }
    let _ = catch_unwind(AssertUnwindSafe(|| listener.on_complete()));
}

#[uniffi::export]
pub fn stop_event_stream(subscription_id: String) -> bool {
    match EVENT_STREAM_TASKS.lock().unwrap().remove(&subscription_id) {
        Some(task) => {
            task.abort();
            true
        }
        None => false,
    }
}

#[uniffi::export]
pub fn stop_all_event_streams() -> u64 {
    let mut tasks = EVENT_STREAM_TASKS.lock().unwrap();
    let count = tasks.len() as u64;
    for (_, task) in tasks.drain() {
        task.abort();
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// Throws from `on_event`, the way a foreign listener's exception arrives on this side.
    struct Throwing {
        events: AtomicUsize,
        errors: Mutex<Vec<String>>,
        completed: AtomicUsize,
    }

    impl PubkyEventStreamListener for Throwing {
        fn on_event(&self, _event: PubkyStorageEvent) {
            self.events.fetch_add(1, Ordering::SeqCst);
            panic!("Callback interface failure: the host listener threw");
        }
        fn on_error(&self, message: String) {
            self.errors.lock().unwrap().push(message);
        }
        fn on_complete(&self) {
            self.completed.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn event(cursor: u64) -> PubkyStorageEvent {
        PubkyStorageEvent {
            event_type: "PUT".to_string(),
            resource: "pubky://x/pub/y".to_string(),
            cursor,
            content_hash: None,
        }
    }

    #[test]
    fn a_throwing_listener_ends_the_stream_and_frees_its_entry() {
        let id = "event-stream-test-throwing".to_string();
        let placeholder = TOKIO_RUNTIME.spawn(std::future::pending::<()>());
        EVENT_STREAM_TASKS
            .lock()
            .unwrap()
            .insert(id.clone(), placeholder);
        let listener = Arc::new(Throwing {
            events: AtomicUsize::new(0),
            errors: Mutex::new(Vec::new()),
            completed: AtomicUsize::new(0),
        });
        let stream = futures_util::stream::iter(vec![Ok(event(1)), Ok(event(2))]);

        // The panic must not leave `pump`: in production it runs in a spawned task, where it
        // would be swallowed with the entry still in the map.
        TOKIO_RUNTIME.block_on(pump(stream, listener.clone(), id.clone()));

        assert_eq!(
            listener.events.load(Ordering::SeqCst),
            1,
            "stopped at the throw"
        );
        assert_eq!(listener.completed.load(Ordering::SeqCst), 0);
        assert_eq!(listener.errors.lock().unwrap().len(), 1);
        assert!(
            !EVENT_STREAM_TASKS.lock().unwrap().contains_key(&id),
            "the entry outlived the task"
        );
    }

    #[test]
    fn a_stream_error_frees_the_entry_too() {
        let id = "event-stream-test-error".to_string();
        let placeholder = TOKIO_RUNTIME.spawn(std::future::pending::<()>());
        EVENT_STREAM_TASKS
            .lock()
            .unwrap()
            .insert(id.clone(), placeholder);
        let listener = Arc::new(Throwing {
            events: AtomicUsize::new(0),
            errors: Mutex::new(Vec::new()),
            completed: AtomicUsize::new(0),
        });
        let stream = futures_util::stream::iter(vec![Err("relay gone".to_string())]);

        TOKIO_RUNTIME.block_on(pump(stream, listener.clone(), id.clone()));

        assert_eq!(listener.errors.lock().unwrap().as_slice(), ["relay gone"]);
        assert!(!EVENT_STREAM_TASKS.lock().unwrap().contains_key(&id));
    }
}
