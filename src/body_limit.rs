//! A ceiling on how much of a response body a read will hold in memory.
//!
//! A read materialises the whole body, uniffi copies it into a `RustBuffer`, and the JVM copies it
//! again into a `ByteArray` — so one fetch costs roughly three times the body in RSS, and the host
//! serving it is whatever the resolved pubky names. A hosted client whose tenants follow decks
//! from homeservers they choose (loopky#214) cannot let one of those pick the number.
//!
//! The limit is enforced twice: a declared `Content-Length` over it is refused before a byte is
//! read, and a body without one (or one that lies) is read chunk by chunk and refused the moment it
//! passes the limit. Error bodies are already bounded by the SDK's `max_error_body_bytes`.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::full_error_chain;

/// Comfortably above the largest record a consumer writes — Loopky caps a media file at 32 MiB
/// (`ApkgLimits.MAX_MEDIA_BYTES`) and a card chunk is text — and far below what a 512 MB container
/// can hold three copies of.
pub const DEFAULT_MAX_BODY_BYTES: u64 = 50 * 1024 * 1024;

static MAX_BODY_BYTES: AtomicU64 = AtomicU64::new(DEFAULT_MAX_BODY_BYTES);

/// Set how large a response body a byte-reading call (`get`, `get_bytes`, `public_get_bytes`,
/// `session_get_bytes`) will accept, and answer with the limit now in force. Zero is not a limit
/// and is ignored, so a caller can also use this to read the current value.
#[uniffi::export]
pub fn configure_max_body_bytes(max_bytes: u64) -> u64 {
    if max_bytes > 0 {
        MAX_BODY_BYTES.store(max_bytes, Ordering::SeqCst);
    }
    MAX_BODY_BYTES.load(Ordering::SeqCst)
}

pub(crate) fn max_body_bytes() -> u64 {
    MAX_BODY_BYTES.load(Ordering::SeqCst)
}

#[derive(Debug)]
pub(crate) enum BodyError {
    /// `declared` is the `Content-Length` when the refusal came from the header, `None` when the
    /// body passed the limit while being read.
    TooLarge {
        declared: Option<u64>,
        limit: u64,
    },
    Transport(reqwest::Error),
}

impl std::fmt::Display for BodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BodyError::TooLarge {
                declared: Some(declared),
                limit,
            } => write!(
                f,
                "response body of {declared} bytes exceeds the {limit}-byte limit"
            ),
            BodyError::TooLarge {
                declared: None,
                limit,
            } => write!(f, "response body exceeds the {limit}-byte limit"),
            BodyError::Transport(error) => f.write_str(&full_error_chain(error)),
        }
    }
}

impl std::error::Error for BodyError {}

/// The whole body of `response`, or a refusal once it is known to be over the configured limit.
pub(crate) async fn read_capped(response: reqwest::Response) -> Result<Vec<u8>, BodyError> {
    read_up_to(response, max_body_bytes()).await
}

pub(crate) async fn read_up_to(
    mut response: reqwest::Response,
    limit: u64,
) -> Result<Vec<u8>, BodyError> {
    if let Some(declared) = response.content_length() {
        if declared > limit {
            return Err(BodyError::TooLarge {
                declared: Some(declared),
                limit,
            });
        }
    }
    // Reserve what was declared (already known to fit), never the limit: the common body is a
    // few KB of JSON, and the limit is sized for the exception.
    let mut body =
        Vec::with_capacity(usize::try_from(response.content_length().unwrap_or(0)).unwrap_or(0));
    while let Some(chunk) = response.chunk().await.map_err(BodyError::Transport)? {
        if (body.len() as u64).saturating_add(chunk.len() as u64) > limit {
            return Err(BodyError::TooLarge {
                declared: None,
                limit,
            });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A server answering one request with `head` and then `body`, in one write each.
    async fn serve_once(head: &'static str, body: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0; 1024];
            let mut request = Vec::new();
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let read = stream.read(&mut buffer).await.unwrap();
                if read == 0 {
                    return;
                }
                request.extend_from_slice(&buffer[..read]);
            }
            stream.write_all(head.as_bytes()).await.unwrap();
            stream.write_all(&body).await.unwrap();
            stream.shutdown().await.ok();
        });
        format!("http://{address}/")
    }

    async fn get(url: &str) -> reqwest::Response {
        reqwest::Client::new().get(url).send().await.unwrap()
    }

    #[tokio::test]
    async fn a_declared_oversize_body_is_refused_before_it_is_read() {
        // The declared length is a lie the server never has to back up: nothing after the head
        // is sent, so reading it would hang — the refusal must come from the header alone.
        let url = serve_once(
            "HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\nConnection: close\r\n\r\n",
            Vec::new(),
        )
        .await;

        let error = read_up_to(get(&url).await, 1024).await.unwrap_err();

        assert!(
            matches!(
                error,
                BodyError::TooLarge {
                    declared: Some(999999999),
                    limit: 1024
                }
            ),
            "{error}"
        );
        assert_eq!(
            error.to_string(),
            "response body of 999999999 bytes exceeds the 1024-byte limit"
        );
    }

    #[tokio::test]
    async fn an_undeclared_body_is_refused_once_it_passes_the_limit() {
        // No Content-Length: the body is delimited by the connection closing, so nothing can be
        // known about its size until it has been read.
        let url = serve_once(
            "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n",
            vec![b'x'; 4096],
        )
        .await;

        let error = read_up_to(get(&url).await, 1024).await.unwrap_err();

        assert!(
            matches!(
                error,
                BodyError::TooLarge {
                    declared: None,
                    limit: 1024
                }
            ),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_body_within_the_limit_is_read_whole() {
        let url = serve_once(
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n",
            b"hello".to_vec(),
        )
        .await;

        let body = read_up_to(get(&url).await, 1024).await.unwrap();

        assert_eq!(body, b"hello");
    }

    #[test]
    fn zero_is_not_a_limit() {
        let before = configure_max_body_bytes(0);
        assert_eq!(before, DEFAULT_MAX_BODY_BYTES);
        assert_eq!(configure_max_body_bytes(1 << 20), 1 << 20);
        assert_eq!(configure_max_body_bytes(0), 1 << 20);
        configure_max_body_bytes(DEFAULT_MAX_BODY_BYTES);
    }
}
