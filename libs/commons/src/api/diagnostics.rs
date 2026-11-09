//! Helpers that turn upstream failures into concise, client-actionable error
//! messages. See [`crate::api::errors::ConnectorError`] for what a message may
//! contain.

use std::error::Error;

use crate::api::redact::truncate_message;

/// MAX_BODY_EXCERPT_BYTES caps how much of an upstream response body is quoted
/// in an error message.
pub const MAX_BODY_EXCERPT_BYTES: usize = 256;

/// error_chain renders `error` followed by each of its sources, skipping
/// sources whose text is already part of the message. Many clients, reqwest
/// among them, print only a generic summary at the top level ("error sending
/// request") and keep the actual cause ("Connection refused", "invalid peer
/// certificate") in the source chain.
pub fn error_chain(error: &(dyn Error + 'static)) -> String {
    let mut out = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        let text = cause.to_string();
        if !text.is_empty() && !out.contains(&text) {
            out.push_str(": ");
            out.push_str(&text);
        }
        source = cause.source();
    }
    out
}

/// body_excerpt condenses an upstream response body for quoting in an error
/// message: whitespace runs collapse to one space and the result is capped
/// at [`MAX_BODY_EXCERPT_BYTES`].
pub fn body_excerpt(body: &str) -> String {
    let condensed = body.split_whitespace().collect::<Vec<_>>().join(" ");
    if condensed.is_empty() {
        return "empty response body".to_string();
    }
    truncate_message(&condensed, MAX_BODY_EXCERPT_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt;

    #[derive(Debug)]
    struct Layer(&'static str, Option<Box<Layer>>);

    impl fmt::Display for Layer {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }

    impl Error for Layer {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            self.1.as_deref().map(|l| l as &(dyn Error + 'static))
        }
    }

    #[test]
    fn error_chain_appends_sources() {
        let e = Layer(
            "error sending request",
            Some(Box::new(Layer(
                "client error (Connect)",
                Some(Box::new(Layer("Connection refused", None))),
            ))),
        );
        assert_eq!(
            error_chain(&e),
            "error sending request: client error (Connect): Connection refused"
        );
    }

    #[test]
    fn error_chain_skips_repeated_sources() {
        let e = Layer("io error: timed out", Some(Box::new(Layer("timed out", None))));
        assert_eq!(error_chain(&e), "io error: timed out");
    }

    #[test]
    fn body_excerpt_condenses_and_caps() {
        assert_eq!(body_excerpt("  <h1>Bad\n\n  Gateway</h1>  "), "<h1>Bad Gateway</h1>");
        assert_eq!(body_excerpt(" \n "), "empty response body");
        let long = "x".repeat(1000);
        assert!(body_excerpt(&long).len() < MAX_BODY_EXCERPT_BYTES + 32);
    }
}
