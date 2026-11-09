//! Credential redaction for client-visible connector errors.
//!
//! Connector errors carry the upstream cause so clients can diagnose a bad
//! request or bad connection settings on their own. Clients may use a data
//! connection without being allowed to read its credentials, so every error a
//! reader returns passes through a [`Redactor`] built from the connection's
//! credentials before it leaves the connector. This is a safety net that does
//! not depend on what a third-party library or an upstream server chooses to
//! print.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use base64::Engine as _;
use futures::TryStreamExt as _;

use crate::api::connector::{BinaryQuery, DataReader, OutputStream, Query, QueryOptions, QueryOutput, TableInfo};
use crate::api::errors::ConnectorError;

/// REDACTED replaces every credential value found in a message.
pub const REDACTED: &str = "***";

/// TRUNCATION_MARKER ends a message cut by [`truncate_message`].
pub const TRUNCATION_MARKER: &str = "... (truncated)";

/// MIN_SECRET_LEN is the shortest credential value that is redacted. Shorter
/// values would mangle unrelated text in the message.
const MIN_SECRET_LEN: usize = 4;

/// PUBLIC_CREDENTIAL_KEYS lists credential keys that hold connection settings
/// rather than secrets. Their values may appear in client-visible errors so a
/// client can spot a wrong endpoint, bucket or username. Every key not listed
/// here is treated as a secret.
const PUBLIC_CREDENTIAL_KEYS: &[&str] = &[
    "USERNAME",
    "DATABASE",
    "CA_CERT",
    "AWS_S3_CA_CERT",
    "AWS_S3_BUCKET",
    "AWS_S3_ENDPOINT",
    "AWS_DEFAULT_REGION",
];

/// URI_CREDENTIAL_KEY holds a connection URI. Its host and path are public,
/// but an embedded password and credential-like query parameters are not.
const URI_CREDENTIAL_KEY: &str = "URI";

const USERNAME_KEY: &str = "USERNAME";
const PASSWORD_KEY: &str = "PASSWORD";

/// SENSITIVE_QUERY_PARAMS are substrings of URI query parameter names whose
/// values are treated as secrets, e.g. `password`, `sslpassword`, `token`,
/// `X-Amz-Signature`, `sig`.
const SENSITIVE_QUERY_PARAMS: &[&str] = &["pass", "pwd", "secret", "token", "key", "sig", "credential", "auth"];

/// Redactor removes known credential values from error messages.
#[derive(Clone, Default)]
pub struct Redactor {
    /// secrets is sorted longest first, so a secret that contains another
    /// one is replaced as a whole.
    secrets: Vec<String>,
}

impl fmt::Debug for Redactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Redactor")
            .field("secrets", &self.secrets.len())
            .finish()
    }
}

impl Redactor {
    /// new builds a redactor for the given secret values.
    pub fn new(secrets: impl IntoIterator<Item = String>) -> Self {
        let mut secrets: Vec<String> = secrets
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| s.len() >= MIN_SECRET_LEN)
            .collect();
        secrets.sort_unstable_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        secrets.dedup();
        Self { secrets }
    }

    /// from_credentials builds a redactor for a connection's credentials.
    /// Values of keys outside `PUBLIC_CREDENTIAL_KEYS` are secrets; for the
    /// `URI` key only the password and credential-like query parameters are.
    /// The HTTP Basic encoding of each username/password pair is included as
    /// well, in case an upstream server echoes the `Authorization` header.
    pub fn from_credentials(credentials: &HashMap<String, String>) -> Self {
        let mut secrets = Vec::new();
        for (key, value) in credentials {
            if key == URI_CREDENTIAL_KEY {
                collect_uri_secrets(value, &mut secrets);
            } else if !PUBLIC_CREDENTIAL_KEYS.contains(&key.as_str()) {
                secrets.push(value.clone());
            }
        }
        if let (Some(username), Some(password)) = (credentials.get(USERNAME_KEY), credentials.get(PASSWORD_KEY)) {
            secrets.push(basic_auth(username.trim(), password.trim()));
        }
        Self::new(secrets)
    }

    /// redact replaces known secrets and URL-embedded passwords in `message`.
    pub fn redact(&self, message: &str) -> String {
        let mut out = message.to_string();
        for secret in &self.secrets {
            if out.contains(secret.as_str()) {
                out = out.replace(secret.as_str(), REDACTED);
            }
        }
        let out = self.redact_cut_secrets(&out);
        redact_url_userinfo(&out)
    }

    /// redact_cut_secrets masks a partial secret left right before a
    /// [`TRUNCATION_MARKER`]. Connectors cap quoted upstream payloads before
    /// the redactor sees them, so the cut can fall inside a secret, leaving a
    /// prefix that no longer matches the whole value.
    fn redact_cut_secrets(&self, message: &str) -> String {
        let mut out = String::with_capacity(message.len());
        let mut rest = message;
        while let Some(idx) = rest.find(TRUNCATION_MARKER) {
            let head = &rest[..idx];
            let cut = self
                .secrets
                .iter()
                .filter_map(|secret| {
                    (1..secret.len())
                        .rev()
                        .find(|&k| secret.is_char_boundary(k) && head.ends_with(&secret[..k]))
                })
                .max()
                .unwrap_or(0);
            out.push_str(&head[..head.len() - cut]);
            if cut > 0 {
                out.push_str(REDACTED);
            }
            out.push_str(TRUNCATION_MARKER);
            rest = &rest[idx + TRUNCATION_MARKER.len()..];
        }
        out.push_str(rest);
        out
    }

    /// redact_error applies [`Redactor::redact`] to every message in `error`.
    pub fn redact_error(&self, error: ConnectorError) -> ConnectorError {
        error.map_messages(|m| self.redact(m))
    }
}

fn collect_uri_secrets(value: &str, secrets: &mut Vec<String>) {
    let Ok(url) = url::Url::parse(value.trim()) else {
        // An unparsable URI may still embed a password; keep it out entirely.
        secrets.push(value.to_string());
        return;
    };
    if let Some(password) = url.password() {
        let decoded = percent_decode(password);
        secrets.push(basic_auth(&percent_decode(url.username()), &decoded));
        secrets.push(password.to_string());
        secrets.push(decoded);
    }
    if let Some(query) = url.query() {
        for pair in query.split('&') {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            let name = percent_decode(name).to_ascii_lowercase();
            if SENSITIVE_QUERY_PARAMS.iter().any(|p| name.contains(p)) {
                secrets.push(value.to_string());
                secrets.push(percent_decode(&value.replace('+', " ")));
            }
        }
    }
}

fn basic_auth(username: &str, password: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"))
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_value(bytes[i + 1]), hex_value(bytes[i + 2]))
        {
            out.push(hi << 4 | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// redact_url_userinfo masks the password of every `scheme://user:password@`
/// URL in `message`, keeping the scheme, username and host. It needs no
/// knowledge of the credentials, so it also guards messages that never went
/// through a [`Redactor`].
pub fn redact_url_userinfo(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let mut rest = message;
    while let Some(idx) = rest.find("://") {
        let (head, tail) = rest.split_at(idx + 3);
        out.push_str(head);
        let end = tail
            .find(|c: char| matches!(c, '/' | '?' | '#' | '"' | '<' | '>' | '`') || c.is_whitespace())
            .unwrap_or(tail.len());
        let authority = &tail[..end];
        match authority
            .rfind('@')
            .and_then(|at| authority[..at].find(':').map(|colon| (colon, at)))
        {
            Some((colon, at)) => {
                out.push_str(&authority[..=colon]);
                out.push_str(REDACTED);
                out.push_str(&authority[at..]);
            },
            None => out.push_str(authority),
        }
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// truncate_message caps `message` at `max_bytes`, cutting on a character
/// boundary and marking the cut, so an oversized upstream payload cannot
/// overflow the transport's error metadata.
pub fn truncate_message(message: &str, max_bytes: usize) -> String {
    if message.len() <= max_bytes {
        return message.to_string();
    }
    let mut end = max_bytes;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{TRUNCATION_MARKER}", &message[..end])
}

/// RedactingReader wraps a [`DataReader`] and redacts every error it returns,
/// including errors yielded by its output streams.
pub struct RedactingReader<R> {
    inner: R,
    redactor: Arc<Redactor>,
}

impl<R> RedactingReader<R> {
    pub fn new(inner: R, redactor: Arc<Redactor>) -> Self {
        Self { inner, redactor }
    }

    fn redact(&self, error: ConnectorError) -> ConnectorError {
        self.redactor.redact_error(error)
    }

    fn redact_stream(&self, stream: OutputStream) -> OutputStream {
        let redactor = Arc::clone(&self.redactor);
        Box::pin(stream.map_err(move |e| redactor.redact_error(e)))
    }
}

#[async_trait::async_trait]
impl<R: DataReader> DataReader for RedactingReader<R> {
    fn provider(&self) -> String {
        self.inner.provider()
    }

    async fn schema(&self, query: &str) -> Result<Arc<Query>, ConnectorError> {
        self.inner.schema(query).await.map_err(|e| self.redact(e))
    }

    async fn read_tabular(&self, query: Arc<Query>, options: &QueryOptions) -> QueryOutput {
        let stream = self
            .inner
            .read_tabular(query, options)
            .await
            .map_err(|e| self.redact(e))?;
        Ok(self.redact_stream(stream))
    }

    async fn can_read_binary(&self, query: Arc<BinaryQuery>) -> Result<(), ConnectorError> {
        self.inner.can_read_binary(query).await.map_err(|e| self.redact(e))
    }

    async fn read_binary(&self, query: Arc<BinaryQuery>) -> QueryOutput {
        let stream = self.inner.read_binary(query).await.map_err(|e| self.redact(e))?;
        Ok(self.redact_stream(stream))
    }

    async fn check_connection(&self) -> Result<(), ConnectorError> {
        self.inner.check_connection().await.map_err(|e| self.redact(e))
    }

    async fn list_tables(
        &self,
        table_name_filter: Option<&str>,
        include_schema: bool,
    ) -> Result<Vec<TableInfo>, ConnectorError> {
        self.inner
            .list_tables(table_name_filter, include_schema)
            .await
            .map_err(|e| self.redact(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::datatypes::Schema;
    use futures::StreamExt as _;

    fn creds(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn redacts_secret_keys_and_keeps_public_ones() {
        let r = Redactor::from_credentials(&creds(&[
            ("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE"),
            ("AWS_SECRET_ACCESS_KEY", "s3cr3t/key+value"),
            ("AWS_S3_BUCKET", "my-bucket"),
            ("AWS_S3_ENDPOINT", "https://s3.example.com"),
        ]));
        let out = r.redact("AKIAEXAMPLE s3cr3t/key+value my-bucket https://s3.example.com");
        assert_eq!(out, "*** *** my-bucket https://s3.example.com");
    }

    #[test]
    fn unknown_keys_are_secret() {
        let r = Redactor::from_credentials(&creds(&[("SOME_NEW_FIELD", "opaque-value")]));
        assert_eq!(r.redact("got opaque-value"), "got ***");
    }

    #[test]
    fn trims_secret_values() {
        let r = Redactor::from_credentials(&creds(&[("TOKEN", "tok-123\n")]));
        assert_eq!(r.redact("Bearer tok-123"), "Bearer ***");
    }

    #[test]
    fn skips_very_short_values() {
        let r = Redactor::from_credentials(&creds(&[("PASSWORD", "abc")]));
        assert_eq!(r.redact("abcdef"), "abcdef");
    }

    #[test]
    fn redacts_longest_secret_first() {
        let r = Redactor::new(["secret".to_string(), "secret-and-more".to_string()]);
        assert_eq!(r.redact("x secret-and-more y secret"), "x *** y ***");
    }

    #[test]
    fn uri_keeps_host_and_redacts_password() {
        let r = Redactor::from_credentials(&creds(&[("URI", "postgres://alice:p%40ss@db.example.com:5432/app")]));
        assert_eq!(
            r.redact("connect to db.example.com:5432 as alice failed, password p@ss"),
            "connect to db.example.com:5432 as alice failed, password ***"
        );
        assert_eq!(
            r.redact("postgres://alice:p%40ss@db.example.com:5432/app"),
            "postgres://alice:***@db.example.com:5432/app"
        );
    }

    #[test]
    fn uri_redacts_sensitive_query_params() {
        let r = Redactor::from_credentials(&creds(&[(
            "URI",
            "https://files.example.com/data.csv?X-Amz-Signature=abcd1234&region=us-east-1&sslpassword=hunter22",
        )]));
        let out = r.redact("GET data.csv?X-Amz-Signature=abcd1234&region=us-east-1 hunter22");
        assert_eq!(out, "GET data.csv?X-Amz-Signature=***&region=us-east-1 ***");
    }

    #[test]
    fn unparsable_uri_is_secret() {
        let r = Redactor::from_credentials(&creds(&[("URI", "not a uri with secret")]));
        assert_eq!(r.redact("bad: not a uri with secret"), "bad: ***");
    }

    #[test]
    fn redacts_basic_auth_encoding() {
        let r = Redactor::from_credentials(&creds(&[("USERNAME", "elastic"), ("PASSWORD", "changeme")]));
        let echoed = format!("Authorization: Basic {}", basic_auth("elastic", "changeme"));
        assert_eq!(r.redact(&echoed), "Authorization: Basic ***");

        let r = Redactor::from_credentials(&creds(&[("URI", "https://bob:pa%3Ass@es:9200")]));
        let echoed = format!("Authorization: Basic {}", basic_auth("bob", "pa:ss"));
        assert_eq!(r.redact(&echoed), "Authorization: Basic ***");
    }

    #[test]
    fn debug_does_not_print_secrets() {
        let r = Redactor::new(["topsecret".to_string()]);
        assert!(!format!("{r:?}").contains("topsecret"));
    }

    #[test]
    fn url_userinfo_is_masked_without_credentials() {
        assert_eq!(
            redact_url_userinfo("error sending request for url (https://u:p@w,d@host:9200/_search)"),
            "error sending request for url (https://u:***@host:9200/_search)"
        );
        assert_eq!(redact_url_userinfo("see http://host/a@b:c"), "see http://host/a@b:c");
        assert_eq!(
            redact_url_userinfo("user only http://u@host"),
            "user only http://u@host"
        );
        assert_eq!(redact_url_userinfo("no url here"), "no url here");
        assert_eq!(
            redact_url_userinfo("a://x:y@h b://x2:y2@h2"),
            "a://x:***@h b://x2:***@h2"
        );
    }

    #[test]
    fn truncates_on_char_boundary() {
        assert_eq!(truncate_message("short", 10), "short");
        assert_eq!(truncate_message("héllo", 2), "h... (truncated)");
    }

    #[test]
    fn redacts_secret_cut_by_truncation() {
        let r = Redactor::new(["AKIAEXAMPLESECRET".to_string()]);
        let cut = truncate_message("Credential=AKIAEXAMPLESECRET/2026", 17);
        assert_eq!(cut, "Credential=AKIAEX... (truncated)");
        assert_eq!(r.redact(&cut), "Credential=***... (truncated)");
        assert_eq!(
            r.redact("a: Credential=AKIA... (truncated), b: fine... (truncated)"),
            "a: Credential=***... (truncated), b: fine... (truncated)"
        );
    }

    #[test]
    fn redact_error_covers_internal_detail() {
        let r = Redactor::new(["topsecret".to_string()]);
        let e = r.redact_error(ConnectorError::internal("ctx topsecret", "detail topsecret"));
        assert!(matches!(e, ConnectorError::Internal { ref context, ref detail }
            if context == "ctx ***" && detail == "detail ***"));
    }

    struct FailingReader;

    #[async_trait::async_trait]
    impl DataReader for FailingReader {
        fn provider(&self) -> String {
            "test".to_string()
        }

        async fn schema(&self, _query: &str) -> Result<Arc<Query>, ConnectorError> {
            Err(ConnectorError::SQLError("bad topsecret".to_string()))
        }

        async fn read_tabular(&self, _query: Arc<Query>, _options: &QueryOptions) -> QueryOutput {
            Ok(Box::pin(futures::stream::iter(vec![Err(ConnectorError::IOError(
                "stream topsecret".to_string(),
            ))])))
        }

        async fn check_connection(&self) -> Result<(), ConnectorError> {
            Err(ConnectorError::ConnectionError("conn topsecret".to_string()))
        }
    }

    #[tokio::test]
    async fn redacting_reader_redacts_calls_and_streams() {
        let reader = RedactingReader::new(FailingReader, Arc::new(Redactor::new(["topsecret".to_string()])));

        assert_eq!(reader.schema("q").await.err().unwrap().message(), "bad ***");
        assert_eq!(reader.check_connection().await.unwrap_err().message(), "conn ***");

        let query = Arc::new(Query::new("q".to_string(), Arc::new(Schema::empty())));
        let mut stream = reader.read_tabular(query, &QueryOptions::default()).await.unwrap();
        assert_eq!(stream.next().await.unwrap().unwrap_err().message(), "stream ***");

        let err = reader
            .read_binary(Arc::new(BinaryQuery::new("p".to_string())))
            .await
            .err()
            .unwrap();
        assert!(matches!(err, ConnectorError::UnsupportedOperation(_)));
    }
}
