use thiserror::Error;

/// Only connector implementations should emit this error.
///
/// The message of every variant except [`ConnectorError::Internal`] is
/// returned to the client verbatim, so it should name the cause precisely
/// enough for the client to fix the request or the connection settings.
/// Endpoints, hosts, buckets, paths and usernames may appear in it;
/// credentials (passwords, tokens, keys, signed URLs) and DCH internals
/// (namespaces, Secret names, local file paths) must not. Readers are wrapped
/// in a [`crate::api::redact::RedactingReader`] that strips known credential
/// values as a safety net, but it is not a license to format raw upstream
/// payloads into the message. Use `Internal` for failures the client cannot
/// act on.
#[derive(Error, Debug, Clone)]
pub enum ConnectorError {
    #[error("SQL error: {0}")]
    SQLError(String),
    #[error("Connection error: {0}")]
    ConnectionError(String),
    #[error("No data returned")]
    NoDataError,
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    #[error("Config error: {0}")]
    ConfigError(String),
    #[error("IO error: {0}")]
    IOError(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),
    /// A failure the client cannot act on. Only `context` is returned to the
    /// client; `detail` is written to the service log.
    #[error("{context}: {detail}")]
    Internal { context: String, detail: String },
}

impl ConnectorError {
    /// internal builds an [`ConnectorError::Internal`] whose `detail` is kept
    /// out of the client response.
    pub fn internal(context: impl Into<String>, detail: impl std::fmt::Display) -> Self {
        Self::Internal {
            context: context.into(),
            detail: detail.to_string(),
        }
    }

    /// message returns the client-visible part of the error.
    pub fn message(&self) -> &str {
        match self {
            Self::SQLError(m)
            | Self::ConnectionError(m)
            | Self::InvalidRequest(m)
            | Self::ConfigError(m)
            | Self::IOError(m)
            | Self::NotFound(m)
            | Self::UnsupportedOperation(m) => m,
            Self::NoDataError => "no data returned",
            Self::Internal { context, .. } => context,
        }
    }

    /// map_messages rewrites every message the error carries, including the
    /// log-only `detail` of [`ConnectorError::Internal`], keeping the variant.
    pub fn map_messages(self, f: impl Fn(&str) -> String) -> Self {
        match self {
            Self::SQLError(m) => Self::SQLError(f(&m)),
            Self::ConnectionError(m) => Self::ConnectionError(f(&m)),
            Self::InvalidRequest(m) => Self::InvalidRequest(f(&m)),
            Self::ConfigError(m) => Self::ConfigError(f(&m)),
            Self::IOError(m) => Self::IOError(f(&m)),
            Self::NotFound(m) => Self::NotFound(f(&m)),
            Self::UnsupportedOperation(m) => Self::UnsupportedOperation(f(&m)),
            Self::NoDataError => Self::NoDataError,
            Self::Internal { context, detail } => Self::Internal {
                context: f(&context),
                detail: f(&detail),
            },
        }
    }
}

/// Only meta store implementations should emit this error.
#[derive(Error, Debug)]
pub enum MetaStoreError {
    #[error("Connection error: {0}")]
    Connection(String),
    #[error("Not found: {0}")]
    ResourceNotFound(String),
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    #[error("Config error: {0}")]
    Config(String),
    #[error("Query error: {0}")]
    Query(String),
    #[error("Resource conflict: {0}")]
    Conflict(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Deserialization error: {0}")]
    Deserialization(String),
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("Unprocessable entity: {0}")]
    UnprocessableEntity(String),
}

/// Only secret store implementations should emit this error.
#[derive(Error, Debug, Clone)]
pub enum SecretStoreError {
    #[error("Secret not found: {0}")]
    SecretNotFound(String),
    #[error("Access denied: {0}")]
    Forbidden(String),
    #[error("Cannot create secret: {0}")]
    CannotCreateSecret(String),
    #[error("Cannot delete secret: {0}")]
    CannotDeleteSecret(String),
    #[error("Cannot set secret labels: {0}")]
    CannotSetSecretLabels(String),
}

/// Errors pertainint to data connection types.
#[derive(Error, Debug)]
pub enum DataConnectionTypeError {
    #[error("Required field {0} is missing")]
    MissingRequiredField(String),
    #[error("{field} must not be empty or whitespace-only{}", index.map(|i| format!(" (index {i})")).unwrap_or_default())]
    EmptyValue { field: &'static str, index: Option<usize> },
}
