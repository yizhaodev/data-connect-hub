use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arrow::array::BinaryArray;
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use commons::api::connections::{DataConnectionResource, DataFormat};
use commons::api::connector::{BinaryQuery, CredentialsResolver};
use commons::api::connector::{DataReader, FlightConnector, Query, QueryOptions, QueryOutput, TableInfo};
use commons::api::diagnostics::{body_excerpt, error_chain};
use commons::api::errors::ConnectorError;
use commons::api::redact::{RedactingReader, Redactor};
use commons::utils::config::ConnectorConfig;
use format_readers::FileFormat;
use futures::TryStreamExt;
use moka::future::Cache;
use opendal::{EntryMode, HttpTransporter, OperationContext, Operator, Reader, layers::TimeoutLayer, services::S3};
use opendal_http_transport_reqwest::ReqwestTransport;
use reqwest_opendal::{Certificate, Client};

const KEY_BUCKET: &str = "AWS_S3_BUCKET";
const KEY_ACCESS_KEY_ID: &str = "AWS_ACCESS_KEY_ID";
const KEY_SECRET_ACCESS_KEY: &str = "AWS_SECRET_ACCESS_KEY";
const KEY_REGION: &str = "AWS_DEFAULT_REGION";
const KEY_ENDPOINT: &str = "AWS_S3_ENDPOINT";
const KEY_CA_CERT: &str = "AWS_S3_CA_CERT";

pub struct S3Connector {
    operators: Cache<String, (Operator, Arc<Redactor>)>,
    config: ConnectorConfig,
}

impl S3Connector {
    pub fn new(cache_ttl: Duration, cache_idle: Duration, cache_max_capacity: u64, config: ConnectorConfig) -> Self {
        Self {
            operators: Cache::builder()
                .time_to_live(cache_ttl)
                .time_to_idle(cache_idle)
                .max_capacity(cache_max_capacity)
                .build(),
            config,
        }
    }

    /// insert_operator caches a prebuilt operator for a connection. The
    /// operator carries no credentials known to DCH, so its errors only get
    /// URL passwords masked.
    pub async fn insert_operator(&self, connection_id: &str, operator: Operator) {
        self.operators
            .insert(connection_id.to_string(), (operator, Arc::new(Redactor::default())))
            .await;
    }
}

fn build_http_transport(ca_cert: &str) -> Result<HttpTransporter, ConnectorError> {
    let certificates = Certificate::from_pem_bundle(ca_cert.as_bytes()).map_err(|error| {
        ConnectorError::ConfigError(format!(
            "{KEY_CA_CERT} contains invalid PEM data: {}",
            error_chain(&error)
        ))
    })?;

    if certificates.is_empty() {
        return Err(ConnectorError::ConfigError(format!(
            "{KEY_CA_CERT} must contain at least one certificate"
        )));
    }

    let mut client_builder = Client::builder();
    for certificate in certificates {
        client_builder = client_builder.add_root_certificate(certificate);
    }

    let client = client_builder.build().map_err(|error| {
        ConnectorError::ConfigError(format!("failed to configure S3 TLS client: {}", error_chain(&error)))
    })?;

    Ok(HttpTransporter::new(ReqwestTransport::new(client)))
}

fn resolve_region(credentials: &HashMap<String, String>) -> String {
    if let Some(region) = credentials.get(KEY_REGION).map(|v| v.trim()).filter(|v| !v.is_empty()) {
        return region.to_string();
    }
    "us-east-1".to_string()
}

fn build_operator(
    credentials: &HashMap<String, String>,
    connection_timeout: Duration,
    io_timeout: Duration,
) -> Result<Operator, ConnectorError> {
    let bucket = credentials
        .get(KEY_BUCKET)
        .ok_or_else(|| ConnectorError::ConfigError(format!("{KEY_BUCKET} is required")))?;

    let access_key = credentials
        .get(KEY_ACCESS_KEY_ID)
        .ok_or_else(|| ConnectorError::ConfigError(format!("{KEY_ACCESS_KEY_ID} is required")))?;

    let secret_key = credentials
        .get(KEY_SECRET_ACCESS_KEY)
        .ok_or_else(|| ConnectorError::ConfigError(format!("{KEY_SECRET_ACCESS_KEY} is required")))?;

    let region = resolve_region(credentials);
    let mut builder = S3::default()
        .bucket(bucket)
        .access_key_id(access_key)
        .secret_access_key(secret_key)
        .region(&region);

    if let Some(endpoint) = credentials
        .get(KEY_ENDPOINT)
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
    {
        builder = builder.endpoint(endpoint);
    }

    let mut op = Operator::new(builder).map_err(|e| {
        tracing::error!(error = %e, "failed to create S3 operator");
        ConnectorError::ConnectionError(format!("failed to create S3 operator: {e}"))
    })?;

    if let Some(ca_cert) = credentials.get(KEY_CA_CERT).filter(|value| !value.trim().is_empty()) {
        let transport = build_http_transport(ca_cert)?;
        op = op.with_context(OperationContext::new().with_http_transport(transport));
    }

    let op = op.layer(
        TimeoutLayer::new()
            .with_timeout(connection_timeout)
            .with_io_timeout(io_timeout),
    );
    Ok(op)
}

/// map_opendal_error classifies an OpenDAL error for `path` and keeps the S3
/// reason, e.g. `NoSuchBucket` or `SignatureDoesNotMatch`, or the transport
/// cause such as a refused connection. `action` names the failed operation.
fn map_opendal_error(e: opendal::Error, action: &str, path: &str) -> ConnectorError {
    tracing::error!(path, error = %e, "{action}");
    let detail = opendal_detail(&e);
    let with_detail = |text: String| {
        if detail.is_empty() {
            text
        } else {
            format!("{text} ({detail})")
        }
    };
    match e.kind() {
        opendal::ErrorKind::NotFound => ConnectorError::NotFound(with_detail(format!("'{path}' not found"))),
        opendal::ErrorKind::PermissionDenied => {
            ConnectorError::ConnectionError(with_detail(format!("access denied for '{path}'")))
        },
        opendal::ErrorKind::IsADirectory
        | opendal::ErrorKind::NotADirectory
        | opendal::ErrorKind::RangeNotSatisfied => {
            ConnectorError::InvalidRequest(with_detail(format!("{action} '{path}' failed: {}", e.kind())))
        },
        opendal::ErrorKind::Unsupported => {
            ConnectorError::UnsupportedOperation(with_detail(format!("{action} '{path}' is not supported")))
        },
        // Network failures, timeouts, throttling and invalid settings: the
        // storage could not serve the request.
        kind => ConnectorError::ConnectionError(with_detail(format!("{action} '{path}' failed: {kind}"))),
    }
}

/// opendal_detail renders the client-relevant part of an OpenDAL error: the
/// S3 error code and message, or the transport cause from the source chain.
/// The error's context is left out on purpose; it dumps the request URI and
/// the full response head, which belong in the log only.
fn opendal_detail(e: &opendal::Error) -> String {
    let mut parts = Vec::new();
    let message = e.message().trim();
    if !message.is_empty() {
        parts.push(s3_error_summary(message).unwrap_or_else(|| body_excerpt(message)));
    }
    if let Some(source) = std::error::Error::source(e) {
        parts.push(error_chain(source));
    }
    parts.join(": ")
}

/// s3_error_summary extracts `Code: Message` from OpenDAL's rendering of a
/// parsed S3 error response (`S3Error { code: "...", message: "...", ... }`).
fn s3_error_summary(message: &str) -> Option<String> {
    let field = |name: &str| {
        let start = message.find(&format!("{name}: \""))? + name.len() + 3;
        let end = start + message[start..].find('"')?;
        Some(&message[start..end])
    };
    if !message.starts_with("S3Error {") {
        return None;
    }
    let code = field("code")?;
    Some(match field("message").filter(|m| !m.is_empty()) {
        Some(text) => format!("{code}: {text}"),
        None => code.to_string(),
    })
}

const MAX_JSON_BYTES: u64 = 128 * 1024 * 1024;

async fn read_json_checked(operator: &Operator, path: &str) -> Result<Vec<u8>, ConnectorError> {
    let reader = operator
        .reader(path)
        .await
        .map_err(|e| map_opendal_error(e, "open", path))?;

    let mut stream = reader
        .into_stream(..)
        .await
        .map_err(|e| map_opendal_error(e, "read", path))?;

    let mut bytes = Vec::new();
    while let Some(buf) = stream
        .try_next()
        .await
        .map_err(|e| map_opendal_error(e, "read", path))?
    {
        let chunk = buf.to_bytes();
        if bytes.len() as u64 + chunk.len() as u64 > MAX_JSON_BYTES {
            return Err(ConnectorError::IOError(format!(
                "JSON file too large (limit {MAX_JSON_BYTES} bytes)"
            )));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

const PROVIDER: &str = "s3";

#[async_trait::async_trait]
impl FlightConnector for S3Connector {
    fn provider(&self) -> String {
        PROVIDER.to_string()
    }

    fn description(&self) -> String {
        "Amazon compatible S3 connector".to_string()
    }

    fn supported_formats(&self) -> Vec<DataFormat> {
        vec![DataFormat::Tabular, DataFormat::Binary]
    }

    #[tracing::instrument(
        skip_all,
        fields(
        connector.provider = PROVIDER,
        connection.id = %data_connection.metadata.id,
        )
    )]
    async fn get_reader(
        &self,
        data_connection: &DataConnectionResource,
        credentials_resolver: &dyn CredentialsResolver,
    ) -> Result<Arc<dyn DataReader>, ConnectorError> {
        let connection_timeout = self.config.connection_timeout();
        let io_timeout = self.config.read_timeout();
        let cache_key = data_connection.metadata.id.clone();

        let (operator, redactor) = self
            .operators
            .try_get_with(cache_key, async {
                let credentials = credentials_resolver.resolve(data_connection).await?;
                let redactor = Arc::new(Redactor::from_credentials(&credentials));
                build_operator(&credentials, connection_timeout, io_timeout)
                    .map(|client| (client, Arc::clone(&redactor)))
                    .map_err(|e| redactor.redact_error(e))
            })
            .await
            .map_err(|e| Arc::try_unwrap(e).unwrap_or_else(|arc| (*arc).clone()))?;

        let format_hint = data_connection.resource.properties.get("format").cloned();
        let reader = S3Reader {
            operator,
            format_hint,
            config: self.config,
            json_cache: Mutex::new(None),
        };
        Ok(Arc::new(RedactingReader::new(reader, redactor)))
    }
}

pub struct S3Reader {
    operator: Operator,
    format_hint: Option<String>,
    config: ConnectorConfig,
    json_cache: Mutex<Option<(String, Vec<u8>)>>,
}

impl S3Reader {
    fn detect_format(&self, path: &str) -> Result<FileFormat, ConnectorError> {
        FileFormat::detect(path, self.format_hint.as_deref())
    }

    async fn make_reader(&self, path: &str) -> Result<Reader, ConnectorError> {
        let reader = self
            .operator
            .reader_with(path)
            .chunk(self.config.chunk_size)
            .await
            .map_err(|e| map_opendal_error(e, "open", path))?;
        Ok(reader)
    }
}

#[async_trait::async_trait]
impl DataReader for S3Reader {
    fn provider(&self) -> String {
        PROVIDER.to_string()
    }

    #[tracing::instrument(skip_all, fields(connector.provider = PROVIDER))]
    async fn schema(&self, query: &str) -> Result<Arc<Query>, ConnectorError> {
        let format = self.detect_format(query)?;

        let schema = match format {
            FileFormat::Parquet => format_readers::read_parquet_schema(self.make_reader(query).await?).await?,
            FileFormat::Csv => format_readers::read_csv_schema(self.make_reader(query).await?).await?,
            FileFormat::JsonLines => format_readers::read_jsonl_schema(self.make_reader(query).await?).await?,
            FileFormat::Json => {
                let data = read_json_checked(&self.operator, query).await?;
                let schema = format_readers::read_json_schema(&data, None)?;
                if let Ok(mut cache) = self.json_cache.lock() {
                    *cache = Some((query.to_owned(), data));
                }
                schema
            },
        };

        Ok(Arc::new(Query::new(query.to_owned(), Arc::new(schema))))
    }

    #[tracing::instrument(skip_all, fields(connector.provider = PROVIDER, batch_size = options.batch_size))]
    async fn read_tabular(&self, view: Arc<Query>, options: &QueryOptions) -> QueryOutput {
        let format = self.detect_format(&view.query)?;
        let batch_size = options.batch_size;

        match format {
            FileFormat::Parquet => {
                let reader = self.make_reader(&view.query).await?;
                format_readers::read_parquet_batches(reader, batch_size).await
            },
            FileFormat::Csv => {
                let reader = self.make_reader(&view.query).await?;
                format_readers::read_csv_batches(reader, &view.schema, batch_size).await
            },
            FileFormat::JsonLines => {
                let reader = self.make_reader(&view.query).await?;
                format_readers::read_jsonl_batches(reader, &view.schema, batch_size).await
            },
            FileFormat::Json => {
                let cached = if let Ok(mut c) = self.json_cache.lock() {
                    if c.as_ref().is_some_and(|(p, _)| *p == view.query) {
                        c.take().map(|(_, d)| d)
                    } else {
                        None
                    }
                } else {
                    None
                };
                let data = match cached {
                    Some(d) => d,
                    None => read_json_checked(&self.operator, &view.query).await?,
                };
                format_readers::read_json_batches(data, view.schema.clone(), batch_size, None)
            },
        }
    }

    #[tracing::instrument(skip_all, fields(connector.provider = PROVIDER, storage.object.path = %query.path))]
    async fn can_read_binary(&self, query: Arc<BinaryQuery>) -> Result<(), ConnectorError> {
        self.operator
            .stat(&query.path)
            .await
            .map_err(|e| map_opendal_error(e, "stat", &query.path))?;
        Ok(())
    }

    #[tracing::instrument(skip_all, fields(connector.provider = PROVIDER, storage.object.path = %query.path))]
    async fn read_binary(&self, query: Arc<BinaryQuery>) -> QueryOutput {
        let reader = self.make_reader(&query.path).await?;
        let schema = Arc::new(Schema::new(vec![Field::new("data", DataType::Binary, false)]));

        let mut buf_stream = reader
            .into_stream(..)
            .await
            .map_err(|e| map_opendal_error(e, "read", &query.path))?;

        let stream = async_stream::try_stream! {
            while let Some(buf) = buf_stream
                .try_next()
                .await
                .map_err(|e| map_opendal_error(e, "read", &query.path))?
            {
                let chunk = buf.to_bytes();
                let array = BinaryArray::from_vec(vec![&chunk]);
                let batch = RecordBatch::try_new(schema.clone(), vec![Arc::new(array)])
                    .map_err(|e| ConnectorError::internal("failed to build binary record batch", e))?;
                yield batch;
            }
        };

        Ok(Box::pin(stream))
    }

    #[tracing::instrument(skip_all, fields(connector.provider = PROVIDER))]
    async fn check_connection(&self) -> Result<(), ConnectorError> {
        // Like `Operator::check`, but NotFound fails the check too. OpenDAL
        // classifies a standard `NoSuchBucket` reply as ConfigInvalid, yet
        // some S3-compatible stores answer a missing bucket with a bare 404,
        // which `Operator::check` would accept.
        let to_error = |e: opendal::Error| {
            let message = map_opendal_error(e, "list", "/").message().to_string();
            ConnectorError::ConnectionError(format!("S3 connection check failed: {message}"))
        };
        let mut lister = self.operator.lister_with("/").limit(1).await.map_err(to_error)?;
        lister.try_next().await.map_err(to_error)?;
        Ok(())
    }

    #[tracing::instrument(
        skip_all,
        fields(
        connector.provider = PROVIDER,
        include_schema = include_schema,
        row_count = tracing::field::Empty,
        )
    )]
    async fn list_tables(
        &self,
        table_name_filter: Option<&str>,
        include_schema: bool,
    ) -> Result<Vec<TableInfo>, ConnectorError> {
        let list_prefix = table_name_filter.map(like_prefix).unwrap_or_default();
        let entries = self
            .operator
            .list_with(list_prefix)
            .recursive(true)
            .await
            .map_err(|e| map_opendal_error(e, "list", &format!("{list_prefix}*")))?;

        let paths: Vec<String> = entries
            .into_iter()
            .filter(|e| e.metadata().mode() == EntryMode::FILE)
            .map(|e| e.path().to_string())
            .filter(|p| self.detect_format(p).is_ok())
            .collect();

        let mut tables = Vec::new();
        for path in &paths {
            if let Some(pattern) = table_name_filter
                && !sql_like_match(path, pattern)
            {
                continue;
            }

            let is_json = matches!(self.detect_format(path), Ok(FileFormat::Json));
            let table_schema = if include_schema && !is_json {
                match self.schema(path).await {
                    Ok(state) => state.schema.as_ref().clone(),
                    Err(e) => {
                        tracing::warn!(path, error = %e, "failed to read schema");
                        Schema::empty()
                    },
                }
            } else {
                Schema::empty()
            };

            tables.push(TableInfo {
                catalog: String::new(),
                schema_name: String::new(),
                table_name: path.clone(),
                table_type: "TABLE".to_string(),
                table_schema,
            });
        }

        tracing::Span::current().record("row_count", tables.len());
        Ok(tables)
    }
}

/// Extract the longest literal prefix from a SQL LIKE pattern (before the
/// first `%` or `_` wildcard) so S3 listing can be narrowed server-side.
fn like_prefix(pattern: &str) -> &str {
    let end = pattern.find(['%', '_']).unwrap_or(pattern.len());
    &pattern[..end]
}

fn sql_like_match(value: &str, pattern: &str) -> bool {
    let v: Vec<char> = value.chars().collect();
    let p: Vec<char> = pattern.chars().collect();

    let (mut vi, mut pi) = (0usize, 0usize);
    let (mut star_pi, mut star_vi): (Option<usize>, usize) = (None, 0);

    while vi < v.len() {
        if pi < p.len() && (p[pi] == '_' || p[pi] == v[vi]) {
            vi += 1;
            pi += 1;
        } else if pi < p.len() && p[pi] == '%' {
            star_pi = Some(pi);
            pi += 1;
            star_vi = vi;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_vi += 1;
            vi = star_vi;
        } else {
            return false;
        }
    }

    while pi < p.len() && p[pi] == '%' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::array::Array;

    fn make_credentials() -> Arc<HashMap<String, String>> {
        Arc::new(HashMap::from([
            (KEY_BUCKET.to_string(), "test-bucket".to_string()),
            (KEY_ACCESS_KEY_ID.to_string(), "AKIAIOSFODNN7EXAMPLE".to_string()),
            (
                KEY_SECRET_ACCESS_KEY.to_string(),
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            ),
            (KEY_REGION.to_string(), "us-east-1".to_string()),
        ]))
    }

    #[test]
    fn test_s3_connector_provider() {
        let connector = S3Connector::new(
            Duration::from_secs(300),
            Duration::from_secs(60),
            100,
            ConnectorConfig::default(),
        );
        assert_eq!(connector.provider(), "s3");
    }

    #[test]
    fn test_build_operator_success() {
        let creds = make_credentials();
        let result = build_operator(&creds, Duration::from_secs(10), Duration::from_secs(30));
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_operator_missing_bucket() {
        let creds = HashMap::from([
            (KEY_ACCESS_KEY_ID.to_string(), "key".to_string()),
            (KEY_SECRET_ACCESS_KEY.to_string(), "secret".to_string()),
        ]);
        let result = build_operator(&creds, Duration::from_secs(10), Duration::from_secs(10));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains(KEY_BUCKET));
    }

    #[test]
    fn test_build_operator_missing_access_key() {
        let creds = HashMap::from([
            (KEY_BUCKET.to_string(), "bucket".to_string()),
            (KEY_SECRET_ACCESS_KEY.to_string(), "secret".to_string()),
        ]);
        let result = build_operator(&creds, Duration::from_secs(10), Duration::from_secs(10));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains(KEY_ACCESS_KEY_ID));
    }

    #[test]
    fn test_build_operator_empty_region_defaults() {
        let mut creds: HashMap<String, String> = (*make_credentials()).clone();
        creds.insert(KEY_REGION.to_string(), "".to_string());
        let result = build_operator(&creds, Duration::from_secs(10), Duration::from_secs(10));
        assert!(result.is_ok());
    }

    #[test]
    fn test_resolve_region_keeps_existing() {
        let mut creds: HashMap<String, String> = (*make_credentials()).clone();
        creds.insert(KEY_REGION.to_string(), "eu-west-1".to_string());
        assert_eq!(resolve_region(&creds), "eu-west-1");
    }

    #[test]
    fn test_resolve_region_empty_string_fallback() {
        let mut creds: HashMap<String, String> = (*make_credentials()).clone();
        creds.insert(KEY_REGION.to_string(), "".to_string());
        assert_eq!(resolve_region(&creds), "us-east-1");
    }

    #[test]
    fn test_resolve_region_whitespace_fallback() {
        let mut creds: HashMap<String, String> = (*make_credentials()).clone();
        creds.insert(KEY_REGION.to_string(), "  ".to_string());
        assert_eq!(resolve_region(&creds), "us-east-1");
    }

    #[test]
    fn test_resolve_region_fallback_us_east_1() {
        let mut creds: HashMap<String, String> = (*make_credentials()).clone();
        creds.remove(KEY_REGION);
        assert_eq!(resolve_region(&creds), "us-east-1");
    }

    #[test]
    fn test_build_operator_with_endpoint() {
        let mut creds: HashMap<String, String> = (*make_credentials()).clone();
        creds.insert(KEY_ENDPOINT.to_string(), "http://seaweedfs:9000".to_string());
        let result = build_operator(&creds, Duration::from_secs(10), Duration::from_secs(10));
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_operator_rejects_invalid_ca_certificate() {
        let mut creds: HashMap<String, String> = (*make_credentials()).clone();
        creds.insert(KEY_CA_CERT.to_string(), "not a PEM certificate".to_string());
        let result = build_operator(&creds, Duration::from_secs(10), Duration::from_secs(10));
        assert!(result.unwrap_err().to_string().contains(KEY_CA_CERT));
    }

    #[test]
    fn test_s3_reader_detect_format() {
        let reader = S3Reader {
            operator: build_operator(&make_credentials(), Duration::from_secs(10), Duration::from_secs(30)).unwrap(),
            format_hint: None,
            config: ConnectorConfig::default(),
            json_cache: Mutex::new(None),
        };
        assert_eq!(reader.detect_format("data/file.parquet").unwrap(), FileFormat::Parquet);
        assert_eq!(reader.detect_format("data/file.csv").unwrap(), FileFormat::Csv);
        assert_eq!(reader.detect_format("data/file.jsonl").unwrap(), FileFormat::JsonLines);
        assert_eq!(reader.detect_format("data/file.ndjson").unwrap(), FileFormat::JsonLines);
        assert_eq!(reader.detect_format("data/file.json").unwrap(), FileFormat::Json);
    }

    #[test]
    fn test_s3_reader_detect_format_with_hint() {
        let reader = S3Reader {
            operator: build_operator(&make_credentials(), Duration::from_secs(10), Duration::from_secs(30)).unwrap(),
            format_hint: Some("parquet".to_string()),
            config: ConnectorConfig::default(),
            json_cache: Mutex::new(None),
        };
        assert_eq!(reader.detect_format("data/no-extension").unwrap(), FileFormat::Parquet);

        let reader = S3Reader {
            operator: build_operator(&make_credentials(), Duration::from_secs(10), Duration::from_secs(30)).unwrap(),
            format_hint: Some("jsonl".to_string()),
            config: ConnectorConfig::default(),
            json_cache: Mutex::new(None),
        };
        assert_eq!(
            reader.detect_format("data/no-extension").unwrap(),
            FileFormat::JsonLines
        );

        let reader = S3Reader {
            operator: build_operator(&make_credentials(), Duration::from_secs(10), Duration::from_secs(30)).unwrap(),
            format_hint: Some("json".to_string()),
            config: ConnectorConfig::default(),
            json_cache: Mutex::new(None),
        };
        assert_eq!(reader.detect_format("data/no-extension").unwrap(), FileFormat::Json);
    }

    #[test]
    fn test_like_prefix() {
        assert_eq!(
            like_prefix("datasets/dch-test-prompts.parquet"),
            "datasets/dch-test-prompts.parquet"
        );
        assert_eq!(like_prefix("%dch-test-prompts%"), "");
        assert_eq!(like_prefix("datasets/%"), "datasets/");
        assert_eq!(like_prefix("data/_.parquet"), "data/");
        assert_eq!(like_prefix(""), "");
    }

    #[test]
    fn test_sql_like_exact() {
        assert!(sql_like_match("cities.parquet", "cities.parquet"));
        assert!(!sql_like_match("cities.parquet", "cities.csv"));
    }

    #[test]
    fn test_sql_like_percent() {
        assert!(sql_like_match("data/cities.parquet", "%cities%"));
        assert!(sql_like_match("cities.parquet", "%"));
        assert!(sql_like_match("data/cities.parquet", "data/%"));
        assert!(!sql_like_match("data/cities.parquet", "other/%"));
    }

    #[test]
    fn test_sql_like_underscore() {
        assert!(sql_like_match("a.csv", "_.csv"));
        assert!(!sql_like_match("ab.csv", "_.csv"));
    }

    #[test]
    fn test_sql_like_combined() {
        assert!(!sql_like_match("data/cities.parquet", "%/_.parquet"));
        assert!(sql_like_match("data/x.parquet", "%/_.parquet"));
    }

    #[tokio::test]
    async fn test_can_read_binary_exists() {
        let op = Operator::new(opendal::services::Memory::default()).unwrap();
        op.write("data/model.bin", vec![1u8, 2, 3]).await.unwrap();
        let reader = S3Reader {
            operator: op,
            format_hint: None,
            config: ConnectorConfig::default(),
            json_cache: Mutex::new(None),
        };
        let query = Arc::new(BinaryQuery::new("data/model.bin".to_string()));
        assert!(reader.can_read_binary(query).await.is_ok());
    }

    #[tokio::test]
    async fn test_can_read_binary_not_found() {
        let op = Operator::new(opendal::services::Memory::default()).unwrap();
        let reader = S3Reader {
            operator: op,
            format_hint: None,
            config: ConnectorConfig::default(),
            json_cache: Mutex::new(None),
        };
        let query = Arc::new(BinaryQuery::new("does/not/exist.bin".to_string()));
        assert!(reader.can_read_binary(query).await.is_err());
    }

    #[tokio::test]
    async fn test_read_binary_streams_data() {
        let data = b"hello binary world".to_vec();
        let op = Operator::new(opendal::services::Memory::default()).unwrap();
        op.write("test.bin", data.clone()).await.unwrap();
        let reader = S3Reader {
            operator: op,
            format_hint: None,
            config: ConnectorConfig::default(),
            json_cache: Mutex::new(None),
        };
        let query = Arc::new(BinaryQuery::new("test.bin".to_string()));
        let stream = reader.read_binary(query).await.unwrap();

        let batches: Vec<_> = stream.try_collect().await.unwrap();
        assert!(!batches.is_empty());

        let mut result = Vec::new();
        for batch in &batches {
            assert_eq!(batch.num_columns(), 1);
            let col = batch.column(0).as_any().downcast_ref::<BinaryArray>().unwrap();
            for i in 0..col.len() {
                result.extend_from_slice(col.value(i));
            }
        }
        assert_eq!(result, data);
    }

    fn make_json_reader(op: Operator) -> S3Reader {
        S3Reader {
            operator: op,
            format_hint: None,
            config: ConnectorConfig::default(),
            json_cache: Mutex::new(None),
        }
    }

    #[tokio::test]
    async fn test_json_cache_populated_after_schema() {
        let op = Operator::new(opendal::services::Memory::default()).unwrap();
        let json_data = serde_json::to_vec(&serde_json::json!([
            {"name": "Alice", "age": 30},
            {"name": "Bob", "age": 25},
        ]))
        .unwrap();
        op.write("data.json", json_data).await.unwrap();

        let reader = make_json_reader(op);
        reader.schema("data.json").await.unwrap();

        let cache = reader.json_cache.lock().unwrap();
        let (path, _) = cache.as_ref().expect("cache should be populated after schema()");
        assert_eq!(path, "data.json");
    }

    #[tokio::test]
    async fn test_json_cache_hit_avoids_redownload() {
        let op = Operator::new(opendal::services::Memory::default()).unwrap();
        let op2 = op.clone();
        let json_data = serde_json::to_vec(&serde_json::json!([{"x": 1}, {"x": 2}])).unwrap();
        op.write("data.json", json_data).await.unwrap();

        let reader = make_json_reader(op);
        let query = reader.schema("data.json").await.unwrap();
        assert!(reader.json_cache.lock().unwrap().is_some());

        // Delete the source file; read_tabular must still succeed via cache
        op2.delete("data.json").await.unwrap();

        let stream = reader.read_tabular(query, &QueryOptions::default()).await.unwrap();
        let batches: Vec<RecordBatch> = stream.try_collect().await.unwrap();
        assert_eq!(batches[0].num_rows(), 2);

        assert!(
            reader.json_cache.lock().unwrap().is_none(),
            "cache should be cleared after read_tabular()"
        );
    }

    #[tokio::test]
    async fn test_json_cache_path_mismatch_no_hit() {
        let op = Operator::new(opendal::services::Memory::default()).unwrap();
        op.write("a.json", serde_json::to_vec(&serde_json::json!([{"v": 1}])).unwrap())
            .await
            .unwrap();
        op.write("b.json", serde_json::to_vec(&serde_json::json!([{"v": 2}])).unwrap())
            .await
            .unwrap();

        let reader = make_json_reader(op);

        // Cache holds a.json
        reader.schema("a.json").await.unwrap();
        assert_eq!(reader.json_cache.lock().unwrap().as_ref().unwrap().0, "a.json");

        // read_tabular for b.json must not use cached a.json data
        let query_b = Arc::new(Query::new(
            "b.json".to_string(),
            Arc::new(
                format_readers::read_json_schema(&serde_json::to_vec(&serde_json::json!([{"v": 2}])).unwrap(), None)
                    .unwrap(),
            ),
        ));
        let stream = reader.read_tabular(query_b, &QueryOptions::default()).await.unwrap();
        let batches: Vec<RecordBatch> = stream.try_collect().await.unwrap();
        let val = batches[0]
            .column_by_name("v")
            .unwrap()
            .as_any()
            .downcast_ref::<arrow::array::Int64Array>()
            .unwrap();
        assert_eq!(val.value(0), 2, "data must come from b.json, not cached a.json");

        // Cache should still hold the stale a.json entry (not cleared on mismatch)
        assert!(
            reader.json_cache.lock().unwrap().is_some(),
            "mismatched cache entry should not be cleared"
        );
    }
}

#[cfg(test)]
mod error_reporting_tests {
    use super::*;
    use commons::test_support::{ECHO_HEADERS, MockHttpServer, StaticCredentials, connection};

    const ACCESS_KEY: &str = "LEAKSENTINELACCESSKEY";
    const SECRET_KEY: &str = "LEAK-SENTINEL-s3-secret-key";

    fn s3_error(code: &str, message: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{code}</Code><Message>{message}</Message><Resource>/b</Resource><RequestId>req-1</RequestId></Error>"
        )
    }

    async fn reader(endpoint: &str) -> Arc<dyn DataReader> {
        let config = ConnectorConfig {
            connection_timeout_secs: 2,
            ..ConnectorConfig::default()
        };
        S3Connector::new(Duration::from_secs(60), Duration::from_secs(60), 10, config)
            .get_reader(
                &connection("s3-1", &[]),
                &StaticCredentials::new(&[
                    ("AWS_S3_BUCKET", "b"),
                    ("AWS_ACCESS_KEY_ID", ACCESS_KEY),
                    ("AWS_SECRET_ACCESS_KEY", SECRET_KEY),
                    ("AWS_S3_ENDPOINT", endpoint),
                ]),
            )
            .await
            .unwrap()
    }

    #[test]
    fn s3_error_summary_extracts_code_and_message() {
        let rendered = r#"S3Error { code: "NoSuchBucket", message: "The specified bucket does not exist", resource: "/b", request_id: "req-1" }"#;
        assert_eq!(
            s3_error_summary(rendered).as_deref(),
            Some("NoSuchBucket: The specified bucket does not exist")
        );
        assert_eq!(s3_error_summary("<html>502</html>"), None);
    }

    #[tokio::test]
    async fn missing_bucket_fails_the_check() {
        let server = MockHttpServer::start(404, &s3_error("NoSuchBucket", "The specified bucket does not exist")).await;
        let err = reader(&server.url()).await.check_connection().await.unwrap_err();
        assert!(matches!(err, ConnectorError::ConnectionError(_)), "{err:?}");
        assert_eq!(
            err.message(),
            "S3 connection check failed: list '/' failed: ConfigInvalid (NoSuchBucket: The specified bucket does not exist)"
        );
    }

    #[tokio::test]
    async fn bare_not_found_fails_the_check() {
        let server = MockHttpServer::start(404, "").await;
        let err = reader(&server.url()).await.check_connection().await.unwrap_err();
        assert_eq!(err.message(), "S3 connection check failed: '/' not found");
    }

    #[tokio::test]
    async fn bad_signature_reports_the_s3_reason() {
        let server = MockHttpServer::start(
            403,
            &s3_error(
                "SignatureDoesNotMatch",
                "The request signature we calculated does not match the signature you provided.",
            ),
        )
        .await;
        let err = reader(&server.url()).await.check_connection().await.unwrap_err();
        assert_eq!(
            err.message(),
            "S3 connection check failed: access denied for '/' (SignatureDoesNotMatch: The request signature we calculated does not match the signature you provided.)"
        );
    }

    #[tokio::test]
    async fn echoed_credentials_are_redacted() {
        let server = MockHttpServer::start(403, ECHO_HEADERS).await;
        let msg = reader(&server.url())
            .await
            .check_connection()
            .await
            .unwrap_err()
            .message()
            .to_string();
        assert!(msg.contains("access denied"), "{msg}");
        // The excerpt may cut the Authorization header anywhere, including
        // inside the access key; no recognizable part of it may survive.
        assert!(!msg.contains(&ACCESS_KEY[..4]), "{msg}");
        assert!(!msg.contains(SECRET_KEY), "{msg}");
    }

    #[tokio::test]
    async fn unreachable_endpoint_reports_the_cause() {
        let err = reader("http://127.0.0.1:1").await.check_connection().await.unwrap_err();
        let msg = err.message();
        assert!(
            msg.starts_with("S3 connection check failed: list '/' failed: Unexpected"),
            "{msg}"
        );
        assert!(msg.to_lowercase().contains("connection refused"), "{msg}");
    }
}
