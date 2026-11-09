use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use arrow::array::ArrayRef;
use arrow::datatypes::{DataType as ArrowDataType, Schema};
use arrow::record_batch::RecordBatch;
use commons::api::arrow_convert::json_values_to_array;
use commons::api::connections::DataConnectionResource;
use commons::api::connector::CredentialsResolver;
use commons::api::connector::{DataReader, FlightConnector, Query, QueryOptions, QueryOutput};
use commons::api::diagnostics::{body_excerpt, error_chain};
use commons::api::errors::ConnectorError;
use commons::api::redact::{RedactingReader, Redactor, truncate_message};
use commons::utils::config::ConnectorConfig;
use moka::future::Cache;

use crate::query::EsRequestInput;
use crate::types;

const KEY_URI: &str = "URI";
const KEY_USERNAME: &str = "USERNAME";
const KEY_PASSWORD: &str = "PASSWORD";
const KEY_API_KEY: &str = "API_KEY";
const KEY_CA_CERT: &str = "CA_CERT";

#[derive(Clone)]
struct EsClient {
    http: reqwest::Client,
    base_url: String,
    auth: EsAuth,
}

#[derive(Clone)]
enum EsAuth {
    None,
    Basic { username: String, password: String },
    ApiKey { encoded: String },
}

const PROVIDER: &str = "elasticsearch";

impl EsClient {
    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let url = format!("{}{}", self.base_url.trim_end_matches('/'), path);
        let mut req = self.http.request(method, &url);
        match &self.auth {
            EsAuth::None => {},
            EsAuth::Basic { username, password } => {
                req = req.basic_auth(username, Some(password));
            },
            EsAuth::ApiKey { encoded } => {
                req = req.header("Authorization", format!("ApiKey {encoded}"));
            },
        }
        req
    }

    fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.request(reqwest::Method::GET, path)
    }

    fn post(&self, path: &str) -> reqwest::RequestBuilder {
        self.request(reqwest::Method::POST, path)
    }

    fn delete(&self, path: &str) -> reqwest::RequestBuilder {
        self.request(reqwest::Method::DELETE, path)
    }
}

pub struct ElasticsearchConnector {
    clients: Cache<String, (EsClient, Arc<Redactor>)>,
    config: ConnectorConfig,
}

impl ElasticsearchConnector {
    pub fn new(cache_ttl: Duration, cache_idle: Duration, cache_max_capacity: u64, config: ConnectorConfig) -> Self {
        Self {
            clients: Cache::builder()
                .time_to_live(cache_ttl)
                .time_to_idle(cache_idle)
                .max_capacity(cache_max_capacity)
                .build(),
            config,
        }
    }
}

fn build_client(credentials: &HashMap<String, String>, config: ConnectorConfig) -> Result<EsClient, ConnectorError> {
    let base_url = credentials
        .get(KEY_URI)
        .cloned()
        .ok_or_else(|| ConnectorError::ConnectionError(format!("'{KEY_URI}' credential is required")))?;

    let mut builder = reqwest::Client::builder()
        .connect_timeout(config.connection_timeout())
        .read_timeout(config.read_timeout())
        .timeout(config.request_timeout());

    if let Some(ca_pem) = credentials.get(KEY_CA_CERT) {
        let cert = reqwest::tls::Certificate::from_pem(ca_pem.as_bytes())
            .map_err(|e| ConnectorError::ConnectionError(format!("Invalid CA certificate: {}", error_chain(&e))))?;
        builder = builder.add_root_certificate(cert);
    }

    let http = builder
        .build()
        .map_err(|e| ConnectorError::ConnectionError(format!("Failed to build HTTP client: {}", error_chain(&e))))?;

    let auth = if let Some(encoded) = credentials.get(KEY_API_KEY) {
        EsAuth::ApiKey {
            encoded: encoded.clone(),
        }
    } else if let (Some(username), Some(password)) = (credentials.get(KEY_USERNAME), credentials.get(KEY_PASSWORD)) {
        EsAuth::Basic {
            username: username.clone(),
            password: password.clone(),
        }
    } else {
        EsAuth::None
    };

    Ok(EsClient { http, base_url, auth })
}

#[async_trait::async_trait]
impl FlightConnector for ElasticsearchConnector {
    fn provider(&self) -> String {
        PROVIDER.to_string()
    }

    fn description(&self) -> String {
        "Elasticsearch connector".to_string()
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
        let cache_key = data_connection.metadata.id.clone();

        let (client, redactor) = self
            .clients
            .try_get_with(cache_key, async {
                let credentials = credentials_resolver.resolve(data_connection).await?;
                let redactor = Arc::new(Redactor::from_credentials(&credentials));
                build_client(&credentials, self.config)
                    .map(|client| (client, Arc::clone(&redactor)))
                    .map_err(|e| redactor.redact_error(e))
            })
            .await
            .map_err(|e| Arc::try_unwrap(e).unwrap_or_else(|arc| (*arc).clone()))?;

        let default_index = data_connection.resource.properties.get("index").cloned();

        Ok(Arc::new(RedactingReader::new(
            ElasticsearchReader { client, default_index },
            redactor,
        )))
    }
}

pub struct ElasticsearchReader {
    client: EsClient,
    default_index: Option<String>,
}

#[async_trait::async_trait]
impl DataReader for ElasticsearchReader {
    fn provider(&self) -> String {
        PROVIDER.to_string()
    }

    #[tracing::instrument(skip_all, fields(connector.provider = PROVIDER))]
    async fn schema(&self, query: &str) -> Result<Arc<Query>, ConnectorError> {
        let request = EsRequestInput::parse(query)?;
        let index = request.resolve_index(self.default_index.as_deref())?;

        let mapping_json = send_json(
            self.client.get(&format!("/{}/_mapping", index)),
            &format!("get mapping of index '{index}'"),
        )
        .await?;

        let mapping_fields = types::parse_mapping(&mapping_json);

        if mapping_fields.is_empty() {
            return Err(ConnectorError::NoDataError);
        }

        let schema = types::mapping_fields_to_schema(&mapping_fields);
        Ok(Arc::new(Query::new(query.to_owned(), Arc::new(schema))))
    }

    #[tracing::instrument(skip_all, fields(connector.provider = PROVIDER, batch_size = options.batch_size))]
    async fn read_tabular(&self, query: Arc<Query>, options: &QueryOptions) -> QueryOutput {
        let request = EsRequestInput::parse(&query.query)?;
        let index = request.resolve_index(self.default_index.as_deref())?;
        let schema = query.schema.clone();
        let batch_size = options.batch_size as u64;
        let total_limit = request.size;
        let client = self.client.clone();

        let stream = async_stream::try_stream! {
            let pit_response = send_json(
                client.post(&format!("/{}/_pit?keep_alive=5m", index)),
                &format!("open point in time on index '{index}'"),
            )
            .await?;

            let pit_id = pit_response
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ConnectorError::ConnectionError("PIT response missing 'id'".to_string()))?
                .to_string();

            let mut search_after: Option<serde_json::Value> = None;
            let mut pit_id_current = pit_id;
            let mut total_fetched: u64 = 0;
            let mut loop_error: Option<ConnectorError> = None;

            loop {
                let remaining = total_limit.map(|limit| limit.saturating_sub(total_fetched));
                if remaining == Some(0) {
                    break;
                }

                let page_size = match remaining {
                    Some(r) => r.min(batch_size),
                    None => batch_size,
                };

                let body = request.build_pit_search_body(&pit_id_current, page_size, search_after.as_ref());

                let response_json = match fetch_search_page(&client, body).await {
                    Ok(v) => v,
                    Err(e) => { loop_error = Some(e); break; }
                };

                if let Some(new_pit_id) = response_json.get("pit_id").and_then(|v| v.as_str()) {
                    pit_id_current = new_pit_id.to_string();
                }

                let hits = response_json
                    .get("hits")
                    .and_then(|h| h.get("hits"))
                    .and_then(|h| h.as_array());

                let Some(hits) = hits else { break };

                if hits.is_empty() {
                    break;
                }

                let num_hits = hits.len() as u64;
                match hits_to_record_batch(&schema, hits) {
                    Ok(batch) => yield batch,
                    Err(e) => { loop_error = Some(e); break; }
                }

                total_fetched += num_hits;

                search_after = hits.last().and_then(|h| h.get("sort").cloned());
                if search_after.is_none() {
                    break;
                }

                if num_hits < page_size {
                    break;
                }
            }

            close_pit(&client, &pit_id_current).await;

            if let Some(e) = loop_error {
                Err(e)?;
            }
        };

        Ok(Box::pin(stream))
    }

    #[tracing::instrument(skip_all, fields(connector.provider = PROVIDER))]
    async fn check_connection(&self) -> Result<(), ConnectorError> {
        // Any failure here means the connection settings do not work,
        // whatever status Elasticsearch answered with.
        send(self.client.get("/"), "connection check")
            .await
            .map_err(|e| ConnectorError::ConnectionError(e.message().to_string()))?;
        Ok(())
    }
}

/// send sends `req` and returns the response body, turning transport
/// failures and error statuses into client-actionable errors. `action` names
/// the request in the message.
async fn send(req: reqwest::RequestBuilder, action: &str) -> Result<String, ConnectorError> {
    let response = req
        .send()
        .await
        .map_err(|e| ConnectorError::ConnectionError(format!("{action} failed: {}", error_chain(&e))))?;
    let status = response.status();
    let body = response.text().await.map_err(|e| {
        ConnectorError::ConnectionError(format!("{action} failed: reading the response: {}", error_chain(&e)))
    })?;
    if !status.is_success() {
        return Err(http_error(action, status, &body));
    }
    Ok(body)
}

/// send_json is [`send`] for requests whose response must be a JSON document.
async fn send_json(req: reqwest::RequestBuilder, action: &str) -> Result<serde_json::Value, ConnectorError> {
    let body = send(req, action).await?;
    serde_json::from_str(&body).map_err(|e| {
        ConnectorError::ConnectionError(format!(
            "{action} failed: Elasticsearch returned an unexpected response ({e}): {}",
            body_excerpt(&body)
        ))
    })
}

fn http_error(action: &str, status: reqwest::StatusCode, body: &str) -> ConnectorError {
    let message = format!("{action} failed (HTTP {status}): {}", es_error_detail(body));
    match status {
        reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN => ConnectorError::ConnectionError(message),
        reqwest::StatusCode::NOT_FOUND => ConnectorError::NotFound(message),
        s if s.is_client_error() => ConnectorError::SQLError(message),
        _ => ConnectorError::ConnectionError(message),
    }
}

/// es_error_detail extracts `type: reason` from an Elasticsearch error body,
/// adding the first root cause when it says more, e.g. the parse error behind
/// `search_phase_execution_exception: all shards failed`. A body that is not
/// an Elasticsearch error, such as a proxy error page, is quoted as an
/// excerpt.
fn es_error_detail(body: &str) -> String {
    let error = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|json| json.get("error").cloned());
    let Some(error) = error else {
        return body_excerpt(body);
    };
    if let Some(text) = error.as_str() {
        return body_excerpt(text);
    }
    let describe = |e: &serde_json::Value| -> Option<String> {
        let reason = e.get("reason")?.as_str()?;
        Some(match e.get("type").and_then(|t| t.as_str()) {
            Some(kind) => format!("{kind}: {reason}"),
            None => reason.to_string(),
        })
    };
    let top = describe(&error);
    let root = error.get("root_cause").and_then(|r| r.get(0)).and_then(describe);
    let detail = match (top, root) {
        (Some(top), Some(root)) if top != root => format!("{top} (root cause: {root})"),
        (Some(top), _) => top,
        (None, Some(root)) => root,
        (None, None) => return body_excerpt(body),
    };
    truncate_message(&detail, MAX_ERROR_DETAIL_BYTES)
}

/// MAX_ERROR_DETAIL_BYTES caps the Elasticsearch error detail quoted in a
/// message. Reasons may quote the offending query.
const MAX_ERROR_DETAIL_BYTES: usize = 512;

async fn fetch_search_page(client: &EsClient, body: serde_json::Value) -> Result<serde_json::Value, ConnectorError> {
    send_json(client.post("/_search").json(&body), "search").await
}

async fn close_pit(client: &EsClient, pit_id: &str) {
    if let Err(e) = client
        .delete("/_pit")
        .json(&serde_json::json!({ "id": pit_id }))
        .send()
        .await
    {
        tracing::error!(error = %error_chain(&e), "failed to close point in time");
    }
}

fn hits_to_record_batch(schema: &Arc<Schema>, hits: &[serde_json::Value]) -> Result<RecordBatch, ConnectorError> {
    let arrays: Vec<ArrayRef> = schema
        .fields()
        .iter()
        .map(|field| extract_column_from_hits(field.name(), field.data_type(), hits))
        .collect::<Result<_, _>>()?;

    RecordBatch::try_new(Arc::clone(schema), arrays)
        .map_err(|e| ConnectorError::internal("failed to assemble record batch", e))
}

fn extract_column_from_hits(
    field_path: &str,
    data_type: &ArrowDataType,
    hits: &[serde_json::Value],
) -> Result<ArrayRef, ConnectorError> {
    let values: Vec<Option<&serde_json::Value>> = hits
        .iter()
        .map(|hit| {
            let source = hit.get("_source")?;
            resolve_path(source, field_path)
        })
        .collect();

    json_values_to_array(field_path, data_type, &values)
}

fn resolve_path<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut current = value;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::array::{Array, Int64Array, StringArray, TimestampMillisecondArray};
    use arrow::datatypes::{Field, TimeUnit};

    #[test]
    fn test_connector_provider() {
        let connector = ElasticsearchConnector::new(
            Duration::from_secs(300),
            Duration::from_secs(60),
            100,
            ConnectorConfig::default(),
        );
        assert_eq!(connector.provider(), "elasticsearch");
    }

    #[test]
    fn test_resolve_path_simple() {
        let val = serde_json::json!({"name": "Alice"});
        assert_eq!(resolve_path(&val, "name").unwrap(), "Alice");
    }

    #[test]
    fn test_resolve_path_nested() {
        let val = serde_json::json!({"user": {"name": "Alice", "age": 30}});
        assert_eq!(resolve_path(&val, "user.name").unwrap(), "Alice");
        assert_eq!(resolve_path(&val, "user.age").unwrap(), 30);
    }

    #[test]
    fn test_resolve_path_missing() {
        let val = serde_json::json!({"name": "Alice"});
        assert!(resolve_path(&val, "missing").is_none());
        assert!(resolve_path(&val, "a.b.c").is_none());
    }

    #[test]
    fn test_hits_to_record_batch_timestamp() {
        let schema = Arc::new(Schema::new(vec![Field::new(
            "created_at",
            ArrowDataType::Timestamp(TimeUnit::Millisecond, Some("UTC".into())),
            true,
        )]));
        let hits = vec![
            serde_json::json!({"_source": {"created_at": 1700000000000_i64}}),
            serde_json::json!({"_source": {"created_at": "2023-11-14T22:13:20.000Z"}}),
            serde_json::json!({"_source": {}}),
        ];
        let batch = hits_to_record_batch(&schema, &hits).unwrap();
        let ts_arr = batch
            .column(0)
            .as_any()
            .downcast_ref::<TimestampMillisecondArray>()
            .unwrap();
        assert_eq!(ts_arr.value(0), 1700000000000);
        assert_eq!(ts_arr.value(1), 1700000000000);
        assert!(ts_arr.is_null(2));
    }

    #[test]
    fn test_hits_to_record_batch_timestamp_invalid() {
        let schema = Arc::new(Schema::new(vec![Field::new(
            "created_at",
            ArrowDataType::Timestamp(TimeUnit::Millisecond, Some("UTC".into())),
            true,
        )]));
        let hits = vec![serde_json::json!({"_source": {"created_at": "not-a-date"}})];
        let err = hits_to_record_batch(&schema, &hits).unwrap_err();
        assert!(
            matches!(err, ConnectorError::SQLError(_)),
            "should be SQLError: {}",
            err
        );
    }

    #[test]
    fn test_hits_to_record_batch() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("title", ArrowDataType::Utf8, true),
            Field::new("count", ArrowDataType::Int64, true),
        ]));
        let hits = vec![
            serde_json::json!({"_source": {"title": "hello", "count": 10}}),
            serde_json::json!({"_source": {"title": "world", "count": 20}}),
        ];
        let batch = hits_to_record_batch(&schema, &hits).unwrap();
        assert_eq!(batch.num_rows(), 2);
        assert_eq!(batch.num_columns(), 2);

        let title_arr = batch.column(0).as_any().downcast_ref::<StringArray>().unwrap();
        assert_eq!(title_arr.value(0), "hello");
        assert_eq!(title_arr.value(1), "world");

        let count_arr = batch.column(1).as_any().downcast_ref::<Int64Array>().unwrap();
        assert_eq!(count_arr.value(0), 10);
        assert_eq!(count_arr.value(1), 20);
    }

    #[test]
    fn test_hits_to_record_batch_nested() {
        let schema = Arc::new(Schema::new(vec![Field::new("user.name", ArrowDataType::Utf8, true)]));
        let hits = vec![
            serde_json::json!({"_source": {"user": {"name": "Alice"}}}),
            serde_json::json!({"_source": {"user": {"name": "Bob"}}}),
        ];
        let batch = hits_to_record_batch(&schema, &hits).unwrap();
        let name_arr = batch.column(0).as_any().downcast_ref::<StringArray>().unwrap();
        assert_eq!(name_arr.value(0), "Alice");
        assert_eq!(name_arr.value(1), "Bob");
    }

    #[test]
    fn test_hits_to_record_batch_null_fields() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("title", ArrowDataType::Utf8, true),
            Field::new("missing", ArrowDataType::Utf8, true),
        ]));
        let hits = vec![serde_json::json!({"_source": {"title": "hello"}})];
        let batch = hits_to_record_batch(&schema, &hits).unwrap();
        assert_eq!(batch.num_rows(), 1);

        let missing_arr = batch.column(1).as_any().downcast_ref::<StringArray>().unwrap();
        assert!(missing_arr.is_null(0));
    }

    #[test]
    fn test_hits_to_record_batch_int8_overflow_propagates() {
        let schema = Arc::new(Schema::new(vec![Field::new("score", ArrowDataType::Int8, true)]));
        let hits = vec![serde_json::json!({"_source": {"score": 300}})];
        let err = hits_to_record_batch(&schema, &hits).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("score"), "should name the field: {msg}");
        assert!(msg.contains("300"), "should include the value: {msg}");
    }
}

#[cfg(test)]
mod error_reporting_tests {
    use super::*;
    use base64::Engine as _;
    use commons::test_support::{ECHO_HEADERS, MockHttpServer, StaticCredentials, connection};

    const SECRET: &str = "LEAK-SENTINEL-es-pw";

    async fn reader(uri: &str, extra: &[(&str, &str)]) -> Arc<dyn DataReader> {
        let mut creds = vec![("URI", uri)];
        creds.extend_from_slice(extra);
        ElasticsearchConnector::new(
            Duration::from_secs(60),
            Duration::from_secs(60),
            10,
            ConnectorConfig::default(),
        )
        .get_reader(
            &connection("es-1", &[("index", "docs")]),
            &StaticCredentials::new(&creds),
        )
        .await
        .unwrap()
    }

    #[test]
    fn es_error_detail_prefers_type_and_root_cause() {
        let body = r#"{"error":{"root_cause":[{"type":"parsing_exception","reason":"unknown query [bogus]"}],
            "type":"search_phase_execution_exception","reason":"all shards failed"},"status":400}"#;
        assert_eq!(
            es_error_detail(body),
            "search_phase_execution_exception: all shards failed (root cause: parsing_exception: unknown query [bogus])"
        );

        let body = r#"{"error":{"root_cause":[{"type":"index_not_found_exception","reason":"no such index [x]"}],
            "type":"index_not_found_exception","reason":"no such index [x]"},"status":404}"#;
        assert_eq!(es_error_detail(body), "index_not_found_exception: no such index [x]");

        assert_eq!(
            es_error_detail("<html>\n502 Bad Gateway\n</html>"),
            "<html> 502 Bad Gateway </html>"
        );
    }

    #[tokio::test]
    async fn unreachable_host_reports_the_cause() {
        let err = reader("http://127.0.0.1:1", &[])
            .await
            .check_connection()
            .await
            .unwrap_err();
        assert!(matches!(err, ConnectorError::ConnectionError(_)));
        let msg = err.message();
        assert!(msg.starts_with("connection check failed: "), "{msg}");
        assert!(msg.to_lowercase().contains("connection refused"), "{msg}");
    }

    #[tokio::test]
    async fn missing_index_is_not_found_with_reason() {
        let server = MockHttpServer::start(
            404,
            r#"{"error":{"type":"index_not_found_exception","reason":"no such index [docs]"},"status":404}"#,
        )
        .await;
        let err = reader(&server.url(), &[]).await.schema("{}").await.err().unwrap();
        assert!(matches!(err, ConnectorError::NotFound(_)), "{err:?}");
        assert_eq!(
            err.message(),
            "get mapping of index 'docs' failed (HTTP 404 Not Found): index_not_found_exception: no such index [docs]"
        );
    }

    #[tokio::test]
    async fn echoed_basic_auth_is_redacted() {
        let server = MockHttpServer::start(401, &format!("unauthorized, got: {ECHO_HEADERS}")).await;
        let reader = reader(&server.url(), &[("USERNAME", "elastic"), ("PASSWORD", SECRET)]).await;
        let msg = reader.check_connection().await.unwrap_err().message().to_string();
        let encoded = base64::engine::general_purpose::STANDARD.encode(format!("elastic:{SECRET}"));
        assert!(msg.contains("HTTP 401"), "{msg}");
        assert!(msg.contains("authorization: Basic ***"), "{msg}");
        assert!(!msg.contains(SECRET) && !msg.contains(&encoded), "{msg}");
    }

    #[tokio::test]
    async fn echoed_api_key_is_redacted() {
        let server = MockHttpServer::start(403, &format!("forbidden, got: {ECHO_HEADERS}")).await;
        let reader = reader(&server.url(), &[("API_KEY", SECRET)]).await;
        let msg = reader.check_connection().await.unwrap_err().message().to_string();
        assert!(msg.contains("HTTP 403"), "{msg}");
        assert!(msg.contains("authorization: ApiKey ***"), "{msg}");
        assert!(!msg.contains(SECRET), "{msg}");
    }
}
