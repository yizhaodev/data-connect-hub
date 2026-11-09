use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use arrow::array::ArrayRef;
use arrow::datatypes::{DataType as ArrowDataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use commons::api::arrow_convert::json_values_to_array;
use commons::api::connections::DataConnectionResource;
use commons::api::connector::CredentialsResolver;
use commons::api::connector::{DataReader, FlightConnector, Query, QueryOptions, QueryOutput};
use commons::api::diagnostics::{body_excerpt, error_chain};
use commons::api::errors::ConnectorError;
use commons::api::redact::{RedactingReader, Redactor};
use commons::utils::config::ConnectorConfig;
use moka::future::Cache;

use crate::query::{MilvusOperation, MilvusRequestInput};

const KEY_URI: &str = "URI";
const KEY_TOKEN: &str = "TOKEN";
const KEY_DATABASE: &str = "DATABASE";
const KEY_CA_CERT: &str = "CA_CERT";

#[derive(Clone)]
struct MilvusClient {
    http: reqwest::Client,
    base_url: String,
    token: Option<String>,
    database: Option<String>,
}

impl MilvusClient {
    async fn execute(&self, path: &str, mut body: serde_json::Value) -> Result<serde_json::Value, ConnectorError> {
        if let (Some(db), Some(obj)) = (&self.database, body.as_object_mut()) {
            obj.entry("dbName").or_insert(serde_json::json!(db));
        }

        let url = format!("{}{}", self.base_url.trim_end_matches('/'), path);
        let mut req = self.http.post(&url);
        if let Some(ref token) = self.token {
            req = req.bearer_auth(token);
        }

        let response = req.json(&body).send().await.map_err(|e| {
            ConnectorError::ConnectionError(format!("Milvus request {path} failed: {}", error_chain(&e)))
        })?;

        let status = response.status();
        let body = response.text().await.map_err(|e| {
            ConnectorError::ConnectionError(format!(
                "Milvus request {path} failed: reading the response: {}",
                error_chain(&e)
            ))
        })?;

        let json = serde_json::from_str::<serde_json::Value>(&body);
        if !status.is_success() {
            // A non-2xx status comes from the HTTP layer in front of the
            // Milvus API (wrong URI, proxy, authentication), not from a
            // rejected request.
            let detail = json
                .as_ref()
                .ok()
                .and_then(milvus_message)
                .map_or_else(|| body_excerpt(&body), |m| body_excerpt(&m));
            return Err(ConnectorError::ConnectionError(format!(
                "Milvus request {path} failed (HTTP {status}): {detail}"
            )));
        }

        let json = json.map_err(|e| {
            ConnectorError::ConnectionError(format!(
                "Milvus request {path} failed: unexpected response ({e}): {}",
                body_excerpt(&body)
            ))
        })?;

        let code = json.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
        if code != 0 {
            let message = milvus_message(&json).unwrap_or_else(|| "no error message".to_string());
            return Err(ConnectorError::SQLError(format!(
                "Milvus rejected request {path} (code {code}): {}",
                body_excerpt(&message)
            )));
        }

        Ok(json)
    }
}

/// milvus_message returns the `message` field of a Milvus REST response.
fn milvus_message(json: &serde_json::Value) -> Option<String> {
    json.get("message").and_then(|m| m.as_str()).map(str::to_string)
}

pub struct MilvusConnector {
    clients: Cache<String, (MilvusClient, Arc<Redactor>)>,
    config: ConnectorConfig,
}

impl MilvusConnector {
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

const PROVIDER: &str = "milvus";

#[async_trait::async_trait]
impl FlightConnector for MilvusConnector {
    fn provider(&self) -> String {
        PROVIDER.to_string()
    }

    fn description(&self) -> String {
        "Milvus vector database connector".to_string()
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
                async {
                    let base_url = credentials
                        .get(KEY_URI)
                        .ok_or_else(|| ConnectorError::ConnectionError(format!("'{KEY_URI}' credential is required")))?
                        .clone();
                    let token = credentials.get(KEY_TOKEN).cloned();
                    let database = credentials.get(KEY_DATABASE).cloned();

                    let mut builder = reqwest::Client::builder()
                        .connect_timeout(self.config.connection_timeout())
                        .read_timeout(self.config.read_timeout())
                        .timeout(self.config.request_timeout());

                    if let Some(ca_pem) = credentials.get(KEY_CA_CERT) {
                        let cert = reqwest::tls::Certificate::from_pem(ca_pem.as_bytes()).map_err(|e| {
                            ConnectorError::ConnectionError(format!("Invalid CA certificate: {}", error_chain(&e)))
                        })?;
                        builder = builder.add_root_certificate(cert);
                    }

                    let http = builder.build().map_err(|e| {
                        ConnectorError::ConnectionError(format!("Failed to build HTTP client: {}", error_chain(&e)))
                    })?;

                    Ok::<_, ConnectorError>(MilvusClient {
                        http,
                        base_url,
                        token,
                        database,
                    })
                }
                .await
                .map(|client| (client, Arc::clone(&redactor)))
                .map_err(|e| redactor.redact_error(e))
            })
            .await
            .map_err(|e| Arc::try_unwrap(e).unwrap_or_else(|arc| (*arc).clone()))?;

        Ok(Arc::new(RedactingReader::new(MilvusReader { client }, redactor)))
    }
}

pub struct MilvusReader {
    client: MilvusClient,
}

struct MilvusFieldDesc {
    name: String,
    field_type: String,
}

#[async_trait::async_trait]
impl DataReader for MilvusReader {
    fn provider(&self) -> String {
        PROVIDER.to_string()
    }

    #[tracing::instrument(skip_all, fields(connector.provider = PROVIDER))]
    async fn schema(&self, query: &str) -> Result<Arc<Query>, ConnectorError> {
        let request = MilvusRequestInput::parse(query)?;
        let field_descs = self.describe_collection(&request.collection_name).await?;
        let output_fields = request.output_fields();
        let schema = build_schema(&field_descs, output_fields.as_deref(), &request.operation);
        Ok(Arc::new(Query::new(query.to_owned(), Arc::new(schema))))
    }

    #[tracing::instrument(skip_all, fields(connector.provider = PROVIDER, batch_size = options.batch_size))]
    async fn read_tabular(&self, query: Arc<Query>, options: &QueryOptions) -> QueryOutput {
        let request = MilvusRequestInput::parse(&query.query)?;
        let schema = query.schema.clone();
        let batch_size = options.batch_size;

        match request.operation {
            MilvusOperation::Query => self.read_query_paginated(request, schema, batch_size),
            MilvusOperation::Search | MilvusOperation::Get => {
                let endpoint = operation_endpoint(&request.operation);
                let response = self.client.execute(endpoint, request.body).await?;
                let rows = extract_data_rows(response);

                let stream = async_stream::try_stream! {
                    let mut offset = 0;
                    while offset < rows.len() {
                        let end = (offset + batch_size).min(rows.len());
                        let batch = rows_to_record_batch(&schema, &rows[offset..end])?;
                        yield batch;
                        offset = end;
                    }
                };
                Ok(Box::pin(stream))
            },
        }
    }

    #[tracing::instrument(skip_all, fields(connector.provider = PROVIDER))]
    async fn check_connection(&self) -> Result<(), ConnectorError> {
        // Any failure here means the connection settings do not work, even
        // when Milvus answered with an API error such as an authentication
        // failure.
        self.client
            .execute("/v2/vectordb/collections/list", serde_json::json!({}))
            .await
            .map_err(|e| ConnectorError::ConnectionError(e.message().to_string()))?;
        Ok(())
    }
}

impl MilvusReader {
    async fn describe_collection(&self, collection_name: &str) -> Result<Vec<MilvusFieldDesc>, ConnectorError> {
        let body = serde_json::json!({ "collectionName": collection_name });
        let response = self.client.execute("/v2/vectordb/collections/describe", body).await?;

        let fields = response
            .get("data")
            .and_then(|d| d.get("fields"))
            .and_then(|f| f.as_array())
            .ok_or_else(|| ConnectorError::ConnectionError("Invalid describe response: missing fields".to_string()))?;

        Ok(fields
            .iter()
            .filter_map(|f| {
                let name = f.get("name")?.as_str()?.to_string();
                let field_type = f.get("type")?.as_str()?.to_string();
                Some(MilvusFieldDesc { name, field_type })
            })
            .collect())
    }

    fn read_query_paginated(&self, request: MilvusRequestInput, schema: Arc<Schema>, batch_size: usize) -> QueryOutput {
        let client = self.client.clone();
        let page_size = batch_size as i64;

        let stream = async_stream::try_stream! {
            let client_offset = request.offset.unwrap_or(0);
            let client_limit = request.limit;
            let mut fetched: i64 = 0;

            loop {
                let remaining = client_limit.map(|l| l - fetched);
                let this_page = match remaining {
                    Some(r) if r <= 0 => break,
                    Some(r) => r.min(page_size),
                    None => page_size,
                };

                let mut body = request.body.clone();
                if let Some(obj) = body.as_object_mut() {
                    obj.insert("limit".to_string(), serde_json::json!(this_page));
                    obj.insert("offset".to_string(), serde_json::json!(client_offset + fetched));
                }

                let response = client.execute("/v2/vectordb/entities/query", body).await?;
                let rows = extract_data_rows(response);

                if rows.is_empty() {
                    break;
                }

                let num_rows = rows.len();
                let batch = rows_to_record_batch(&schema, &rows)?;
                yield batch;

                fetched += num_rows as i64;

                if (num_rows as i64) < this_page {
                    break;
                }
            }
        };

        Ok(Box::pin(stream))
    }
}

fn operation_endpoint(op: &MilvusOperation) -> &'static str {
    match op {
        MilvusOperation::Query => "/v2/vectordb/entities/query",
        MilvusOperation::Search => "/v2/vectordb/entities/search",
        MilvusOperation::Get => "/v2/vectordb/entities/get",
    }
}

fn extract_data_rows(response: serde_json::Value) -> Vec<serde_json::Value> {
    match response {
        serde_json::Value::Object(mut map) => match map.remove("data") {
            Some(serde_json::Value::Array(arr)) => arr,
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
}

fn build_schema(
    field_descs: &[MilvusFieldDesc],
    output_fields: Option<&[String]>,
    operation: &MilvusOperation,
) -> Schema {
    let type_map: HashMap<&str, &str> = field_descs
        .iter()
        .map(|f| (f.name.as_str(), f.field_type.as_str()))
        .collect();

    let mut arrow_fields: Vec<Field> = if let Some(fields) = output_fields {
        let expanded_fields: Vec<&str> = fields
            .iter()
            .flat_map(|name| {
                if name == "*" {
                    field_descs.iter().map(|field| field.name.as_str()).collect::<Vec<_>>()
                } else {
                    vec![name.as_str()]
                }
            })
            .collect();

        expanded_fields
            .into_iter()
            .map(|name| {
                let arrow_type = type_map
                    .get(name)
                    .map(|t| milvus_type_to_arrow(t))
                    .unwrap_or(ArrowDataType::Utf8);
                Field::new(name, arrow_type, true)
            })
            .collect()
    } else {
        field_descs
            .iter()
            .filter(|f| !is_vector_type(&f.field_type))
            .map(|f| Field::new(&f.name, milvus_type_to_arrow(&f.field_type), true))
            .collect()
    };

    if matches!(operation, MilvusOperation::Search) && !arrow_fields.iter().any(|f| f.name() == "distance") {
        arrow_fields.push(Field::new("distance", ArrowDataType::Float64, true));
    }

    Schema::new(arrow_fields)
}

fn milvus_type_to_arrow(milvus_type: &str) -> ArrowDataType {
    match milvus_type {
        "Bool" => ArrowDataType::Boolean,
        "Int8" => ArrowDataType::Int8,
        "Int16" => ArrowDataType::Int16,
        "Int32" => ArrowDataType::Int32,
        "Int64" => ArrowDataType::Int64,
        "Float" => ArrowDataType::Float32,
        "Double" => ArrowDataType::Float64,
        _ => ArrowDataType::Utf8,
    }
}

fn is_vector_type(milvus_type: &str) -> bool {
    matches!(
        milvus_type,
        "FloatVector" | "Float16Vector" | "BFloat16Vector" | "BinaryVector" | "SparseFloatVector"
    )
}

fn rows_to_record_batch(schema: &Arc<Schema>, rows: &[serde_json::Value]) -> Result<RecordBatch, ConnectorError> {
    let arrays: Vec<ArrayRef> = schema
        .fields()
        .iter()
        .map(|field| {
            let values: Vec<Option<&serde_json::Value>> = rows.iter().map(|row| row.get(field.name())).collect();
            json_values_to_array(field.name(), field.data_type(), &values)
        })
        .collect::<Result<_, _>>()?;

    RecordBatch::try_new(Arc::clone(schema), arrays)
        .map_err(|e| ConnectorError::internal("failed to assemble record batch", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::array::{Array, Int64Array, StringArray};

    #[test]
    fn test_milvus_connector_provider() {
        let connector = MilvusConnector::new(
            Duration::from_secs(300),
            Duration::from_secs(60),
            100,
            ConnectorConfig::default(),
        );
        assert_eq!(connector.provider(), "milvus");
    }

    #[test]
    fn test_milvus_type_to_arrow() {
        assert_eq!(milvus_type_to_arrow("Bool"), ArrowDataType::Boolean);
        assert_eq!(milvus_type_to_arrow("Int8"), ArrowDataType::Int8);
        assert_eq!(milvus_type_to_arrow("Int16"), ArrowDataType::Int16);
        assert_eq!(milvus_type_to_arrow("Int32"), ArrowDataType::Int32);
        assert_eq!(milvus_type_to_arrow("Int64"), ArrowDataType::Int64);
        assert_eq!(milvus_type_to_arrow("Float"), ArrowDataType::Float32);
        assert_eq!(milvus_type_to_arrow("Double"), ArrowDataType::Float64);
        assert_eq!(milvus_type_to_arrow("VarChar"), ArrowDataType::Utf8);
        assert_eq!(milvus_type_to_arrow("JSON"), ArrowDataType::Utf8);
        assert_eq!(milvus_type_to_arrow("Unknown"), ArrowDataType::Utf8);
    }

    #[test]
    fn test_is_vector_type() {
        assert!(is_vector_type("FloatVector"));
        assert!(is_vector_type("Float16Vector"));
        assert!(is_vector_type("BFloat16Vector"));
        assert!(is_vector_type("BinaryVector"));
        assert!(is_vector_type("SparseFloatVector"));
        assert!(!is_vector_type("Int64"));
        assert!(!is_vector_type("VarChar"));
        assert!(!is_vector_type("Bool"));
    }

    #[test]
    fn test_build_schema_excludes_vectors() {
        let field_descs = vec![
            MilvusFieldDesc {
                name: "id".to_string(),
                field_type: "Int64".to_string(),
            },
            MilvusFieldDesc {
                name: "name".to_string(),
                field_type: "VarChar".to_string(),
            },
            MilvusFieldDesc {
                name: "vector".to_string(),
                field_type: "FloatVector".to_string(),
            },
            MilvusFieldDesc {
                name: "active".to_string(),
                field_type: "Bool".to_string(),
            },
        ];
        let schema = build_schema(&field_descs, None, &MilvusOperation::Query);
        assert_eq!(schema.fields().len(), 3);
        assert_eq!(schema.field(0).name(), "id");
        assert_eq!(*schema.field(0).data_type(), ArrowDataType::Int64);
        assert_eq!(schema.field(1).name(), "name");
        assert_eq!(*schema.field(1).data_type(), ArrowDataType::Utf8);
        assert_eq!(schema.field(2).name(), "active");
        assert_eq!(*schema.field(2).data_type(), ArrowDataType::Boolean);
    }

    #[test]
    fn test_build_schema_with_output_fields() {
        let field_descs = vec![
            MilvusFieldDesc {
                name: "id".to_string(),
                field_type: "Int64".to_string(),
            },
            MilvusFieldDesc {
                name: "name".to_string(),
                field_type: "VarChar".to_string(),
            },
            MilvusFieldDesc {
                name: "vector".to_string(),
                field_type: "FloatVector".to_string(),
            },
        ];
        let output = vec!["id".to_string(), "name".to_string()];
        let schema = build_schema(&field_descs, Some(&output), &MilvusOperation::Query);
        assert_eq!(schema.fields().len(), 2);
        assert_eq!(schema.field(0).name(), "id");
        assert_eq!(schema.field(1).name(), "name");
    }

    #[test]
    fn test_build_schema_expands_wildcard_output_fields() {
        let field_descs = vec![
            MilvusFieldDesc {
                name: "id".to_string(),
                field_type: "Int64".to_string(),
            },
            MilvusFieldDesc {
                name: "name".to_string(),
                field_type: "VarChar".to_string(),
            },
        ];
        let output = vec!["*".to_string()];
        let schema = build_schema(&field_descs, Some(&output), &MilvusOperation::Query);

        assert_eq!(schema.fields().len(), 2);
        assert_eq!(schema.field(0).name(), "id");
        assert_eq!(*schema.field(0).data_type(), ArrowDataType::Int64);
        assert_eq!(schema.field(1).name(), "name");
        assert_eq!(*schema.field(1).data_type(), ArrowDataType::Utf8);
    }

    #[test]
    fn test_build_schema_search_adds_distance() {
        let field_descs = vec![
            MilvusFieldDesc {
                name: "id".to_string(),
                field_type: "Int64".to_string(),
            },
            MilvusFieldDesc {
                name: "vector".to_string(),
                field_type: "FloatVector".to_string(),
            },
        ];
        let schema = build_schema(&field_descs, None, &MilvusOperation::Search);
        assert!(schema.fields().iter().any(|f| f.name() == "distance"));
        let distance = schema.fields().iter().find(|f| f.name() == "distance").unwrap();
        assert_eq!(*distance.data_type(), ArrowDataType::Float64);
    }

    #[test]
    fn test_build_schema_search_no_duplicate_distance() {
        let field_descs = vec![MilvusFieldDesc {
            name: "id".to_string(),
            field_type: "Int64".to_string(),
        }];
        let output = vec!["id".to_string(), "distance".to_string()];
        let schema = build_schema(&field_descs, Some(&output), &MilvusOperation::Search);
        let distance_count = schema.fields().iter().filter(|f| f.name() == "distance").count();
        assert_eq!(distance_count, 1);
    }

    #[test]
    fn test_extract_data_rows() {
        let response = serde_json::json!({
            "code": 0,
            "data": [
                {"id": 1, "name": "Alice"},
                {"id": 2, "name": "Bob"}
            ]
        });
        let rows = extract_data_rows(response);
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn test_extract_data_rows_empty() {
        let response = serde_json::json!({"code": 0, "data": []});
        let rows = extract_data_rows(response);
        assert!(rows.is_empty());
    }

    #[test]
    fn test_extract_data_rows_missing() {
        let response = serde_json::json!({"code": 0});
        let rows = extract_data_rows(response);
        assert!(rows.is_empty());
    }

    #[test]
    fn test_rows_to_record_batch() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("id", ArrowDataType::Int64, true),
            Field::new("name", ArrowDataType::Utf8, true),
        ]));
        let rows = vec![
            serde_json::json!({"id": 1, "name": "Alice"}),
            serde_json::json!({"id": 2, "name": "Bob"}),
        ];
        let batch = rows_to_record_batch(&schema, &rows).unwrap();
        assert_eq!(batch.num_rows(), 2);
        assert_eq!(batch.num_columns(), 2);

        let id_arr = batch.column(0).as_any().downcast_ref::<Int64Array>().unwrap();
        assert_eq!(id_arr.value(0), 1);
        assert_eq!(id_arr.value(1), 2);

        let name_arr = batch.column(1).as_any().downcast_ref::<StringArray>().unwrap();
        assert_eq!(name_arr.value(0), "Alice");
        assert_eq!(name_arr.value(1), "Bob");
    }

    #[test]
    fn test_rows_to_record_batch_missing_fields() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("id", ArrowDataType::Int64, true),
            Field::new("missing", ArrowDataType::Utf8, true),
        ]));
        let rows = vec![serde_json::json!({"id": 1})];
        let batch = rows_to_record_batch(&schema, &rows).unwrap();
        assert_eq!(batch.num_rows(), 1);

        let missing_arr = batch.column(1).as_any().downcast_ref::<StringArray>().unwrap();
        assert!(missing_arr.is_null(0));
    }

    #[test]
    fn test_rows_to_record_batch_int8_overflow_propagates() {
        let schema = Arc::new(Schema::new(vec![Field::new("score", ArrowDataType::Int8, true)]));
        let rows = vec![serde_json::json!({"score": 300})];
        let err = rows_to_record_batch(&schema, &rows).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("score"), "should name the field: {msg}");
        assert!(msg.contains("300"), "should include the value: {msg}");
    }

    #[test]
    fn test_operation_endpoint() {
        assert_eq!(
            operation_endpoint(&MilvusOperation::Query),
            "/v2/vectordb/entities/query"
        );
        assert_eq!(
            operation_endpoint(&MilvusOperation::Search),
            "/v2/vectordb/entities/search"
        );
        assert_eq!(operation_endpoint(&MilvusOperation::Get), "/v2/vectordb/entities/get");
    }
}

#[cfg(test)]
mod error_reporting_tests {
    use super::*;
    use commons::test_support::{ECHO_HEADERS, MockHttpServer, StaticCredentials, connection};

    const SECRET: &str = "LEAK-SENTINEL-milvus-token";

    async fn reader(uri: &str) -> Arc<dyn DataReader> {
        MilvusConnector::new(
            Duration::from_secs(60),
            Duration::from_secs(60),
            10,
            ConnectorConfig::default(),
        )
        .get_reader(
            &connection("milvus-1", &[]),
            &StaticCredentials::new(&[("URI", uri), ("TOKEN", SECRET)]),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn unreachable_host_reports_the_cause() {
        let err = reader("http://127.0.0.1:1").await.check_connection().await.unwrap_err();
        let msg = err.message();
        assert!(matches!(err, ConnectorError::ConnectionError(_)));
        assert!(
            msg.starts_with("Milvus request /v2/vectordb/collections/list failed: "),
            "{msg}"
        );
        assert!(msg.to_lowercase().contains("connection refused"), "{msg}");
    }

    #[tokio::test]
    async fn api_error_is_reported_as_rejected_request() {
        let server =
            MockHttpServer::start(200, r#"{"code":100,"message":"collection not found[collection=docs]"}"#).await;
        let err = reader(&server.url())
            .await
            .schema(r#"{"collectionName":"docs"}"#)
            .await
            .err()
            .unwrap();
        assert!(matches!(err, ConnectorError::SQLError(_)), "{err:?}");
        assert_eq!(
            err.message(),
            "Milvus rejected request /v2/vectordb/collections/describe (code 100): collection not found[collection=docs]"
        );
    }

    #[tokio::test]
    async fn check_connection_reports_api_errors_as_connection_errors() {
        let server = MockHttpServer::start(200, r#"{"code":1800,"message":"user hasn't authenticated"}"#).await;
        let err = reader(&server.url()).await.check_connection().await.unwrap_err();
        assert!(matches!(err, ConnectorError::ConnectionError(_)), "{err:?}");
        assert!(err.message().contains("user hasn't authenticated"), "{}", err.message());
    }

    #[tokio::test]
    async fn echoed_token_is_redacted() {
        let server = MockHttpServer::start(401, &format!("denied, got: {ECHO_HEADERS}")).await;
        let msg = reader(&server.url())
            .await
            .check_connection()
            .await
            .unwrap_err()
            .message()
            .to_string();
        assert!(msg.contains("HTTP 401"), "{msg}");
        assert!(msg.contains("authorization: Bearer ***"), "{msg}");
        assert!(!msg.contains(SECRET), "{msg}");
    }
}
