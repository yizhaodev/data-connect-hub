use std::collections::HashMap;
use std::io::Write;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use arrow::array::{
    ArrayRef, BinaryArray, BooleanArray, Date32Array, Float64Array, Int64Array, StringArray, TimestampMillisecondArray,
};
use arrow::datatypes::{DataType as ArrowDataType, Field, Schema, TimeUnit};
use arrow::record_batch::RecordBatch;
use commons::api::connections::DataConnectionResource;
use commons::api::connector::CredentialsResolver;
use commons::api::connector::{DataReader, FlightConnector, Query, QueryOptions, QueryOutput};
use commons::api::diagnostics::error_chain;
use commons::api::errors::ConnectorError;
use commons::api::redact::{RedactingReader, Redactor};
use commons::utils::config::ConnectorConfig;
use futures::Stream;
use moka::future::Cache;
use neo4rs::{BoltType, Graph};
use tempfile::NamedTempFile;

use crate::types;

const KEY_URI: &str = "URI";
const KEY_USERNAME: &str = "USERNAME";
const KEY_PASSWORD: &str = "PASSWORD";
const KEY_DATABASE: &str = "DATABASE";
const KEY_CA_CERT: &str = "CA_CERT";

pub struct Neo4jConnector {
    graphs: Cache<String, (Graph, Arc<Redactor>)>,
    config: ConnectorConfig,
}

impl Neo4jConnector {
    pub fn new(cache_ttl: Duration, cache_idle: Duration, cache_max_capacity: u64, config: ConnectorConfig) -> Self {
        Self {
            graphs: Cache::builder()
                .time_to_live(cache_ttl)
                .time_to_idle(cache_idle)
                .max_capacity(cache_max_capacity)
                .build(),
            config,
        }
    }
}

async fn build_graph(
    credentials: &HashMap<String, String>,
    connection_timeout: Duration,
) -> Result<Graph, ConnectorError> {
    let uri = credentials
        .get(KEY_URI)
        .ok_or_else(|| ConnectorError::ConnectionError(format!("'{KEY_URI}' credential is required")))?;
    let username = credentials
        .get(KEY_USERNAME)
        .cloned()
        .unwrap_or_else(|| "neo4j".to_string());
    let password = credentials
        .get(KEY_PASSWORD)
        .ok_or_else(|| ConnectorError::ConnectionError(format!("'{KEY_PASSWORD}' credential is required")))?;
    let database = credentials
        .get(KEY_DATABASE)
        .cloned()
        .unwrap_or_else(|| "neo4j".to_string());

    // The URI scheme selects the TLS mode of the Bolt connection:
    //   * `neo4j://`     -> plaintext (no TLS)
    //   * `neo4j+s://`   -> TLS, verify the server certificate against the
    //                       trust store (system roots plus any CA provided below)
    //   * `neo4j+ssc://` -> TLS; neo4rs 0.8 still verifies the server
    //                       certificate
    // The connector does not force a scheme here; the operator supplies the
    // appropriate `URI`. For a private/custom CA, use `neo4j+s` and
    // provide it through `CA_CERT`.
    let mut builder = neo4rs::ConfigBuilder::default()
        .uri(uri)
        .user(&username)
        .password(password)
        .db(database.as_str());

    // neo4rs 0.8 accepts a CA certificate path, while credentials from the
    // Kubernetes Secret contain the PEM contents. Keep the temporary file
    // alive until Graph::connect has built its TLS connector and loaded the
    // certificate; NamedTempFile then removes it automatically.
    let _ca_cert_file = if let Some(ca_cert_pem) = credentials.get(KEY_CA_CERT) {
        let mut file =
            NamedTempFile::new().map_err(|e| ConnectorError::internal("failed to prepare Neo4j CA certificate", e))?;
        file.write_all(ca_cert_pem.as_bytes())
            .map_err(|e| ConnectorError::internal("failed to prepare Neo4j CA certificate", e))?;
        builder = builder.with_client_certificate(file.path());
        Some(file)
    } else {
        None
    };

    let config = builder.build().map_err(|e| {
        ConnectorError::ConnectionError(format!("invalid Neo4j connection settings: {}", error_chain(&e)))
    })?;

    tokio::time::timeout(connection_timeout, Graph::connect(config))
        .await
        .map_err(|_| {
            ConnectorError::ConnectionError(format!(
                "timed out connecting to Neo4j after {}s",
                connection_timeout.as_secs()
            ))
        })?
        .map_err(|e| {
            ConnectorError::ConnectionError(format!("unable to connect to Neo4j: {}", map_neo4j_error(e).message()))
        })
}

const PROVIDER: &str = "neo4j";

#[async_trait::async_trait]
impl FlightConnector for Neo4jConnector {
    fn provider(&self) -> String {
        PROVIDER.to_string()
    }

    fn description(&self) -> String {
        "Neo4j graph database connector".to_string()
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

        let cache_key = data_connection.metadata.id.clone();

        let (graph, redactor) = self
            .graphs
            .try_get_with(cache_key, async {
                let credentials = credentials_resolver.resolve(data_connection).await?;
                let redactor = Arc::new(Redactor::from_credentials(&credentials));
                build_graph(&credentials, connection_timeout)
                    .await
                    .map(|client| (client, Arc::clone(&redactor)))
                    .map_err(|e| redactor.redact_error(e))
            })
            .await
            .map_err(|e| Arc::try_unwrap(e).unwrap_or_else(|arc| (*arc).clone()))?;

        Ok(Arc::new(RedactingReader::new(Neo4jReader { graph }, redactor)))
    }
}

pub struct Neo4jReader {
    graph: Graph,
}

#[async_trait::async_trait]
impl DataReader for Neo4jReader {
    fn provider(&self) -> String {
        PROVIDER.to_string()
    }

    #[tracing::instrument(skip_all, fields(connector.provider = PROVIDER))]
    async fn schema(&self, query: &str) -> Result<Arc<Query>, ConnectorError> {
        let mut result = self
            .graph
            .execute(neo4rs::query(query))
            .await
            .map_err(map_neo4j_error)?;

        let row = match result.next().await.map_err(map_neo4j_error)? {
            Some(row) => row,
            None => {
                return Ok(Arc::new(Query::new(query.to_owned(), Arc::new(Schema::empty()))));
            },
        };

        let json_row: serde_json::Value = row
            .to()
            .map_err(|e| ConnectorError::SQLError(format!("Failed to deserialize row: {e}")))?;

        let obj = json_row
            .as_object()
            .ok_or_else(|| ConnectorError::SQLError("Expected row to be a JSON object".to_string()))?;

        let fields: Vec<Field> = obj
            .keys()
            .map(|key| {
                let arrow_type = match row.get::<BoltType>(key) {
                    Ok(bt) => types::bolt_type_to_arrow(&bt),
                    Err(_) => ArrowDataType::Utf8,
                };
                Field::new(key, arrow_type, true)
            })
            .collect();

        Ok(Arc::new(Query::new(query.to_owned(), Arc::new(Schema::new(fields)))))
    }

    #[tracing::instrument(skip_all, fields(connector.provider = PROVIDER, batch_size = options.batch_size))]
    async fn read_tabular(&self, query: Arc<Query>, options: &QueryOptions) -> QueryOutput {
        let graph = self.graph.clone();
        let schema = query.schema.clone();
        let query = query.query.clone();
        let batch_size = options.batch_size;

        #[allow(clippy::while_let_loop)]
        let stream = async_stream::try_stream! {
            let mut result = graph
                .execute(neo4rs::query(&query))
                .await
                .map_err(map_neo4j_error)?;

            let mut chunk: Vec<neo4rs::Row> = Vec::with_capacity(batch_size);

            loop {
                match result.next().await.map_err(map_neo4j_error)? {
                    Some(row) => {
                        chunk.push(row);
                        if chunk.len() >= batch_size {
                            yield rows_to_record_batch(&schema, &chunk)?;
                            chunk.clear();
                        }
                    }
                    None => break,
                }
            }

            if !chunk.is_empty() {
                yield rows_to_record_batch(&schema, &chunk)?;
            }
        };

        Ok(Box::pin(stream)
            as Pin<
                Box<dyn Stream<Item = Result<RecordBatch, ConnectorError>> + Send>,
            >)
    }

    #[tracing::instrument(skip_all, fields(connector.provider = PROVIDER))]
    async fn check_connection(&self) -> Result<(), ConnectorError> {
        let mut result = self
            .graph
            .execute(neo4rs::query("RETURN 1"))
            .await
            .map_err(map_neo4j_error)?;

        result.next().await.map_err(map_neo4j_error)?;
        Ok(())
    }
}

/// map_neo4j_error classifies a neo4rs error so the client sees whether its
/// query was rejected or the database could not be reached, together with the
/// reason.
fn map_neo4j_error(e: neo4rs::Error) -> ConnectorError {
    match &e {
        neo4rs::Error::Neo4j(server) => classify_server_error(server.code(), server.message()),
        neo4rs::Error::IOError { .. }
        | neo4rs::Error::ConnectionError
        | neo4rs::Error::AuthenticationError(_)
        | neo4rs::Error::UrlParseError(_)
        | neo4rs::Error::UnsupportedScheme(_)
        | neo4rs::Error::InvalidDnsName(_)
        | neo4rs::Error::InvalidConfig
        | neo4rs::Error::UnsupportedVersion(_)
        | neo4rs::Error::UnexpectedMessage(_)
        | neo4rs::Error::UnknownMessage(_) => ConnectorError::ConnectionError(error_chain(&e)),
        neo4rs::Error::DeserializationError(_)
        | neo4rs::Error::ConversionError
        | neo4rs::Error::UnknownType(_)
        | neo4rs::Error::InvalidTypeMarker(_) => ConnectorError::SQLError(error_chain(&e)),
        _ => ConnectorError::internal("Neo4j client error", error_chain(&e)),
    }
}

/// classify_server_error maps an error reported by the Neo4j server by its
/// status code (`Neo.<Classification>.<Category>.<Title>`), keeping the
/// server's message and code.
fn classify_server_error(code: &str, message: &str) -> ConnectorError {
    let text = format!("{message} ({code})");
    match code {
        "Neo.ClientError.Statement.AccessMode" => {
            ConnectorError::InvalidRequest(format!("data source is read-only: {text}"))
        },
        "Neo.ClientError.Security.Forbidden" => ConnectorError::InvalidRequest(format!("permission denied: {text}")),
        // Authentication failures and a wrong DATABASE setting are problems
        // with the connection settings, not with the query.
        c if c.starts_with("Neo.ClientError.Security.") || c == "Neo.ClientError.Database.DatabaseNotFound" => {
            ConnectorError::ConnectionError(text)
        },
        c if c.starts_with("Neo.ClientError.") => ConnectorError::SQLError(text),
        // TransientError and DatabaseError are failures on the server side.
        _ => ConnectorError::ConnectionError(text),
    }
}

fn rows_to_record_batch(schema: &Arc<Schema>, rows: &[neo4rs::Row]) -> Result<RecordBatch, ConnectorError> {
    let arrays: Vec<ArrayRef> = schema
        .fields()
        .iter()
        .map(|field| build_column_array(field.name(), field.data_type(), rows))
        .collect::<Result<_, _>>()?;

    RecordBatch::try_new(Arc::clone(schema), arrays)
        .map_err(|e| ConnectorError::internal("failed to assemble record batch", e))
}

fn build_column_array(
    field_name: &str,
    data_type: &ArrowDataType,
    rows: &[neo4rs::Row],
) -> Result<ArrayRef, ConnectorError> {
    match data_type {
        ArrowDataType::Boolean => {
            let vals: Vec<Option<bool>> = rows
                .iter()
                .map(|r| r.get::<Option<bool>>(field_name).ok().flatten())
                .collect();
            Ok(Arc::new(BooleanArray::from(vals)))
        },
        ArrowDataType::Int64 => {
            let vals: Vec<Option<i64>> = rows
                .iter()
                .map(|r| r.get::<Option<i64>>(field_name).ok().flatten())
                .collect();
            Ok(Arc::new(Int64Array::from(vals)))
        },
        ArrowDataType::Float64 => {
            let vals: Vec<Option<f64>> = rows
                .iter()
                .map(|r| r.get::<Option<f64>>(field_name).ok().flatten())
                .collect();
            Ok(Arc::new(Float64Array::from(vals)))
        },
        ArrowDataType::Date32 => {
            let epoch = chrono::NaiveDate::from_ymd_opt(1970, 1, 1).unwrap();
            let vals: Vec<Option<i32>> = rows
                .iter()
                .map(|r| {
                    r.get::<chrono::NaiveDate>(field_name)
                        .ok()
                        .map(|d| (d - epoch).num_days() as i32)
                })
                .collect();
            Ok(Arc::new(Date32Array::from(vals)))
        },
        ArrowDataType::Timestamp(TimeUnit::Millisecond, tz) => {
            let vals: Vec<Option<i64>> = rows
                .iter()
                .map(|r| {
                    r.get::<BoltType>(field_name).ok().and_then(|bt| match bt {
                        BoltType::DateTime(dt) => {
                            let chrono_dt: chrono::DateTime<chrono::FixedOffset> = dt.try_into().ok()?;
                            Some(chrono_dt.timestamp_millis())
                        },
                        BoltType::DateTimeZoneId(_) => r
                            .get::<chrono::DateTime<chrono::FixedOffset>>(field_name)
                            .ok()
                            .map(|dt| dt.timestamp_millis()),
                        BoltType::LocalDateTime(dt) => {
                            let chrono_dt: chrono::NaiveDateTime = dt.try_into().ok()?;
                            Some(chrono_dt.and_utc().timestamp_millis())
                        },
                        _ => None,
                    })
                })
                .collect();
            let arr = TimestampMillisecondArray::from(vals);
            if let Some(tz) = tz {
                Ok(Arc::new(arr.with_timezone(tz.as_ref())))
            } else {
                Ok(Arc::new(arr))
            }
        },
        ArrowDataType::Binary => {
            let bolt_vals: Vec<Option<Vec<u8>>> = rows.iter().map(|r| r.get::<Vec<u8>>(field_name).ok()).collect();
            let refs: Vec<Option<&[u8]>> = bolt_vals.iter().map(|v| v.as_deref()).collect();
            Ok(Arc::new(BinaryArray::from(refs)))
        },
        _ => {
            let vals: Vec<Option<String>> = rows.iter().map(|r| extract_as_string(r, field_name)).collect();
            Ok(Arc::new(StringArray::from(vals)))
        },
    }
}

fn extract_as_string(row: &neo4rs::Row, key: &str) -> Option<String> {
    if let Ok(Some(s)) = row.get::<Option<String>>(key) {
        return Some(s);
    }
    if let Ok(bolt) = row.get::<BoltType>(key) {
        return match bolt {
            BoltType::Null(_) => None,
            other => Some(types::bolt_value_to_json(&other).to_string()),
        };
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::array::Array;

    #[test]
    fn test_connector_provider() {
        let connector = Neo4jConnector::new(
            Duration::from_secs(300),
            Duration::from_secs(60),
            100,
            ConnectorConfig::default(),
        );
        assert_eq!(connector.provider(), "neo4j");
    }

    #[test]
    fn test_connector_description() {
        let connector = Neo4jConnector::new(
            Duration::from_secs(300),
            Duration::from_secs(60),
            100,
            ConnectorConfig::default(),
        );
        assert_eq!(connector.description(), "Neo4j graph database connector");
    }

    #[test]
    fn test_classify_server_error_read_only() {
        let err = classify_server_error(
            "Neo.ClientError.Statement.AccessMode",
            "Writing in read access mode not allowed.",
        );
        assert!(matches!(err, ConnectorError::InvalidRequest(_)));
        let err = classify_server_error(
            "Neo.ClientError.Security.Forbidden",
            "Write operations are not allowed for user 'reader' with roles [reader].",
        );
        assert!(matches!(err, ConnectorError::InvalidRequest(_)));
        assert_eq!(
            err.message(),
            "permission denied: Write operations are not allowed for user 'reader' with roles [reader]. (Neo.ClientError.Security.Forbidden)"
        );
    }

    #[test]
    fn test_classify_server_error_connection_settings() {
        for code in [
            "Neo.ClientError.Security.Unauthorized",
            "Neo.ClientError.Security.AuthenticationRateLimit",
            "Neo.ClientError.Database.DatabaseNotFound",
            "Neo.TransientError.General.DatabaseUnavailable",
            "Neo.DatabaseError.General.UnknownError",
        ] {
            assert!(
                matches!(classify_server_error(code, "x"), ConnectorError::ConnectionError(_)),
                "{code}"
            );
        }
    }

    #[test]
    fn test_classify_server_error_rejected_query() {
        let err = classify_server_error("Neo.ClientError.Statement.SyntaxError", "Invalid input 'BOGUS'");
        assert!(matches!(err, ConnectorError::SQLError(_)));
        assert_eq!(
            err.message(),
            "Invalid input 'BOGUS' (Neo.ClientError.Statement.SyntaxError)"
        );
    }

    #[test]
    fn test_map_neo4j_error_client_side_is_not_read_only() {
        let err = map_neo4j_error(neo4rs::Error::UnsupportedScheme("permission denied".into()));
        assert!(matches!(err, ConnectorError::ConnectionError(_)));
    }

    #[test]
    fn test_map_neo4j_error_io_reports_the_cause() {
        let io = std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "Connection refused (os error 111)",
        );
        let err = map_neo4j_error(neo4rs::Error::IOError { detail: io });
        assert!(matches!(err, ConnectorError::ConnectionError(_)));
        assert_eq!(err.message(), "an IO error occurred: Connection refused (os error 111)");
    }

    #[test]
    fn test_build_column_array_boolean() {
        let fields = neo4rs::BoltList::from(vec![BoltType::String("active".into())]);
        let data1 = neo4rs::BoltList::from(vec![BoltType::Boolean(neo4rs::BoltBoolean { value: true })]);
        let data2 = neo4rs::BoltList::from(vec![BoltType::Boolean(neo4rs::BoltBoolean { value: false })]);
        let rows = vec![
            neo4rs::Row::new(fields.clone(), data1),
            neo4rs::Row::new(fields.clone(), data2),
        ];
        let arr = build_column_array("active", &ArrowDataType::Boolean, &rows).unwrap();
        let bool_arr = arr.as_any().downcast_ref::<BooleanArray>().unwrap();
        assert_eq!(bool_arr.len(), 2);
        assert!(bool_arr.value(0));
        assert!(!bool_arr.value(1));
    }

    #[test]
    fn test_build_column_array_int64() {
        let fields = neo4rs::BoltList::from(vec![BoltType::String("count".into())]);
        let data1 = neo4rs::BoltList::from(vec![BoltType::Integer(neo4rs::BoltInteger { value: 42 })]);
        let data2 = neo4rs::BoltList::from(vec![BoltType::Null(neo4rs::BoltNull)]);
        let rows = vec![
            neo4rs::Row::new(fields.clone(), data1),
            neo4rs::Row::new(fields.clone(), data2),
        ];
        let arr = build_column_array("count", &ArrowDataType::Int64, &rows).unwrap();
        let int_arr = arr.as_any().downcast_ref::<Int64Array>().unwrap();
        assert_eq!(int_arr.value(0), 42);
        assert!(int_arr.is_null(1));
    }

    #[test]
    fn test_build_column_array_float64() {
        let fields = neo4rs::BoltList::from(vec![BoltType::String("score".into())]);
        let data = neo4rs::BoltList::from(vec![BoltType::Float(neo4rs::BoltFloat { value: 2.72 })]);
        let rows = vec![neo4rs::Row::new(fields, data)];
        let arr = build_column_array("score", &ArrowDataType::Float64, &rows).unwrap();
        let f_arr = arr.as_any().downcast_ref::<Float64Array>().unwrap();
        assert!((f_arr.value(0) - 2.72).abs() < f64::EPSILON);
    }

    #[test]
    fn test_build_column_array_utf8_fallback() {
        let fields = neo4rs::BoltList::from(vec![BoltType::String("name".into())]);
        let data = neo4rs::BoltList::from(vec![BoltType::String("Alice".into())]);
        let rows = vec![neo4rs::Row::new(fields, data)];
        let arr = build_column_array("name", &ArrowDataType::Utf8, &rows).unwrap();
        let str_arr = arr.as_any().downcast_ref::<StringArray>().unwrap();
        assert_eq!(str_arr.value(0), "Alice");
    }

    #[test]
    fn test_rows_to_record_batch() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("name", ArrowDataType::Utf8, true),
            Field::new("age", ArrowDataType::Int64, true),
        ]));
        let fields = neo4rs::BoltList::from(vec![BoltType::String("name".into()), BoltType::String("age".into())]);
        let data1 = neo4rs::BoltList::from(vec![
            BoltType::String("Alice".into()),
            BoltType::Integer(neo4rs::BoltInteger { value: 30 }),
        ]);
        let data2 = neo4rs::BoltList::from(vec![
            BoltType::String("Bob".into()),
            BoltType::Integer(neo4rs::BoltInteger { value: 25 }),
        ]);
        let rows = vec![
            neo4rs::Row::new(fields.clone(), data1),
            neo4rs::Row::new(fields.clone(), data2),
        ];
        let batch = rows_to_record_batch(&schema, &rows).unwrap();
        assert_eq!(batch.num_rows(), 2);
        assert_eq!(batch.num_columns(), 2);

        let name_arr = batch.column(0).as_any().downcast_ref::<StringArray>().unwrap();
        assert_eq!(name_arr.value(0), "Alice");
        assert_eq!(name_arr.value(1), "Bob");

        let age_arr = batch.column(1).as_any().downcast_ref::<Int64Array>().unwrap();
        assert_eq!(age_arr.value(0), 30);
        assert_eq!(age_arr.value(1), 25);
    }
}
