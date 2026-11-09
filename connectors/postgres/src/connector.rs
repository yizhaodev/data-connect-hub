use std::sync::Arc;

use arrow::array::{
    ArrayRef, BinaryArray, BooleanArray, Date32Array, Float32Array, Float64Array, Int16Array, Int32Array, Int64Array,
    StringArray, Time64MicrosecondArray, TimestampMicrosecondArray,
};
use arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use arrow::record_batch::RecordBatch;
use commons::api::connections::DataConnectionResource;
use commons::api::connector::{DataReader, QueryOutput, TableInfo};
use commons::api::connector::{Query, QueryOptions};
use commons::api::diagnostics::error_chain;
use commons::api::errors::ConnectorError;
use commons::api::redact::{RedactingReader, Redactor};

use futures::StreamExt;

use commons::api::connector::CredentialsResolver;
use commons::api::connector::FlightConnector;
use commons::utils::config::ConnectorConfig;
use moka::future::Cache;
use sqlx::Acquire;
use sqlx::postgres::{PgConnectOptions, PgRow};
use sqlx::{Column, Executor, PgPool, Row, Statement, TypeInfo};
use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;
use tracing::info;

use crate::pgvector;

const PG_READ_ONLY_SQL_TRANSACTION: &str = "25006";
const KEY_URI: &str = "URI";
const KEY_CA_CERT: &str = "CA_CERT";

/// SQLSTATE classes that mean the server could not serve the request at all
/// (connection exception, invalid authorization, insufficient resources,
/// operator intervention, system error), rather than rejecting the query.
const PG_UNAVAILABLE_CLASSES: &[&str] = &["08", "28", "53", "57", "58"];
/// `query_canceled` is in an "unavailable" class but is usually a statement
/// timeout the client can avoid with a narrower query.
const PG_QUERY_CANCELED: &str = "57014";

/// map_sqlx_error classifies a sqlx error so the client sees whether its query
/// was rejected or the database could not be reached, together with the
/// server's reason.
pub(crate) fn map_sqlx_error(e: sqlx::Error) -> ConnectorError {
    match &e {
        sqlx::Error::Database(db_err) => {
            let code = db_err.code().map(|c| c.into_owned()).unwrap_or_default();
            if code == PG_READ_ONLY_SQL_TRANSACTION {
                return ConnectorError::InvalidRequest("data source is read-only".to_string());
            }
            let hint = db_err
                .try_downcast_ref::<sqlx::postgres::PgDatabaseError>()
                .and_then(|pg| pg.hint());
            classify_database_error(&code, db_err.message(), hint)
        },
        sqlx::Error::Configuration(_) => {
            ConnectorError::ConnectionError(format!("invalid PostgreSQL connection settings: {}", error_chain(&e)))
        },
        sqlx::Error::Io(_) | sqlx::Error::Tls(_) | sqlx::Error::Protocol(_) => {
            ConnectorError::ConnectionError(error_chain(&e))
        },
        sqlx::Error::PoolTimedOut => ConnectorError::ConnectionError(
            "timed out waiting for a PostgreSQL connection; the server may be unreachable or overloaded".to_string(),
        ),
        sqlx::Error::InvalidArgument(_) => ConnectorError::InvalidRequest(e.to_string()),
        // The query ran but a value could not be converted; casting the
        // column in the query (e.g. `col::text`) works around it.
        sqlx::Error::ColumnDecode { .. }
        | sqlx::Error::Decode(_)
        | sqlx::Error::ColumnNotFound(_)
        | sqlx::Error::ColumnIndexOutOfBounds { .. }
        | sqlx::Error::TypeNotFound { .. } => ConnectorError::SQLError(error_chain(&e)),
        _ => ConnectorError::internal("PostgreSQL client error", error_chain(&e)),
    }
}

/// classify_database_error maps an error reported by the PostgreSQL server,
/// keeping its message, SQLSTATE and hint.
fn classify_database_error(code: &str, message: &str, hint: Option<&str>) -> ConnectorError {
    let mut text = message.to_string();
    if !code.is_empty() {
        text.push_str(&format!(" (SQLSTATE {code})"));
    }
    if let Some(hint) = hint {
        text.push_str(&format!("; hint: {hint}"));
    }
    let class = code.get(..2).unwrap_or_default();
    if code != PG_QUERY_CANCELED && PG_UNAVAILABLE_CLASSES.contains(&class) {
        ConnectorError::ConnectionError(text)
    } else {
        ConnectorError::SQLError(text)
    }
}

pub struct PgConnector {
    pools: Cache<String, (PgPool, Arc<Redactor>)>,
    config: ConnectorConfig,
}

const PROVIDER: &str = "postgres";

impl PgConnector {
    pub fn new(cache_ttl: Duration, cache_idle: Duration, cache_max_capacity: u64, config: ConnectorConfig) -> Self {
        Self {
            pools: Cache::builder()
                .time_to_live(cache_ttl)
                .time_to_idle(cache_idle)
                .max_capacity(cache_max_capacity)
                .build(),
            config,
        }
    }
}
#[async_trait::async_trait]
impl FlightConnector for PgConnector {
    fn provider(&self) -> String {
        PROVIDER.to_string()
    }

    fn description(&self) -> String {
        "PostgreSQL connector".to_string()
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
        info!("Creating Postgres reader");

        let connection_timeout = self.config.connection_timeout();
        let cache_key = data_connection.metadata.id.clone();

        let (pool, redactor) = self
            .pools
            .try_get_with(cache_key, async {
                let credentials = credentials_resolver.resolve(data_connection).await?;
                let redactor = Arc::new(Redactor::from_credentials(&credentials));
                connect_pg(&credentials, connection_timeout)
                    .await
                    .map(|pool| (pool, Arc::clone(&redactor)))
                    .map_err(|e| redactor.redact_error(e))
            })
            .await
            .map_err(|e| Arc::try_unwrap(e).unwrap_or_else(|arc| (*arc).clone()))?;

        Ok(Arc::new(RedactingReader::new(PgReader { pool }, redactor)))
    }
}

async fn connect_pg(
    credentials: &HashMap<String, String>,
    connection_timeout: Duration,
) -> Result<PgPool, ConnectorError> {
    let url = credentials
        .get(KEY_URI)
        .ok_or_else(|| ConnectorError::ConnectionError(format!("'{KEY_URI}' credential is required")))?;

    let mut options = PgConnectOptions::from_str(url.as_str())
        .map_err(|e| ConnectorError::ConnectionError(format!("invalid PostgreSQL URL: {}", error_chain(&e))))?;

    if let Some(ca_cert) = credentials.get(KEY_CA_CERT) {
        options = options.ssl_root_cert_from_pem(ca_cert.as_bytes().to_vec());
    }

    // Equivalent to `connect_with`, but keeps the pool so a timeout can be
    // explained by `diagnose`.
    let pool = sqlx::pool::PoolOptions::<sqlx::Postgres>::new()
        .acquire_timeout(connection_timeout)
        .connect_lazy_with(options);
    match pool.acquire().await {
        Ok(_) => Ok(pool),
        Err(e) => {
            let message = diagnose(&pool, e).await.message().to_string();
            Err(ConnectorError::ConnectionError(format!(
                "unable to connect to PostgreSQL: {message}"
            )))
        },
    }
}

/// diagnose maps a sqlx error like [`map_sqlx_error`], but explains a pool
/// timeout. sqlx keeps retrying retryable connect failures (refused
/// connection, unknown host) until the acquire timeout and then reports only
/// `PoolTimedOut`; a single direct connection attempt recovers the cause.
async fn diagnose(pool: &PgPool, e: sqlx::Error) -> ConnectorError {
    if !matches!(e, sqlx::Error::PoolTimedOut) {
        return map_sqlx_error(e);
    }
    let timeout = pool.options().get_acquire_timeout();
    let options = pool.connect_options();
    match tokio::time::timeout(
        timeout,
        <sqlx::PgConnection as sqlx::Connection>::connect_with(&options),
    )
    .await
    {
        Ok(Err(cause)) => ConnectorError::ConnectionError(format!(
            "timed out waiting for a PostgreSQL connection: {}",
            map_sqlx_error(cause).message()
        )),
        _ => map_sqlx_error(e),
    }
}

pub struct PgReader {
    pool: PgPool,
}

impl PgReader {}

#[async_trait::async_trait]
impl DataReader for PgReader {
    fn provider(&self) -> String {
        PROVIDER.to_string()
    }

    #[tracing::instrument(skip_all, fields(connector.provider = PROVIDER))]
    async fn schema(&self, query: &str) -> Result<Arc<Query>, ConnectorError> {
        let statement = match self.pool.prepare(query).await {
            Ok(statement) => statement,
            Err(e) => return Err(diagnose(&self.pool, e).await),
        };

        let fields: Vec<Field> = statement
            .columns()
            .iter()
            .map(|col| Field::new(col.name(), pg_type_to_arrow(col.type_info().name()), true))
            .collect();

        Ok(Arc::new(Query::new(query.to_owned(), Arc::new(Schema::new(fields)))))
    }

    #[tracing::instrument(skip_all, fields(connector.provider = PROVIDER, batch_size = options.batch_size))]
    async fn read_tabular(&self, query: Arc<Query>, options: &QueryOptions) -> QueryOutput {
        let pool = self.pool.clone();
        let schema = query.schema.clone();
        let query = query.query.clone();
        let batch_size = options.batch_size;

        let stream = async_stream::try_stream! {
            let mut conn = match pool.acquire().await {
                Ok(conn) => conn,
                Err(e) => Err(diagnose(&pool, e).await)?,
            };
            let mut tx = conn.begin().await.map_err(map_sqlx_error)?;
            sqlx::query("SET TRANSACTION READ ONLY")
                .execute(&mut *tx)
                .await
                .map_err(map_sqlx_error)?;

            {
                let mut rows = sqlx::query(query.as_str()).fetch(&mut *tx);
                let mut chunk = Vec::with_capacity(batch_size);

                while let Some(row) = rows.next().await {
                    chunk.push(row.map_err(map_sqlx_error)?);

                    if chunk.len() >= batch_size {
                        yield rows_to_batch(&schema, &chunk)?;
                        chunk.clear();
                    }
                }

                if !chunk.is_empty() {
                    yield rows_to_batch(&schema, &chunk)?;
                }
            }

            tx.commit().await.map_err(map_sqlx_error)?;
        };

        Ok(Box::pin(stream))
    }

    #[tracing::instrument(skip_all, fields(connector.provider = PROVIDER))]
    async fn check_connection(&self) -> Result<(), ConnectorError> {
        if let Err(e) = sqlx::query("SELECT 1").execute(&self.pool).await {
            return Err(ConnectorError::ConnectionError(format!(
                "PostgreSQL connection check failed: {}",
                diagnose(&self.pool, e).await.message()
            )));
        }
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
        let rows: Vec<(String, String, String, String)> = match table_name_filter {
            Some(pattern) => sqlx::query_as(
                "SELECT table_catalog, table_schema, table_name, table_type \
                     FROM information_schema.tables \
                     WHERE table_schema NOT IN ('information_schema', 'pg_catalog') \
                     AND table_name LIKE $1 \
                     ORDER BY table_schema, table_name",
            )
            .bind(pattern)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?,
            None => sqlx::query_as(
                "SELECT table_catalog, table_schema, table_name, table_type \
                     FROM information_schema.tables \
                     WHERE table_schema NOT IN ('information_schema', 'pg_catalog') \
                     ORDER BY table_schema, table_name",
            )
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?,
        };

        let mut tables = Vec::with_capacity(rows.len());
        for (catalog, schema_name, table_name, table_type) in rows {
            let table_schema = if include_schema {
                let qualified = format!(
                    "\"{}\".\"{}\"",
                    schema_name.replace('"', "\"\""),
                    table_name.replace('"', "\"\"")
                );
                let query = format!("SELECT * FROM {} LIMIT 0", qualified);
                let statement = self.pool.prepare(&query).await.map_err(map_sqlx_error)?;

                let fields: Vec<Field> = statement
                    .columns()
                    .iter()
                    .map(|col| Field::new(col.name(), pg_type_to_arrow(col.type_info().name()), true))
                    .collect();
                Schema::new(fields)
            } else {
                Schema::empty()
            };

            tables.push(TableInfo {
                catalog,
                schema_name,
                table_name,
                table_type,
                table_schema,
            });
        }

        tracing::Span::current().record("row_count", tables.len());
        Ok(tables)
    }
}

fn rows_to_batch(schema: &Arc<Schema>, rows: &[PgRow]) -> Result<RecordBatch, ConnectorError> {
    let columns = rows[0].columns();
    let arrays: Vec<ArrayRef> = (0..columns.len())
        .map(|col_idx| {
            let col = &columns[col_idx];
            build_array(col.type_info().name(), rows, col_idx)
        })
        .collect::<Result<_, _>>()?;

    RecordBatch::try_new(Arc::clone(schema), arrays)
        .map_err(|e| ConnectorError::internal("failed to assemble record batch", e))
}

/// Strip the schema qualifier and identifier quotes from a type name.
///
/// sqlx names extension types via `oid::regtype::text`, which is
/// schema-qualified (e.g. `ext.vector`, `"my schema".vector`) when the
/// type's schema is not on the session `search_path`. Built-in names never
/// contain a dot, so they pass through unchanged. Only a schema qualifier is
/// stripped; a quoted identifier that itself contains a dot (e.g. `"a.b"`)
/// is not supported.
fn unqualified_type_name(pg_type: &str) -> &str {
    pg_type
        .rsplit_once('.')
        .map_or(pg_type, |(_, name)| name)
        .trim_matches('"')
}

fn pg_type_to_arrow(pg_type: &str) -> DataType {
    match unqualified_type_name(pg_type) {
        "BOOL" => DataType::Boolean,
        "INT2" | "SMALLINT" | "SMALLSERIAL" => DataType::Int16,
        "INT4" | "INT" | "INTEGER" | "SERIAL" => DataType::Int32,
        "INT8" | "BIGINT" | "BIGSERIAL" => DataType::Int64,
        "FLOAT4" | "REAL" => DataType::Float32,
        "FLOAT8" | "DOUBLE PRECISION" => DataType::Float64,
        "BYTEA" => DataType::Binary,
        "TIMESTAMP" => DataType::Timestamp(TimeUnit::Microsecond, None),
        "TIMESTAMPTZ" => DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
        "DATE" => DataType::Date32,
        "TIME" => DataType::Time64(TimeUnit::Microsecond),
        "NUMERIC" => DataType::Utf8,
        "UUID" | "JSON" | "JSONB" => DataType::Utf8,
        // pgvector extension types. Dimension lives in the column typmod,
        // which sqlx does not expose, so a variable-size list is used.
        pgvector::VECTOR | pgvector::HALFVEC => pgvector::list_type(),
        pgvector::SPARSEVEC => DataType::Utf8,
        _ => DataType::Utf8,
    }
}

fn timestamp_to_micros(dt: chrono::NaiveDateTime) -> i64 {
    dt.and_utc().timestamp_micros()
}

fn timestamptz_to_micros(dt: chrono::DateTime<chrono::Utc>) -> i64 {
    dt.timestamp_micros()
}

fn date_to_days(d: chrono::NaiveDate) -> i32 {
    d.signed_duration_since(chrono::NaiveDate::from_ymd_opt(1970, 1, 1).unwrap())
        .num_days() as i32
}

fn time_to_micros(t: chrono::NaiveTime) -> i64 {
    use chrono::Timelike;
    t.num_seconds_from_midnight() as i64 * 1_000_000 + t.nanosecond() as i64 / 1_000
}

fn build_array(pg_type: &str, rows: &[PgRow], col_idx: usize) -> Result<ArrayRef, ConnectorError> {
    let err = map_sqlx_error;
    match unqualified_type_name(pg_type) {
        "BOOL" => {
            let vals: Vec<Option<bool>> = rows
                .iter()
                .map(|r| r.try_get(col_idx))
                .collect::<Result<_, _>>()
                .map_err(err)?;
            Ok(Arc::new(BooleanArray::from(vals)))
        },
        "INT2" | "SMALLINT" | "SMALLSERIAL" => {
            let vals: Vec<Option<i16>> = rows
                .iter()
                .map(|r| r.try_get(col_idx))
                .collect::<Result<_, _>>()
                .map_err(err)?;
            Ok(Arc::new(Int16Array::from(vals)))
        },
        "INT4" | "INT" | "INTEGER" | "SERIAL" => {
            let vals: Vec<Option<i32>> = rows
                .iter()
                .map(|r| r.try_get(col_idx))
                .collect::<Result<_, _>>()
                .map_err(err)?;
            Ok(Arc::new(Int32Array::from(vals)))
        },
        "INT8" | "BIGINT" | "BIGSERIAL" => {
            let vals: Vec<Option<i64>> = rows
                .iter()
                .map(|r| r.try_get(col_idx))
                .collect::<Result<_, _>>()
                .map_err(err)?;
            Ok(Arc::new(Int64Array::from(vals)))
        },
        "FLOAT4" | "REAL" => {
            let vals: Vec<Option<f32>> = rows
                .iter()
                .map(|r| r.try_get(col_idx))
                .collect::<Result<_, _>>()
                .map_err(err)?;
            Ok(Arc::new(Float32Array::from(vals)))
        },
        "FLOAT8" | "DOUBLE PRECISION" => {
            let vals: Vec<Option<f64>> = rows
                .iter()
                .map(|r| r.try_get(col_idx))
                .collect::<Result<_, _>>()
                .map_err(err)?;
            Ok(Arc::new(Float64Array::from(vals)))
        },
        "BYTEA" => {
            let vals: Vec<Option<Vec<u8>>> = rows
                .iter()
                .map(|r| r.try_get(col_idx))
                .collect::<Result<_, _>>()
                .map_err(err)?;
            let vals: Vec<Option<&[u8]>> = vals.iter().map(|v| v.as_deref()).collect();
            Ok(Arc::new(BinaryArray::from(vals)))
        },
        "TIMESTAMP" => {
            let vals: Vec<Option<chrono::NaiveDateTime>> = rows
                .iter()
                .map(|r| r.try_get(col_idx))
                .collect::<Result<_, _>>()
                .map_err(err)?;
            let micros: Vec<Option<i64>> = vals.iter().map(|v| v.map(timestamp_to_micros)).collect();
            Ok(Arc::new(TimestampMicrosecondArray::from(micros)))
        },
        "TIMESTAMPTZ" => {
            let vals: Vec<Option<chrono::DateTime<chrono::Utc>>> = rows
                .iter()
                .map(|r| r.try_get(col_idx))
                .collect::<Result<_, _>>()
                .map_err(err)?;
            let micros: Vec<Option<i64>> = vals.iter().map(|v| v.map(timestamptz_to_micros)).collect();
            Ok(Arc::new(TimestampMicrosecondArray::from(micros).with_timezone("UTC")))
        },
        "DATE" => {
            let vals: Vec<Option<chrono::NaiveDate>> = rows
                .iter()
                .map(|r| r.try_get(col_idx))
                .collect::<Result<_, _>>()
                .map_err(err)?;
            let days: Vec<Option<i32>> = vals.iter().map(|v| v.map(date_to_days)).collect();
            Ok(Arc::new(Date32Array::from(days)))
        },
        "TIME" => {
            let vals: Vec<Option<chrono::NaiveTime>> = rows
                .iter()
                .map(|r| r.try_get(col_idx))
                .collect::<Result<_, _>>()
                .map_err(err)?;
            let micros: Vec<Option<i64>> = vals.iter().map(|v| v.map(time_to_micros)).collect();
            Ok(Arc::new(Time64MicrosecondArray::from(micros)))
        },
        "UUID" => {
            let vals: Vec<Option<uuid::Uuid>> = rows
                .iter()
                .map(|r| r.try_get(col_idx))
                .collect::<Result<_, _>>()
                .map_err(err)?;
            let strs: Vec<Option<String>> = vals.iter().map(|v| v.map(|u| u.to_string())).collect();
            Ok(Arc::new(StringArray::from(strs)))
        },
        "JSON" | "JSONB" => {
            let vals: Vec<Option<serde_json::Value>> = rows
                .iter()
                .map(|r| r.try_get(col_idx))
                .collect::<Result<_, _>>()
                .map_err(err)?;
            let strs: Vec<Option<String>> = vals.into_iter().map(|v| v.map(|j| j.to_string())).collect();
            Ok(Arc::new(StringArray::from(strs)))
        },
        "NUMERIC" => {
            let vals: Vec<Option<bigdecimal::BigDecimal>> = rows
                .iter()
                .map(|r| r.try_get(col_idx))
                .collect::<Result<_, _>>()
                .map_err(err)?;
            let strs: Vec<Option<String>> = vals.into_iter().map(|v| v.map(|d| d.to_string())).collect();
            Ok(Arc::new(StringArray::from(strs)))
        },
        pgvector::VECTOR => pgvector::build_vector_array(rows, col_idx),
        pgvector::HALFVEC => pgvector::build_halfvec_array(rows, col_idx),
        pgvector::SPARSEVEC => pgvector::build_sparsevec_array(rows, col_idx),
        _ => {
            let vals: Vec<Option<String>> = rows
                .iter()
                .map(|r| r.try_get(col_idx))
                .collect::<Result<_, _>>()
                .map_err(err)?;
            Ok(Arc::new(StringArray::from(vals)))
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pg_type_to_arrow_bool() {
        assert_eq!(pg_type_to_arrow("BOOL"), DataType::Boolean);
    }

    #[test]
    fn test_pg_type_to_arrow_int16() {
        assert_eq!(pg_type_to_arrow("INT2"), DataType::Int16);
        assert_eq!(pg_type_to_arrow("SMALLINT"), DataType::Int16);
        assert_eq!(pg_type_to_arrow("SMALLSERIAL"), DataType::Int16);
    }

    #[test]
    fn test_pg_type_to_arrow_int32() {
        assert_eq!(pg_type_to_arrow("INT4"), DataType::Int32);
        assert_eq!(pg_type_to_arrow("INT"), DataType::Int32);
        assert_eq!(pg_type_to_arrow("INTEGER"), DataType::Int32);
        assert_eq!(pg_type_to_arrow("SERIAL"), DataType::Int32);
    }

    #[test]
    fn test_pg_type_to_arrow_int64() {
        assert_eq!(pg_type_to_arrow("INT8"), DataType::Int64);
        assert_eq!(pg_type_to_arrow("BIGINT"), DataType::Int64);
        assert_eq!(pg_type_to_arrow("BIGSERIAL"), DataType::Int64);
    }

    #[test]
    fn test_pg_type_to_arrow_float32() {
        assert_eq!(pg_type_to_arrow("FLOAT4"), DataType::Float32);
        assert_eq!(pg_type_to_arrow("REAL"), DataType::Float32);
    }

    #[test]
    fn test_pg_type_to_arrow_float64() {
        assert_eq!(pg_type_to_arrow("FLOAT8"), DataType::Float64);
        assert_eq!(pg_type_to_arrow("DOUBLE PRECISION"), DataType::Float64);
    }

    #[test]
    fn test_pg_type_to_arrow_binary() {
        assert_eq!(pg_type_to_arrow("BYTEA"), DataType::Binary);
    }

    #[test]
    fn test_pg_type_to_arrow_timestamp() {
        assert_eq!(
            pg_type_to_arrow("TIMESTAMP"),
            DataType::Timestamp(TimeUnit::Microsecond, None)
        );
    }

    #[test]
    fn test_pg_type_to_arrow_timestamptz() {
        assert_eq!(
            pg_type_to_arrow("TIMESTAMPTZ"),
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))
        );
    }

    #[test]
    fn test_pg_type_to_arrow_date() {
        assert_eq!(pg_type_to_arrow("DATE"), DataType::Date32);
    }

    #[test]
    fn test_pg_type_to_arrow_time() {
        assert_eq!(pg_type_to_arrow("TIME"), DataType::Time64(TimeUnit::Microsecond));
    }

    #[test]
    fn test_pg_type_to_arrow_pgvector() {
        assert_eq!(pg_type_to_arrow("vector"), pgvector::list_type());
        assert_eq!(pg_type_to_arrow("halfvec"), pgvector::list_type());
        assert_eq!(pg_type_to_arrow("sparsevec"), DataType::Utf8);
    }

    #[test]
    fn test_pg_type_to_arrow_pgvector_schema_qualified() {
        assert_eq!(pg_type_to_arrow("public.vector"), pgvector::list_type());
        assert_eq!(pg_type_to_arrow("ext.halfvec"), pgvector::list_type());
        assert_eq!(pg_type_to_arrow("\"my schema\".vector"), pgvector::list_type());
        assert_eq!(pg_type_to_arrow("\"My.Schema\".halfvec"), pgvector::list_type());
    }

    #[test]
    fn test_unqualified_type_name() {
        assert_eq!(unqualified_type_name("INT4"), "INT4");
        assert_eq!(unqualified_type_name("DOUBLE PRECISION"), "DOUBLE PRECISION");
        assert_eq!(unqualified_type_name("vector"), "vector");
        assert_eq!(unqualified_type_name("public.vector"), "vector");
        assert_eq!(unqualified_type_name("\"my schema\".vector"), "vector");
    }

    #[test]
    fn test_pg_type_to_arrow_fallback() {
        assert_eq!(pg_type_to_arrow("TEXT"), DataType::Utf8);
        assert_eq!(pg_type_to_arrow("VARCHAR"), DataType::Utf8);
        assert_eq!(pg_type_to_arrow("UUID"), DataType::Utf8);
        assert_eq!(pg_type_to_arrow("JSON"), DataType::Utf8);
        assert_eq!(pg_type_to_arrow("JSONB"), DataType::Utf8);
        assert_eq!(pg_type_to_arrow("NUMERIC"), DataType::Utf8);
    }

    #[test]
    fn test_pg_connector_new() {
        let connector = PgConnector::new(
            Duration::from_secs(300),
            Duration::from_secs(60),
            100,
            ConnectorConfig::default(),
        );
        assert_eq!(connector.provider(), "postgres");
    }

    #[test]
    fn test_timestamp_to_micros() {
        let dt = chrono::NaiveDate::from_ymd_opt(2025, 6, 15)
            .unwrap()
            .and_hms_micro_opt(10, 30, 0, 123_456)
            .unwrap();
        assert_eq!(timestamp_to_micros(dt), 1_749_983_400_123_456);
    }

    #[test]
    fn test_timestamp_to_micros_epoch() {
        let dt = chrono::NaiveDate::from_ymd_opt(1970, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();
        assert_eq!(timestamp_to_micros(dt), 0);
    }

    #[test]
    fn test_timestamp_to_micros_before_epoch() {
        let dt = chrono::NaiveDate::from_ymd_opt(1969, 12, 31)
            .unwrap()
            .and_hms_opt(23, 59, 59)
            .unwrap();
        assert_eq!(timestamp_to_micros(dt), -1_000_000);
    }

    #[test]
    fn test_timestamptz_to_micros() {
        use chrono::TimeZone;
        let dt = chrono::Utc.with_ymd_and_hms(2025, 6, 15, 10, 30, 0).unwrap();
        assert_eq!(timestamptz_to_micros(dt), 1_749_983_400_000_000);
    }

    #[test]
    fn test_date_to_days() {
        let d = chrono::NaiveDate::from_ymd_opt(1970, 1, 1).unwrap();
        assert_eq!(date_to_days(d), 0);

        let d = chrono::NaiveDate::from_ymd_opt(2025, 6, 15).unwrap();
        assert_eq!(date_to_days(d), 20_254);

        let d = chrono::NaiveDate::from_ymd_opt(1969, 12, 31).unwrap();
        assert_eq!(date_to_days(d), -1);
    }

    #[test]
    fn test_time_to_micros() {
        let t = chrono::NaiveTime::from_hms_opt(0, 0, 0).unwrap();
        assert_eq!(time_to_micros(t), 0);

        let t = chrono::NaiveTime::from_hms_micro_opt(13, 45, 30, 123_456).unwrap();
        assert_eq!(time_to_micros(t), 49_530_123_456);

        let t = chrono::NaiveTime::from_hms_micro_opt(23, 59, 59, 999_999).unwrap();
        assert_eq!(time_to_micros(t), 86_399_999_999);
    }
}

#[cfg(test)]
mod error_reporting_tests {
    use super::*;
    use commons::test_support::{StaticCredentials, connection};

    const SECRET: &str = "LEAK-SENTINEL-pg-pw";

    #[test]
    fn rejected_query_keeps_reason_sqlstate_and_hint() {
        let err = classify_database_error(
            "42703",
            "column \"nickname\" does not exist",
            Some("Perhaps you meant to reference the column \"users.name\"."),
        );
        assert!(matches!(err, ConnectorError::SQLError(_)), "{err:?}");
        assert_eq!(
            err.message(),
            "column \"nickname\" does not exist (SQLSTATE 42703); hint: Perhaps you meant to reference the column \"users.name\"."
        );
    }

    #[test]
    fn server_side_failures_are_connection_errors() {
        for code in ["28P01", "08006", "53300", "57P01", "58000"] {
            assert!(
                matches!(
                    classify_database_error(code, "x", None),
                    ConnectorError::ConnectionError(_)
                ),
                "{code}"
            );
        }
        assert!(matches!(
            classify_database_error("57014", "canceling statement due to statement timeout", None),
            ConnectorError::SQLError(_)
        ));
    }

    #[test]
    fn client_side_failures_are_classified() {
        assert!(matches!(
            map_sqlx_error(sqlx::Error::PoolTimedOut),
            ConnectorError::ConnectionError(_)
        ));
        let io = sqlx::Error::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "Connection refused",
        ));
        let err = map_sqlx_error(io);
        assert!(matches!(err, ConnectorError::ConnectionError(_)));
        assert!(err.message().contains("Connection refused"), "{}", err.message());
        assert!(matches!(
            map_sqlx_error(sqlx::Error::WorkerCrashed),
            ConnectorError::Internal { .. }
        ));
    }

    #[tokio::test]
    async fn unreachable_server_reports_the_cause_without_the_password() {
        let config = ConnectorConfig {
            connection_timeout_secs: 2,
            ..ConnectorConfig::default()
        };
        let uri = format!("postgres://alice:{SECRET}@127.0.0.1:1/app");
        let err = PgConnector::new(Duration::from_secs(60), Duration::from_secs(60), 10, config)
            .get_reader(&connection("pg-1", &[]), &StaticCredentials::new(&[("URI", &uri)]))
            .await
            .err()
            .unwrap();
        let msg = err.message();
        assert!(matches!(err, ConnectorError::ConnectionError(_)), "{err:?}");
        assert!(msg.starts_with("unable to connect to PostgreSQL: "), "{msg}");
        assert!(msg.to_lowercase().contains("connection refused"), "{msg}");
        assert!(!msg.contains(SECRET), "{msg}");
    }
}
