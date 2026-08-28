use arrow::array::AsArray;
use arrow::array::StringArray;
use arrow::record_batch::RecordBatch;
use arrow_flight::Action;
use arrow_flight::flight_service_client::FlightServiceClient;
use commons::api::creds::TestCredentials;
use commons::api::{X_DATA_CONNECTION_ID, X_TENANT_ID};
use std::sync::Arc;
use tokio::sync::OnceCell;
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, ClientTlsConfig};

#[derive(Debug, Clone)]
pub struct SupportedConnector {
    pub name: String,
    #[allow(dead_code)]
    pub description: String,
}

const AUTHORIZATION_KEY: &str = "authorization";

pub struct FlightClient {
    endpoint: String,
    tls_config: Option<ClientTlsConfig>,
    sa_token_file: Option<String>,
    client: OnceCell<FlightServiceClient<Channel>>,
}

impl FlightClient {
    pub fn new(endpoint: String, tls_config: Option<ClientTlsConfig>, sa_token_file: Option<String>) -> Self {
        Self {
            endpoint,
            tls_config,
            sa_token_file,
            client: OnceCell::new(),
        }
    }

    async fn read_sa_token(&self) -> Result<Option<String>, tonic::Status> {
        let Some(path) = &self.sa_token_file else {
            return Ok(None);
        };
        let token = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| tonic::Status::internal(format!("failed to read SA token from {path}: {e}")))?;
        Ok(Some(token.trim().to_string()))
    }

    fn set_auth(metadata: &mut tonic::metadata::MetadataMap, token: &Option<String>) -> Result<(), tonic::Status> {
        if let Some(token) = token {
            metadata.insert(
                AUTHORIZATION_KEY,
                MetadataValue::try_from(format!("Bearer {token}"))
                    .map_err(|_| tonic::Status::internal("invalid SA token"))?,
            );
        }
        Ok(())
    }

    async fn client(&self) -> Result<FlightServiceClient<Channel>, tonic::Status> {
        self.client
            .get_or_try_init(|| async {
                let mut channel = Channel::from_shared(self.endpoint.clone())
                    .map_err(|e| tonic::Status::internal(format!("invalid flight endpoint: {e}")))?;
                if let Some(tls) = &self.tls_config {
                    channel = channel
                        .tls_config(tls.clone())
                        .map_err(|e| tonic::Status::internal(format!("flight TLS config error: {e}")))?;
                }
                let channel = channel
                    .connect()
                    .await
                    .map_err(|e| tonic::Status::unavailable(format!("failed to connect to flight service: {e}")))?;
                Ok(FlightServiceClient::new(channel))
            })
            .await
            .cloned()
    }

    pub async fn get_supported_connectors(&self) -> Result<Vec<SupportedConnector>, tonic::Status> {
        let mut client = self.client().await?;
        let token = self.read_sa_token().await?;

        let mut request = tonic::Request::new(Action::new("GetSupportedConnectors", ""));
        Self::set_auth(request.metadata_mut(), &token)?;

        let mut stream = client.do_action(request).await?.into_inner();
        let result = stream
            .message()
            .await?
            .ok_or_else(|| tonic::Status::internal("empty response from GetSupportedConnectors"))?;

        let reader = arrow::ipc::reader::StreamReader::try_new(std::io::Cursor::new(result.body), None)
            .map_err(|e| tonic::Status::internal(format!("failed to read IPC stream: {e}")))?;

        let batches: Result<Vec<_>, _> = reader.collect();
        let batches = batches.map_err(|e| tonic::Status::internal(format!("failed to read IPC batches: {e}")))?;

        if batches.is_empty() {
            return Err(tonic::Status::internal(
                "no batches returned from GetSupportedConnectors",
            ));
        }

        let batch = arrow::compute::concat_batches(&batches[0].schema(), &batches)
            .map_err(|e| tonic::Status::internal(format!("failed to concat batches: {e}")))?;

        let names = batch
            .column_by_name("name")
            .ok_or_else(|| tonic::Status::internal("missing 'name' column"))?
            .as_string::<i32>();

        let descriptions = batch
            .column_by_name("description")
            .ok_or_else(|| tonic::Status::internal("missing 'description' column"))?
            .as_string::<i32>();

        Ok((0..batch.num_rows())
            .map(|i| SupportedConnector {
                name: names.value(i).to_string(),
                description: descriptions.value(i).to_string(),
            })
            .collect())
    }

    pub async fn check_connection(&self, tenant_id: &str, connection_id: &str) -> Result<(), tonic::Status> {
        let mut client = self.client().await?;
        let token = self.read_sa_token().await?;

        let mut request = tonic::Request::new(Action::new("CheckConnection", ""));
        let metadata = request.metadata_mut();
        Self::set_auth(metadata, &token)?;
        metadata.insert(
            X_TENANT_ID,
            MetadataValue::try_from(tenant_id).map_err(|_| tonic::Status::invalid_argument("invalid tenant_id"))?,
        );
        metadata.insert(
            X_DATA_CONNECTION_ID,
            MetadataValue::try_from(connection_id)
                .map_err(|_| tonic::Status::invalid_argument("invalid connection_id"))?,
        );

        let mut stream = client.do_action(request).await?.into_inner();
        stream.message().await?;
        Ok(())
    }

    pub async fn test_credentials(&self, tenant_id: &str, creds: &TestCredentials) -> Result<(), tonic::Status> {
        let mut keys = vec!["data_connection_type_id".to_string()];
        let mut values = vec![creds.data_connection_type_id.clone()];
        for (k, v) in &creds.secret {
            keys.push(format!("secret.{k}"));
            values.push(v.clone());
        }

        let batch = RecordBatch::try_from_iter(vec![
            ("key", Arc::new(StringArray::from(keys)) as _),
            ("value", Arc::new(StringArray::from(values)) as _),
        ])
        .map_err(|e| tonic::Status::internal(format!("failed to build credentials batch: {e}")))?;

        let mut buf = Vec::new();
        {
            let mut writer = arrow::ipc::writer::StreamWriter::try_new(&mut buf, &batch.schema())
                .map_err(|e| tonic::Status::internal(format!("failed to create IPC writer: {e}")))?;
            writer
                .write(&batch)
                .map_err(|e| tonic::Status::internal(format!("failed to write IPC batch: {e}")))?;
            writer
                .finish()
                .map_err(|e| tonic::Status::internal(format!("failed to finish IPC stream: {e}")))?;
        }

        let mut client = self.client().await?;
        let token = self.read_sa_token().await?;

        let mut request = tonic::Request::new(Action::new("CheckConnection", buf));
        let metadata = request.metadata_mut();
        Self::set_auth(metadata, &token)?;
        metadata.insert(
            X_TENANT_ID,
            MetadataValue::try_from(tenant_id).map_err(|_| tonic::Status::invalid_argument("invalid tenant_id"))?,
        );

        let mut stream = client.do_action(request).await?.into_inner();
        stream.message().await?;
        Ok(())
    }
}
