use crate::utils::FlightServiceTls;
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
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};

#[derive(Debug, Clone)]
pub struct SupportedConnector {
    pub name: String,
    #[allow(dead_code)]
    pub description: String,
}

pub struct FlightClient {
    endpoint: String,
    tls: FlightServiceTls,
    client: OnceCell<FlightServiceClient<Channel>>,
}

impl FlightClient {
    pub fn new(endpoint: String, tls: FlightServiceTls) -> Self {
        Self {
            endpoint,
            tls,
            client: OnceCell::new(),
        }
    }

    async fn client(&self) -> Result<FlightServiceClient<Channel>, tonic::Status> {
        self.client
            .get_or_try_init(|| async {
                let mut endpoint = Endpoint::from_shared(self.endpoint.clone())
                    .map_err(|e| tonic::Status::internal(format!("invalid Flight endpoint: {e}")))?;

                if let Some(ca_cert_file) = &self.tls.ca_cert_file {
                    let ca_cert = tokio::fs::read(ca_cert_file)
                        .await
                        .map_err(|e| tonic::Status::internal(format!("failed to read Flight CA certificate: {e}")))?;
                    let mut tls_config = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca_cert));
                    if let Some(server_name) = &self.tls.server_name {
                        tls_config = tls_config.domain_name(server_name.clone());
                    }
                    endpoint = endpoint
                        .tls_config(tls_config)
                        .map_err(|e| tonic::Status::internal(format!("invalid Flight TLS configuration: {e}")))?;
                }

                let channel = endpoint
                    .connect()
                    .await
                    .map_err(|e| tonic::Status::unavailable(format!("failed to connect to flight service: {e}")))?;
                Ok(FlightServiceClient::new(channel))
            })
            .await
            .cloned()
    }

    pub async fn get_supported_connectors(
        &self,
        authorization: Option<&str>,
    ) -> Result<Vec<SupportedConnector>, tonic::Status> {
        let mut client = self.client().await?;
        let mut request = tonic::Request::new(Action::new("GetSupportedConnectors", ""));
        add_authorization(&mut request, authorization)?;

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

    pub async fn check_connection(
        &self,
        tenant_id: &str,
        connection_id: &str,
        authorization: Option<&str>,
    ) -> Result<(), tonic::Status> {
        let mut client = self.client().await?;
        let mut request = tonic::Request::new(Action::new("CheckConnection", ""));
        add_authorization(&mut request, authorization)?;
        let metadata = request.metadata_mut();
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

    pub async fn test_credentials(
        &self,
        tenant_id: &str,
        creds: &TestCredentials,
        authorization: Option<&str>,
    ) -> Result<(), tonic::Status> {
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
        let mut request = tonic::Request::new(Action::new("CheckConnection", buf));
        add_authorization(&mut request, authorization)?;
        request.metadata_mut().insert(
            X_TENANT_ID,
            MetadataValue::try_from(tenant_id).map_err(|_| tonic::Status::invalid_argument("invalid tenant_id"))?,
        );

        let mut stream = client.do_action(request).await?.into_inner();
        stream.message().await?;
        Ok(())
    }
}

fn add_authorization(request: &mut tonic::Request<Action>, authorization: Option<&str>) -> Result<(), tonic::Status> {
    let authorization =
        authorization.ok_or_else(|| tonic::Status::unauthenticated("authorization header is required"))?;
    let value = MetadataValue::try_from(authorization)
        .map_err(|_| tonic::Status::invalid_argument("invalid authorization header"))?;
    request.metadata_mut().insert("authorization", value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_is_forwarded_as_grpc_metadata() {
        let mut request = tonic::Request::new(Action::new("CheckConnection", ""));

        add_authorization(&mut request, Some("Bearer test-token")).unwrap();

        assert_eq!(request.metadata().get("authorization").unwrap(), "Bearer test-token");
    }

    #[test]
    fn missing_authorization_is_rejected() {
        let mut request = tonic::Request::new(Action::new("CheckConnection", ""));

        let error = add_authorization(&mut request, None).unwrap_err();

        assert_eq!(error.code(), tonic::Code::Unauthenticated);
    }
}
