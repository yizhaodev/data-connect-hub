//! Test helpers shared by connector crates. Enabled by the `test-support`
//! feature and only meant for dev-dependencies.

use std::collections::HashMap;
use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::api::ResourceMetadata;
use crate::api::connections::{
    CredentialsRef, DataConnection, DataConnectionResource, DataConnectionStatus, DataFormat,
};
use crate::api::connector::CredentialsResolver;
use crate::api::errors::ConnectorError;

/// ECHO_HEADERS in a [`MockHttpServer`] response body is replaced by the raw
/// request headers, mimicking an upstream that reflects the request back,
/// e.g. on an error page.
pub const ECHO_HEADERS: &str = "{{request_headers}}";

/// MockHttpServer answers every HTTP/1.1 request with a fixed status and body.
pub struct MockHttpServer {
    addr: SocketAddr,
}

impl MockHttpServer {
    /// start serves `status` with `body` on an ephemeral localhost port until
    /// the test runtime shuts down.
    pub async fn start(status: u16, body: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock server");
        let addr = listener.local_addr().expect("mock server address");
        let body = body.to_string();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let body = body.clone();
                tokio::spawn(async move {
                    let Some(headers) = read_request(&mut socket).await else {
                        return;
                    };
                    let body = body.replace(ECHO_HEADERS, &headers);
                    let response = format!(
                        "HTTP/1.1 {status} Mock\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        Self { addr }
    }

    /// url returns the server's base URL, e.g. `http://127.0.0.1:41234`.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

/// read_request consumes one request, including its body so the client never
/// sees a reset, and returns the raw header block.
async fn read_request(socket: &mut tokio::net::TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let n = socket.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };
    let headers = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let content_length = headers
        .lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    while buf.len() < header_end + content_length {
        let n = socket.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Some(headers)
}

/// StaticCredentials resolves every connection to the same credentials.
pub struct StaticCredentials(pub HashMap<String, String>);

impl StaticCredentials {
    pub fn new(pairs: &[(&str, &str)]) -> Self {
        Self(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        )
    }
}

#[async_trait::async_trait]
impl CredentialsResolver for StaticCredentials {
    async fn resolve(&self, _connection: &DataConnectionResource) -> Result<HashMap<String, String>, ConnectorError> {
        Ok(self.0.clone())
    }
}

/// connection builds a minimal data connection with the given id and
/// properties.
pub fn connection(id: &str, properties: &[(&str, &str)]) -> DataConnectionResource {
    DataConnectionResource {
        metadata: ResourceMetadata {
            id: id.to_string(),
            tenant_id: Some("default".to_string()),
            created_at: String::new(),
            updated_at: String::new(),
        },
        resource: DataConnection {
            name: id.to_string(),
            data_connection_type_id: "test".to_string(),
            format: DataFormat::Tabular,
            credentials_ref: CredentialsRef::default(),
            properties: properties
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        },
        status: DataConnectionStatus::default(),
    }
}
