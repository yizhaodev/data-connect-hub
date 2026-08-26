use serde::Deserialize;
use std::collections::HashMap;

/// OTLP transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OtlpProtocol {
    /// OTLP over gRPC (default, port 4317).
    #[default]
    Grpc,
    /// OTLP over HTTP with protobuf encoding (port 4318).
    Http,
}

impl OtlpProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Grpc => "grpc",
            Self::Http => "http",
        }
    }

    /// Parse the value of the standard `OTEL_EXPORTER_OTLP_PROTOCOL`
    /// environment variable.
    pub(crate) fn from_env(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "grpc" => Some(Self::Grpc),
            "http" | "http/protobuf" | "httpproto" => Some(Self::Http),
            _ => None,
        }
    }
}

/// OpenTelemetry configuration shared by all services.
///
/// Values set here take precedence over the standard OpenTelemetry
/// environment variables (`OTEL_SERVICE_NAME`,
/// `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_PROTOCOL`),
/// which are used as fallbacks.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct OtelConfig {
    /// Enable OpenTelemetry trace/metric export.
    #[serde(default)]
    pub enabled: bool,
    /// Service name reported in the resource. Falls back to
    /// `OTEL_SERVICE_NAME`, then to the per-service default.
    #[serde(default)]
    pub service_name: String,
    /// OTLP collector endpoint, e.g. `http://otel-collector.observability.svc:4317`.
    /// Falls back to `OTEL_EXPORTER_OTLP_ENDPOINT`, then to the protocol default
    /// (`http://localhost:4317` for gRPC, `http://localhost:4318` for HTTP).
    #[serde(default)]
    pub endpoint: Option<String>,
    /// OTLP protocol. Falls back to `OTEL_EXPORTER_OTLP_PROTOCOL`, then to gRPC.
    #[serde(default)]
    pub protocol: Option<OtlpProtocol>,
    /// Extra headers (e.g. auth tokens) sent to the collector.
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

impl OtelConfig {
    /// Apply the standard OpenTelemetry environment variable fallbacks.
    pub fn resolve(&self, fallback_service_name: &str) -> OtelConfig {
        let mut resolved = self.clone();

        if resolved.service_name.trim().is_empty() {
            resolved.service_name =
                std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| fallback_service_name.to_string());
        }
        if resolved.endpoint.as_deref().is_some_and(str::is_empty) {
            resolved.endpoint = None;
        }
        if resolved.endpoint.is_none() {
            resolved.endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                .ok()
                .filter(|v| !v.trim().is_empty());
        }
        if resolved.protocol.is_none() {
            resolved.protocol = std::env::var("OTEL_EXPORTER_OTLP_PROTOCOL")
                .ok()
                .and_then(|v| OtlpProtocol::from_env(&v));
        }

        resolved
    }

    /// The protocol after applying the environment fallback.
    pub fn protocol(&self) -> OtlpProtocol {
        self.protocol.unwrap_or_default()
    }
}
