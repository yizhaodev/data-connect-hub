//! OpenTelemetry setup shared by the Data Connect Hub services.
//!
//! Configures the OpenTelemetry SDK (traces and metrics) with an OTLP
//! exporter (gRPC via tonic, or HTTP/protobuf via hyper) and bridges
//! `tracing` events into spans.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result};
use opentelemetry::global;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::resource::Resource;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

pub mod config;
pub use config::{OtelConfig, OtlpProtocol};

const METRIC_EXPORT_INTERVAL: Duration = Duration::from_secs(60);

/// OpenTelemetry SDK providers for one service process.
///
/// Keep the instance alive for the whole process lifetime: dropping it
/// shuts the providers down and flushes pending spans/metrics.
pub struct Otel {
    service_name: String,
    tracer_provider: SdkTracerProvider,
    meter_provider: SdkMeterProvider,
}

impl Otel {
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    /// A `'static` tracer backed by the global tracer provider
    /// installed by [init].
    pub fn tracer(&self) -> global::BoxedTracer {
        global::tracer(self.service_name.clone())
    }
}

impl Drop for Otel {
    fn drop(&mut self) {
        if let Err(e) = self.tracer_provider.shutdown() {
            tracing::error!(error = %e, "failed to shut down the tracer provider");
        }
        if let Err(e) = self.meter_provider.shutdown() {
            tracing::error!(error = %e, "failed to shut down the meter provider");
        }
    }
}

/// Initialize the OpenTelemetry SDK from the service configuration.
///
/// Returns `Ok(None)` when telemetry is disabled. When enabled, the
/// providers are also installed as the global defaults so that
/// `opentelemetry::global::meter(...)` works throughout the process.
pub fn init(config: &OtelConfig, fallback_service_name: &str) -> Result<Option<Otel>> {
    let config = config.resolve(fallback_service_name);
    if !config.enabled {
        return Ok(None);
    }

    let protocol = config.protocol();
    let default_endpoint = match protocol {
        OtlpProtocol::Grpc => "http://localhost:4317",
        OtlpProtocol::Http => "http://localhost:4318",
    };
    if config.endpoint.is_none() {
        tracing::warn!(
            default_endpoint,
            "no OTLP endpoint configured; setting otel.endpoint or OTEL_EXPORTER_OTLP_ENDPOINT is recommended"
        );
    }

    let trace_exporter =
        build_trace_exporter(&config).with_context(|| format!("building OTLP {} trace exporter", protocol.as_str()))?;
    let metric_exporter = build_metric_exporter(&config)
        .with_context(|| format!("building OTLP {} metric exporter", protocol.as_str()))?;

    let resource = Resource::builder()
        .with_service_name(config.service_name.clone())
        .build();

    let tracer_provider = SdkTracerProvider::builder()
        .with_resource(resource.clone())
        .with_batch_exporter(trace_exporter)
        .build();
    let meter_provider = SdkMeterProvider::builder()
        .with_resource(resource)
        .with_reader(
            PeriodicReader::builder(metric_exporter)
                .with_interval(METRIC_EXPORT_INTERVAL)
                .build(),
        )
        .build();

    global::set_tracer_provider(tracer_provider.clone());
    global::set_meter_provider(meter_provider.clone());

    tracing::info!(
        service = %config.service_name,
        endpoint = config.endpoint.as_deref().unwrap_or(default_endpoint),
        protocol = protocol.as_str(),
        "OpenTelemetry enabled"
    );

    Ok(Some(Otel {
        service_name: config.service_name,
        tracer_provider,
        meter_provider,
    }))
}

/// Install the global tracing subscriber. When OpenTelemetry is
/// enabled, `tracing` events are also exported as spans.
pub fn install_tracing(otel: Option<&Otel>, json_logs: bool) -> Result<()> {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let registry = tracing_subscriber::registry().with(env_filter);

    let otel_layer = otel.map(|otel| tracing_opentelemetry::layer().with_tracer(otel.tracer()));

    let result = match (otel_layer, json_logs) {
        (Some(otel_layer), true) => registry
            .with(otel_layer)
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_file(true)
                    .with_line_number(true)
                    .with_target(true),
            )
            .try_init(),
        (Some(otel_layer), false) => registry
            .with(otel_layer)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_file(true)
                    .with_line_number(true)
                    .with_target(true),
            )
            .try_init(),
        (None, true) => registry
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_file(true)
                    .with_line_number(true)
                    .with_target(true),
            )
            .try_init(),
        (None, false) => registry
            .with(
                tracing_subscriber::fmt::layer()
                    .with_file(true)
                    .with_line_number(true)
                    .with_target(true),
            )
            .try_init(),
    };

    result.context("installing the tracing subscriber")
}

fn headers_to_metadata(headers: &HashMap<String, String>) -> Result<tonic::metadata::MetadataMap> {
    let mut http_headers = http::HeaderMap::new();
    for (key, value) in headers {
        let name =
            http::HeaderName::from_bytes(key.as_bytes()).with_context(|| format!("invalid OTLP header name: {key}"))?;
        let value =
            http::HeaderValue::from_str(value).with_context(|| format!("invalid OTLP header value for {key}"))?;
        http_headers.append(name, value);
    }
    Ok(tonic::metadata::MetadataMap::from_headers(http_headers))
}

fn build_trace_exporter(config: &OtelConfig) -> Result<opentelemetry_otlp::SpanExporter> {
    use opentelemetry_otlp::{SpanExporter, WithExportConfig, WithHttpConfig, WithTonicConfig};

    match config.protocol() {
        OtlpProtocol::Grpc => {
            let mut builder = SpanExporter::builder().with_tonic();
            if let Some(endpoint) = &config.endpoint {
                builder = builder.with_endpoint(endpoint.clone());
            }
            if !config.headers.is_empty() {
                builder = builder.with_metadata(headers_to_metadata(&config.headers)?);
            }
            builder.build().map_err(Into::into)
        },
        OtlpProtocol::Http => {
            let mut builder = SpanExporter::builder().with_http();
            if let Some(endpoint) = &config.endpoint {
                builder = builder.with_endpoint(endpoint.clone());
            }
            if !config.headers.is_empty() {
                builder = builder.with_headers(config.headers.clone());
            }
            builder.build().map_err(Into::into)
        },
    }
}

fn build_metric_exporter(config: &OtelConfig) -> Result<opentelemetry_otlp::MetricExporter> {
    use opentelemetry_otlp::{MetricExporter, WithExportConfig, WithHttpConfig, WithTonicConfig};

    match config.protocol() {
        OtlpProtocol::Grpc => {
            let mut builder = MetricExporter::builder().with_tonic();
            if let Some(endpoint) = &config.endpoint {
                builder = builder.with_endpoint(endpoint.clone());
            }
            if !config.headers.is_empty() {
                builder = builder.with_metadata(headers_to_metadata(&config.headers)?);
            }
            builder.build().map_err(Into::into)
        },
        OtlpProtocol::Http => {
            let mut builder = MetricExporter::builder().with_http();
            if let Some(endpoint) = &config.endpoint {
                builder = builder.with_endpoint(endpoint.clone());
            }
            if !config.headers.is_empty() {
                builder = builder.with_headers(config.headers.clone());
            }
            builder.build().map_err(Into::into)
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::trace::Tracer;

    #[tokio::test]
    async fn test_init_and_tracing_with_unreachable_collector() {
        let config = OtelConfig {
            enabled: true,
            service_name: "dch-test".to_string(),
            endpoint: Some("http://127.0.0.1:1".to_string()),
            protocol: Some(OtlpProtocol::Grpc),
            headers: Default::default(),
        };

        let otel = init(&config, "dch-test").unwrap().unwrap();
        assert_eq!(otel.service_name(), "dch-test");

        install_tracing(Some(&otel), false).unwrap();

        let tracer = global::tracer("dch-test");
        tracer.in_span("test-span", |_| {});

        let meter = global::meter("dch-test");
        let counter = meter.u64_counter("test_counter").build();
        counter.add(1, &[]);

        // Dropping the providers flushes; exports fail fast against the
        // unreachable collector but must not panic.
        drop(otel);
    }

    #[test]
    fn test_init_disabled() {
        let config = OtelConfig {
            enabled: false,
            ..Default::default()
        };
        assert!(init(&config, "dch-test").unwrap().is_none());
    }

    #[test]
    fn test_protocol_from_env() {
        assert_eq!(OtlpProtocol::from_env("grpc"), Some(OtlpProtocol::Grpc));
        assert_eq!(OtlpProtocol::from_env("HTTP"), Some(OtlpProtocol::Http));
        assert_eq!(OtlpProtocol::from_env("http/protobuf"), Some(OtlpProtocol::Http));
        assert_eq!(OtlpProtocol::from_env("grpc-web"), None);
        assert_eq!(OtlpProtocol::from_env("nonsense"), None);
    }

    #[test]
    fn test_config_deserialize() {
        let json = r#"{
            "enabled": true,
            "service_name": "dch-flight-service",
            "endpoint": "http://otel-collector:4317",
            "protocol": "grpc"
        }"#;
        let config: OtelConfig = serde_json::from_str(json).unwrap();
        assert!(config.enabled);
        assert_eq!(config.service_name, "dch-flight-service");
        assert_eq!(config.endpoint.as_deref(), Some("http://otel-collector:4317"));
        assert_eq!(config.protocol(), OtlpProtocol::Grpc);
    }

    #[test]
    fn test_config_defaults() {
        let config: OtelConfig = serde_json::from_str("{}").unwrap();
        assert!(!config.enabled);
        assert!(config.service_name.is_empty());
        assert_eq!(config.endpoint, None);
        assert_eq!(config.protocol(), OtlpProtocol::Grpc);
    }
}
