use actix_web::body::MessageBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::middleware::Next;
use opentelemetry::global;
use opentelemetry::metrics::{Counter, Histogram};
use opentelemetry::propagation::{Extractor, TextMapPropagator};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use std::sync::OnceLock;
use std::time::Instant;
use tracing::Instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;

const REST_HTTP_REQUESTS_TOTAL: &str = "dch_rest_http_requests_total";
const REST_HTTP_DURATION: &str = "dch_rest_http_request_duration_seconds";

static REST_HTTP_METRICS: OnceLock<RestHttpMetrics> = OnceLock::new();

struct RestHttpMetrics {
    requests_total: Counter<u64>,
    duration: Histogram<f64>,
}

impl RestHttpMetrics {
    fn install() -> &'static RestHttpMetrics {
        REST_HTTP_METRICS.get_or_init(|| {
            let meter = global::meter("dch-rest-service");
            let requests_total = meter
                .u64_counter(REST_HTTP_REQUESTS_TOTAL)
                .with_description("Total number of HTTP requests by method/route/status")
                .with_unit("{request}")
                .build();
            let duration = meter
                .f64_histogram(REST_HTTP_DURATION)
                .with_description("HTTP request duration by method/route/status")
                .with_unit("s")
                .build();
            RestHttpMetrics {
                requests_total,
                duration,
            }
        })
    }
}

struct HeaderExtractor<'a> {
    headers: &'a actix_web::http::header::HeaderMap,
}

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.headers.get(key).and_then(|value| value.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.headers.keys().map(|key| key.as_str()).collect()
    }
}

/// Middleware that opens a span per request (linked to an incoming
/// `traceparent` header when present) and records HTTP request metrics
/// with OpenTelemetry.
pub fn otel_http_metrics(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> impl std::future::Future<Output = Result<ServiceResponse<impl MessageBody>, actix_web::Error>> {
    let method = req.method().as_str().to_string();
    let route = req.match_pattern().unwrap_or_else(|| req.path().to_string());

    let span = tracing::info_span!("http request", http.method = %method, http.route = %route);
    let carrier = HeaderExtractor { headers: req.headers() };
    let parent = TraceContextPropagator::new().extract(&carrier);
    // Fails when the OpenTelemetry layer is not installed; the span
    // then stays a regular tracing span.
    let _ = span.set_parent(parent);

    let started = Instant::now();
    async move {
        let response = next.call(req).await?;
        let status_code = response.response().status().as_u16().to_string();

        let metrics = RestHttpMetrics::install();
        let attributes = [
            opentelemetry::KeyValue::new("method", method),
            opentelemetry::KeyValue::new("route", route),
            opentelemetry::KeyValue::new("status_code", status_code),
        ];
        metrics.requests_total.add(1, &attributes);
        metrics.duration.record(started.elapsed().as_secs_f64(), &attributes);

        Ok(response)
    }
    .instrument(span)
}
