use opentelemetry::KeyValue;
use opentelemetry::global;
use opentelemetry::metrics::{Counter, Histogram};
use std::sync::OnceLock;
use std::time::Duration;

const FLIGHT_RPC_REQUESTS_TOTAL: &str = "dch_flight_rpc_requests_total";
const FLIGHT_RPC_DURATION: &str = "dch_flight_rpc_duration_seconds";

static FLIGHT_RPC_METRICS: OnceLock<FlightRpcMetrics> = OnceLock::new();

struct FlightRpcMetrics {
    requests_total: Counter<u64>,
    duration: Histogram<f64>,
}

impl FlightRpcMetrics {
    fn install() -> &'static FlightRpcMetrics {
        FLIGHT_RPC_METRICS.get_or_init(|| {
            let meter = global::meter("dch-flight-service");
            let requests_total = meter
                .u64_counter(FLIGHT_RPC_REQUESTS_TOTAL)
                .with_description("Total number of Flight RPC requests by method/operation/status")
                .with_unit("{request}")
                .build();
            let duration = meter
                .f64_histogram(FLIGHT_RPC_DURATION)
                .with_description(
                    "Flight RPC handler duration by method/operation/status. For streaming RPCs, this measures setup time before stream consumption.",
                )
                .with_unit("s")
                .build();
            FlightRpcMetrics {
                requests_total,
                duration,
            }
        })
    }
}

/// Record a Flight RPC request. Instruments resolve to no-ops when
/// OpenTelemetry is disabled.
pub fn observe_rpc(method: &'static str, operation: &'static str, status: &'static str, duration: Duration) {
    let metrics = FlightRpcMetrics::install();
    let attributes = [
        KeyValue::new("method", method),
        KeyValue::new("operation", operation),
        KeyValue::new("status", status),
    ];
    metrics.requests_total.add(1, &attributes);
    metrics.duration.record(duration.as_secs_f64(), &attributes);
}
