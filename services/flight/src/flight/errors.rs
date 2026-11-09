use commons::api::errors::{ConnectorError, MetaStoreError};
use commons::api::redact::{redact_url_userinfo, truncate_message};
use tonic::Status;

pub(crate) fn map_meta_store_error(e: MetaStoreError) -> Status {
    match e {
        MetaStoreError::ResourceNotFound(msg) => Status::not_found(msg),
        MetaStoreError::InvalidRequest(msg) => Status::invalid_argument(msg),
        MetaStoreError::Validation(msg) => Status::invalid_argument(msg),
        MetaStoreError::UnprocessableEntity(msg) => Status::invalid_argument(msg),
        e @ MetaStoreError::Connection(_) => {
            tracing::error!(error = %e, "metadata store connection failed");
            Status::unavailable("metadata service unavailable")
        },
        e @ MetaStoreError::Config(_) => {
            tracing::error!(error = %e, "metadata store config error");
            Status::internal("metadata service configuration error")
        },
        e @ MetaStoreError::Query(_) => {
            tracing::error!(error = %e, "metadata store query failed");
            Status::internal("metadata query error")
        },
        e @ MetaStoreError::Conflict(_) => {
            tracing::warn!(error = %e, "metadata store conflict");
            Status::already_exists("resource already exists")
        },
        e @ MetaStoreError::Serialization(_) => {
            tracing::error!(error = %e, "metadata serialization failed");
            Status::internal("metadata serialization error")
        },
        e @ MetaStoreError::Deserialization(_) => {
            tracing::error!(error = %e, "metadata deserialization failed");
            Status::internal("metadata deserialization error; see service logs for details")
        },
    }
}

/// MAX_CLIENT_MESSAGE_BYTES caps the message of a connector error returned to
/// the client. gRPC carries it in the `grpc-message` trailer, which peers
/// reject when it grows past their header size limit.
const MAX_CLIENT_MESSAGE_BYTES: usize = 1024;

/// map_connector_error converts a connector error into the client response.
/// Connector messages are returned so the client can diagnose its request or
/// connection settings, except for [`ConnectorError::Internal`] whose detail
/// is only logged. Readers already redact known credential values; URL
/// passwords are masked here once more as a last line of defense.
pub(crate) fn map_connector_error(e: ConnectorError) -> Status {
    let e = e.map_messages(redact_url_userinfo);
    let msg = |prefix: &str| truncate_message(&format!("{prefix}{}", e.message()), MAX_CLIENT_MESSAGE_BYTES);
    match &e {
        ConnectorError::InvalidRequest(_) => Status::invalid_argument(msg("")),
        ConnectorError::NoDataError => Status::not_found("no data found"),
        ConnectorError::ConnectionError(_) => {
            tracing::error!(error = %e, "connector connection failed");
            Status::unavailable(msg("data source connection failed: "))
        },
        // The data source rejected the query; server-side failures are
        // reported as ConnectionError or Internal instead.
        ConnectorError::SQLError(_) => {
            tracing::warn!(error = %e, "connector rejected query");
            Status::invalid_argument(msg("query execution failed: "))
        },
        ConnectorError::ConfigError(_) => {
            tracing::error!(error = %e, "connector config error");
            Status::internal(msg("connector configuration error: "))
        },
        ConnectorError::IOError(_) => {
            tracing::error!(error = %e, "connector IO error");
            Status::internal(msg("data source IO error: "))
        },
        ConnectorError::NotFound(_) => Status::not_found(msg("")),
        ConnectorError::UnsupportedOperation(_) => {
            tracing::error!(error = %e, "connector unsupported operation");
            Status::unimplemented(msg("unsupported operation: "))
        },
        ConnectorError::Internal { .. } => {
            tracing::error!(error = %e, "connector internal error");
            Status::internal(msg(""))
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::Code;

    #[test]
    fn connector_messages_reach_the_client() {
        let status = map_connector_error(ConnectorError::IOError("Failed to read 'a.csv'".to_string()));
        assert_eq!(status.code(), Code::Internal);
        assert_eq!(status.message(), "data source IO error: Failed to read 'a.csv'");

        let status = map_connector_error(ConnectorError::UnsupportedOperation("binary reads".to_string()));
        assert_eq!(status.code(), Code::Unimplemented);
        assert_eq!(status.message(), "unsupported operation: binary reads");

        let status = map_connector_error(ConnectorError::ConnectionError("dns error: no such host".to_string()));
        assert_eq!(status.code(), Code::Unavailable);
        assert_eq!(
            status.message(),
            "data source connection failed: dns error: no such host"
        );
    }

    #[test]
    fn rejected_query_is_invalid_argument() {
        let status = map_connector_error(ConnectorError::SQLError(
            "relation \"userz\" does not exist (SQLSTATE 42P01)".to_string(),
        ));
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(
            status.message(),
            "query execution failed: relation \"userz\" does not exist (SQLSTATE 42P01)"
        );
    }

    #[test]
    fn internal_detail_stays_in_the_log() {
        let status = map_connector_error(ConnectorError::internal(
            "failed to resolve connection credentials",
            "secrets \"conn-1\" is forbidden in namespace \"dch\"",
        ));
        assert_eq!(status.code(), Code::Internal);
        assert_eq!(status.message(), "failed to resolve connection credentials");
    }

    #[test]
    fn url_passwords_are_masked() {
        let status = map_connector_error(ConnectorError::ConnectionError(
            "error sending request for url (https://elastic:changeme@es:9200/)".to_string(),
        ));
        assert_eq!(
            status.message(),
            "data source connection failed: error sending request for url (https://elastic:***@es:9200/)"
        );
    }

    #[test]
    fn long_messages_are_truncated() {
        let status = map_connector_error(ConnectorError::SQLError("x".repeat(4096)));
        assert!(status.message().len() < MAX_CLIENT_MESSAGE_BYTES + 32);
        assert!(status.message().ends_with("... (truncated)"));
    }
}
