"""E2E tests for the custom Flight actions (PR #173).

Covers the two actions dispatched by ``dispatch_action``:

- ``GetSupportedConnectors`` — returns an Arrow IPC table of supported
  connector providers.
- ``CheckConnection`` — verifies connectivity either for a stored data
  connection (``x-data-connection-id`` header, empty body) or for inline
  credentials passed in the action body (``key``/``value`` Arrow IPC stream).
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pyarrow as pa
import pyarrow.flight as flight
import pytest
from data_connect_hub.client import _build_urls

ACTION_GET_SUPPORTED_CONNECTORS = "GetSupportedConnectors"
ACTION_CHECK_CONNECTION = "CheckConnection"

# The flight service registers connectors conditionally on its deployment
# config (sqlite/s3/milvus/elasticsearch/neo4j/uri are optional); postgres is
# enabled by default, so it is the only provider asserted unconditionally.


def _flight_client(
    gateway_endpoint: str,
    *,
    tenant_id: str = "",
    token: str = "",
    connection_id: str | None = None,
    ca_cert: str | None = None,
    insecure: bool = False,
) -> tuple[flight.FlightClient, flight.FlightCallOptions]:
    """Create a raw Flight client with explicit auth/tenant/connection headers."""
    _, url = _build_urls(gateway_endpoint)
    kwargs: dict = {}
    if insecure:
        kwargs["disable_server_verification"] = True
    if ca_cert:
        kwargs["tls_root_certs"] = Path(ca_cert).read_bytes()

    client = flight.connect(url, **kwargs)
    headers: list[tuple[bytes, bytes]] = []
    if tenant_id:
        headers.append((b"x-tenant-id", tenant_id.encode()))
    if token:
        headers.append((b"authorization", f"Bearer {token}".encode()))
    if connection_id:
        headers.append((b"x-data-connection-id", connection_id.encode()))
    opts = flight.FlightCallOptions(headers=headers)
    return client, opts


def _do_action(
    client: flight.FlightClient,
    opts: flight.FlightCallOptions,
    action_type: str,
    body: bytes = b"",
) -> list[flight.Result]:
    return list(client.do_action(flight.Action(action_type, body), opts))


def _decode_ipc(body: bytes) -> pa.Table | None:
    if not body:
        return None
    return pa.ipc.open_stream(body).read_all()


def _encode_kv(pairs: dict[str, str]) -> bytes:
    """Encode key/value pairs as the Arrow IPC credentials stream."""
    batch = pa.record_batch(
        [pa.array(list(pairs.keys()), pa.string()), pa.array(list(pairs.values()), pa.string())],
        names=["key", "value"],
    )
    sink = pa.BufferOutputStream()
    with pa.ipc.new_stream(sink, batch.schema) as writer:
        writer.write_batch(batch)
    return sink.get().to_pybytes()


class TestGetSupportedConnectors:
    def test_returns_connector_table(
        self, gateway_endpoint: str, auth_token: str, tenant_id: str, ca_cert: str | None, insecure: bool
    ) -> None:
        client, opts = _flight_client(
            gateway_endpoint, tenant_id=tenant_id, token=auth_token, ca_cert=ca_cert, insecure=insecure
        )
        try:
            results = _do_action(client, opts, ACTION_GET_SUPPORTED_CONNECTORS)
        finally:
            client.close()

        assert len(results) == 1
        table = _decode_ipc(results[0].body.to_pybytes())
        assert table is not None
        assert set(table.column_names) == {"name", "description"}
        names = table.column("name").to_pylist()
        assert names, "expected at least one supported connector"
        assert all(isinstance(n, str) and n for n in names)
        assert "postgres" in names
        descriptions = table.column("description").to_pylist()
        assert len(descriptions) == len(names)
        assert all(isinstance(desc, str) and desc for desc in descriptions)

    def test_actions_advertised_by_server(
        self, gateway_endpoint: str, auth_token: str, tenant_id: str, ca_cert: str | None, insecure: bool
    ) -> None:
        client, _ = _flight_client(
            gateway_endpoint, tenant_id=tenant_id, token=auth_token, ca_cert=ca_cert, insecure=insecure
        )
        try:
            actions = {a.type: a for a in client.list_actions()}
        finally:
            client.close()

        assert ACTION_GET_SUPPORTED_CONNECTORS in actions
        assert ACTION_CHECK_CONNECTION in actions
        assert all(a.description for a in actions.values())

    def test_sdk_server_info_exposes_connectors(
        self, gateway_endpoint: str, auth_token: str, tenant_id: str, ca_cert: str | None, insecure: bool
    ) -> None:
        from data_connect_hub import DataConnectClient

        client = DataConnectClient(
            gateway_endpoint, token=auth_token, tenant_id=tenant_id, ca_cert=ca_cert, insecure=insecure
        )
        try:
            info = client.server_info()
        finally:
            client.close()

        connectors = info.get("supported_connectors")
        assert isinstance(connectors, list) and connectors
        assert "postgres" in connectors


class TestCheckConnectionStored:
    def test_stored_connection_succeeds(
        self,
        gateway_endpoint: str,
        auth_token: str,
        tenant_id: str,
        ca_cert: str | None,
        insecure: bool,
        pg_flight_connection: str,
    ) -> None:
        client, opts = _flight_client(
            gateway_endpoint,
            tenant_id=tenant_id,
            token=auth_token,
            connection_id=pg_flight_connection,
            ca_cert=ca_cert,
            insecure=insecure,
        )
        try:
            results = _do_action(client, opts, ACTION_CHECK_CONNECTION)
        finally:
            client.close()

        assert len(results) == 1
        assert results[0].body.to_pybytes() == b""

    def test_missing_connection_header_rejected(
        self, gateway_endpoint: str, auth_token: str, tenant_id: str, ca_cert: str | None, insecure: bool
    ) -> None:
        client, opts = _flight_client(
            gateway_endpoint, tenant_id=tenant_id, token=auth_token, ca_cert=ca_cert, insecure=insecure
        )
        try:
            with pytest.raises(flight.FlightError, match="x-data-connection-id header is required"):
                _do_action(client, opts, ACTION_CHECK_CONNECTION)
        finally:
            client.close()

    def test_unknown_connection_rejected(
        self, gateway_endpoint: str, auth_token: str, tenant_id: str, ca_cert: str | None, insecure: bool
    ) -> None:
        connection_id = f"missing-{uuid.uuid4().hex}"
        client, opts = _flight_client(
            gateway_endpoint,
            tenant_id=tenant_id,
            token=auth_token,
            connection_id=connection_id,
            ca_cert=ca_cert,
            insecure=insecure,
        )
        try:
            with pytest.raises(flight.FlightError):
                _do_action(client, opts, ACTION_CHECK_CONNECTION)
        finally:
            client.close()


class TestCheckConnectionInline:
    def test_inline_credentials_succeed(
        self,
        gateway_endpoint: str,
        auth_token: str,
        tenant_id: str,
        ca_cert: str | None,
        insecure: bool,
        create_connection_type,
        tenant_pg_url: str | None,
    ) -> None:
        if not tenant_pg_url:
            pytest.skip("DCH_TENANT_PG_URL not set")

        ct = create_connection_type(provider="postgres")
        body = _encode_kv({"data_connection_type_id": ct.id, "secret.url": tenant_pg_url})

        client, opts = _flight_client(
            gateway_endpoint, tenant_id=tenant_id, token=auth_token, ca_cert=ca_cert, insecure=insecure
        )
        try:
            results = _do_action(client, opts, ACTION_CHECK_CONNECTION, body)
        finally:
            client.close()

        assert len(results) == 1
        assert results[0].body.to_pybytes() == b""

    def test_inline_bad_url_fails(
        self,
        gateway_endpoint: str,
        auth_token: str,
        tenant_id: str,
        ca_cert: str | None,
        insecure: bool,
        create_connection_type,
    ) -> None:
        ct = create_connection_type(provider="postgres")
        body = _encode_kv({"data_connection_type_id": ct.id, "secret.url": "postgresql://user:pass@127.0.0.1:9/no-db"})

        client, opts = _flight_client(
            gateway_endpoint, tenant_id=tenant_id, token=auth_token, ca_cert=ca_cert, insecure=insecure
        )
        try:
            with pytest.raises(flight.FlightError):
                _do_action(client, opts, ACTION_CHECK_CONNECTION, body)
        finally:
            client.close()

    def test_missing_data_connection_type_id_rejected(
        self,
        gateway_endpoint: str,
        auth_token: str,
        tenant_id: str,
        ca_cert: str | None,
        insecure: bool,
    ) -> None:
        body = _encode_kv({"secret.url": "postgresql://user:pass@127.0.0.1:9/no-db"})

        client, opts = _flight_client(
            gateway_endpoint, tenant_id=tenant_id, token=auth_token, ca_cert=ca_cert, insecure=insecure
        )
        try:
            with pytest.raises(flight.FlightError, match="data_connection_type_id is required"):
                _do_action(client, opts, ACTION_CHECK_CONNECTION, body)
        finally:
            client.close()

    def test_missing_required_credential_rejected(
        self,
        gateway_endpoint: str,
        auth_token: str,
        tenant_id: str,
        ca_cert: str | None,
        insecure: bool,
        create_connection_type,
    ) -> None:
        ct = create_connection_type(provider="postgres")
        body = _encode_kv({"data_connection_type_id": ct.id})

        client, opts = _flight_client(
            gateway_endpoint, tenant_id=tenant_id, token=auth_token, ca_cert=ca_cert, insecure=insecure
        )
        try:
            with pytest.raises(flight.FlightError, match="url"):
                _do_action(client, opts, ACTION_CHECK_CONNECTION, body)
        finally:
            client.close()

    def test_malformed_credentials_body_rejected(
        self, gateway_endpoint: str, auth_token: str, tenant_id: str, ca_cert: str | None, insecure: bool
    ) -> None:
        client, opts = _flight_client(
            gateway_endpoint, tenant_id=tenant_id, token=auth_token, ca_cert=ca_cert, insecure=insecure
        )
        try:
            with pytest.raises(flight.FlightError, match=r"(?i)invalid credentials payload"):
                _do_action(client, opts, ACTION_CHECK_CONNECTION, b"not-an-arrow-stream")
        finally:
            client.close()


class TestActionDispatchErrors:
    def test_unknown_action_rejected(
        self, gateway_endpoint: str, auth_token: str, tenant_id: str, ca_cert: str | None, insecure: bool
    ) -> None:
        client, opts = _flight_client(
            gateway_endpoint, tenant_id=tenant_id, token=auth_token, ca_cert=ca_cert, insecure=insecure
        )
        try:
            with pytest.raises(flight.FlightError, match="Unknown action"):
                _do_action(client, opts, "NoSuchAction")
        finally:
            client.close()
