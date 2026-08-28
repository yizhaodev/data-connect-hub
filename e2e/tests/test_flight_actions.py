"""Flight DoAction tests: CheckConnection and ListActions."""

from __future__ import annotations

import pyarrow as pa
import pyarrow.flight as flight
import pytest
from data_connect_hub import DataConnectClient


def _flight_client_and_options(
    dch_client: DataConnectClient,
) -> tuple[flight.FlightClient, flight.FlightCallOptions]:
    fc = dch_client._require_flight()
    client = fc._flight_connect()
    options = fc._call_options()
    return client, options


class TestFlightActions:
    def test_list_actions_includes_check_connection(
        self, dch_client: DataConnectClient
    ) -> None:
        client, options = _flight_client_and_options(dch_client)
        try:
            actions = list(client.list_actions(options))
            action_types = [a.type for a in actions]
            assert "CheckConnection" in action_types
            assert "GetSupportedConnectors" in action_types
        finally:
            client.close()

    def test_check_connection_existing(
        self, dch_client: DataConnectClient, pg_flight_connection: str
    ) -> None:
        fc = dch_client._require_flight()
        client = fc._flight_connect()
        headers = [
            *fc._call_options().headers,
            (b"x-data-connection-id", pg_flight_connection.encode()),
        ]
        options = flight.FlightCallOptions(headers=headers)
        try:
            results = list(client.do_action(flight.Action("CheckConnection", b""), options))
            assert len(results) == 1
        finally:
            client.close()

    def test_check_connection_nonexistent_fails(
        self, dch_client: DataConnectClient
    ) -> None:
        fc = dch_client._require_flight()
        client = fc._flight_connect()
        headers = [
            *fc._call_options().headers,
            (b"x-data-connection-id", b"00000000-0000-0000-0000-000000000000"),
        ]
        options = flight.FlightCallOptions(headers=headers)
        try:
            with pytest.raises((flight.FlightServerError, pa.ArrowKeyError)):
                list(client.do_action(flight.Action("CheckConnection", b""), options))
        finally:
            client.close()

    def test_check_connection_with_inline_credentials(
        self,
        dch_client: DataConnectClient,
        pg_flight_connection: str,
        rest_client: DataConnectClient,
    ) -> None:
        import os

        pg_url = os.environ.get("DCH_TENANT_PG_URL")
        if not pg_url:
            pytest.skip("DCH_TENANT_PG_URL not set (raw PG URL needed for inline credential test)")

        conn = rest_client.get_connection(pg_flight_connection)
        dct_id = conn.data_connection_type_id

        keys = pa.array(["data_connection_type_id", "secret.URI"], type=pa.utf8())
        values = pa.array([dct_id, pg_url], type=pa.utf8())
        batch = pa.RecordBatch.from_arrays([keys, values], names=["key", "value"])

        sink = pa.BufferOutputStream()
        writer = pa.ipc.new_stream(sink, batch.schema)
        writer.write_batch(batch)
        writer.close()
        body = sink.getvalue().to_pybytes()

        fc = dch_client._require_flight()
        client = fc._flight_connect()
        options = fc._call_options()
        try:
            results = list(client.do_action(flight.Action("CheckConnection", body), options))
            assert len(results) == 1
        finally:
            client.close()

    def test_unknown_action_fails(
        self, dch_client: DataConnectClient
    ) -> None:
        client, options = _flight_client_and_options(dch_client)
        try:
            with pytest.raises((flight.FlightServerError, pa.ArrowInvalid)):
                list(client.do_action(flight.Action("NoSuchAction", b""), options))
        finally:
            client.close()
