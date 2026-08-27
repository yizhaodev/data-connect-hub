"""Connection readiness via POST /api/v1/data/connections/{id}/readiness."""

from __future__ import annotations

import uuid

import httpx
import pytest

from data_connect_hub import AdminSecretRef, DataConnectClient


@pytest.fixture()
def pg_connection_type(create_connection_type):
    return create_connection_type(provider="postgres")


class TestRestConnectionReadiness:
    def test_ready_connection(
        self,
        rest_client: DataConnectClient,
        authed_http_client: httpx.Client,
        pg_secret: str | None,
        create_connection,
        pg_connection_type,
    ) -> None:
        if not pg_secret:
            pytest.skip("DCH_PG_SECRET not set (run e2e/run-e2e.sh first)")
        conn = create_connection(
            name="e2e-readiness-pg",
            connection_type_id=pg_connection_type.id,
            admin=AdminSecretRef(secret_ref=pg_secret),
        )

        resp = authed_http_client.post(f"/api/v1/data/connections/{conn.id}/readiness")
        assert resp.status_code == 204, f"expected 204, got {resp.status_code}: {resp.text[:500]}"

        fetched = rest_client.get_connection(conn.id)
        assert fetched.status.state == "ready"

    def test_unready_connection_returns_502(
        self,
        rest_client: DataConnectClient,
        authed_http_client: httpx.Client,
        pg_bad_secret: str | None,
        create_connection,
        pg_connection_type,
    ) -> None:
        if not pg_bad_secret:
            pytest.skip("DCH_PG_BAD_SECRET not set (run e2e/run-e2e.sh first)")
        conn = create_connection(
            name="e2e-unready-pg",
            connection_type_id=pg_connection_type.id,
            admin=AdminSecretRef(secret_ref=pg_bad_secret),
        )

        resp = authed_http_client.post(f"/api/v1/data/connections/{conn.id}/readiness")
        assert resp.status_code == 502, f"expected 502, got {resp.status_code}: {resp.text[:500]}"
        assert resp.json()["code"] == "connection_check_failed"

        fetched = rest_client.get_connection(conn.id)
        assert fetched.status.state == "not_ready"

    def test_nonexistent_connection_returns_404(self, authed_http_client: httpx.Client) -> None:
        resp = authed_http_client.post(f"/api/v1/data/connections/{uuid.uuid4()}/readiness")
        assert resp.status_code == 404, f"expected 404, got {resp.status_code}: {resp.text[:500]}"
