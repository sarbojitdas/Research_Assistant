import pytest
from httpx import AsyncClient

from tests.conftest import client  # noqa: F401


class TestHealth:
    async def test_health_check(self, client: AsyncClient) -> None:
        response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "Autonomous Research Assistant"

    async def test_openapi_docs(self, client: AsyncClient) -> None:
        response = await client.get("/openapi.json")
        assert response.status_code == 200

    async def test_docs_endpoint(self, client: AsyncClient) -> None:
        response = await client.get("/docs")
        assert response.status_code == 200
