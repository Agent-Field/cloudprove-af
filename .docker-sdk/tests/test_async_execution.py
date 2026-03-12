import asyncio
import httpx
import pytest

from agentfield.agent import Agent
from agentfield.client import AgentFieldClient


@pytest.mark.asyncio
async def test_reasoner_async_mode_sends_status(monkeypatch):
    agent = Agent(
        node_id="test-agent", agentfield_server="http://control", auto_register=False
    )

    @agent.reasoner()
    async def echo(value: int) -> dict:
        await asyncio.sleep(0)
        return {"value": value}

    recorded = []

    class DummyResponse:
        def __init__(self, status_code: int = 200):
            self.status_code = status_code

        def json(self):
            return {}

    async def fake_request(self, method, url, **kwargs):
        recorded.append({"method": method, "url": url, "json": kwargs.get("json")})
        return DummyResponse(200)

    monkeypatch.setattr(AgentFieldClient, "_async_request", fake_request)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=agent), base_url="http://agent"
    ) as client:
        response = await client.post(
            "/reasoners/echo",
            json={"value": 7},
            headers={"X-Execution-ID": "exec-123"},
        )

    assert response.status_code == 202
    await asyncio.sleep(0.1)

    status_calls = [entry for entry in recorded if "/executions/" in entry["url"]]
    assert status_calls, "expected async status callback"
    payload = status_calls[-1]["json"]
    assert payload["status"] == "succeeded"
    assert payload["result"]["value"] == 7


@pytest.mark.asyncio
async def test_post_execution_status_retries(monkeypatch):
    agent = Agent(
        node_id="test-agent", agentfield_server="http://control", auto_register=False
    )

    attempts = {"count": 0}

    class DummyResponse:
        def __init__(self, status_code: int):
            self.status_code = status_code

    async def fake_request(self, method, url, **kwargs):
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise RuntimeError("transient error")
        return DummyResponse(200)

    monkeypatch.setattr(AgentFieldClient, "_async_request", fake_request)

    sleeps = []

    async def fake_sleep(delay):
        sleeps.append(delay)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    await agent._post_execution_status(
        "http://control/api/v1/executions/exec-1/status",
        {"status": "running"},
        "exec-1",
        max_retries=5,
    )

    assert attempts["count"] == 3
    assert sleeps == [1, 2]
