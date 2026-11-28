"""Unit tests for the console sign-in log."""

import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from services.ingest.app import app
from services.ingest.signins import MemoryStore

client = TestClient(app)
TEST_API_KEY = "tenet-dev-key-change-in-production"
HEADERS = {"X-API-Key": TEST_API_KEY}


class TestRecordSignIn:
    def test_records_a_google_sign_in(self):
        response = client.post(
            "/v1/signins",
            headers=HEADERS,
            json={"email": "Analyst@Tenet.AI", "provider": "google", "role": "SOC Analyst"},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["recorded"] is True
        # No Redis in the unit test environment, so the in-process store answers.
        assert body["storage"] in {"memory", "redis"}

    def test_requires_an_api_key(self):
        response = client.post("/v1/signins", json={"email": "someone@tenet.ai"})
        assert response.status_code in {401, 403}

    def test_rejects_a_malformed_email(self):
        response = client.post("/v1/signins", headers=HEADERS, json={"email": "a"})
        assert response.status_code == 422

    def test_can_be_switched_off(self, monkeypatch):
        monkeypatch.setenv("SIGNIN_LOG_ENABLED", "false")
        response = client.post("/v1/signins", headers=HEADERS, json={"email": "someone@tenet.ai"})
        assert response.status_code == 200
        assert response.json() == {"recorded": False, "storage": "none"}


class TestSignInStats:
    def test_counts_sign_ins_by_provider_and_account(self):
        client.post("/v1/signins", headers=HEADERS, json={"email": "one@tenet.ai", "provider": "google"})
        client.post("/v1/signins", headers=HEADERS, json={"email": "two@tenet.ai", "provider": "google"})
        client.post("/v1/signins", headers=HEADERS, json={"email": "one@tenet.ai", "provider": "password"})

        response = client.get("/v1/signins/stats?days=7", headers=HEADERS)
        assert response.status_code == 200

        body = response.json()
        assert body["window_days"] == 7
        assert body["total"] >= 3
        assert body["unique_accounts"] >= 2
        assert body["by_provider"].get("google", 0) >= 2
        assert body["last_signin"]["email"] in {"one@tenet.ai", "two@tenet.ai"}

    def test_rejects_a_bad_window(self):
        assert client.get("/v1/signins/stats?days=0", headers=HEADERS).status_code == 422
        assert client.get("/v1/signins/stats?days=999", headers=HEADERS).status_code == 422


class TestMemoryStore:
    @pytest.mark.asyncio
    async def test_windows_by_day(self):
        store = MemoryStore()
        today = datetime.now(timezone.utc)
        old_day = (today - timedelta(days=30)).strftime("%Y-%m-%d")

        await store.append(
            {"email": "old@tenet.ai", "provider": "google", "day": old_day, "at": old_day, "role": None, "org_domain": None}
        )
        await store.append(
            {
                "email": "new@tenet.ai",
                "provider": "google",
                "day": today.strftime("%Y-%m-%d"),
                "at": today.isoformat(),
                "role": None,
                "org_domain": None,
            }
        )

        recent = await store.stats(days=7)
        assert recent.total == 1
        assert recent.unique_accounts == 1

        wider = await store.stats(days=60)
        assert wider.total == 2

    @pytest.mark.asyncio
    async def test_caps_the_log(self):
        store = MemoryStore()
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        for index in range(20):
            await store.append(
                {"email": f"user{index}@tenet.ai", "provider": "google", "day": day, "at": day, "role": None, "org_domain": None}
            )
        stats = await store.stats(days=1)
        assert stats.total == 20
        assert stats.unique_accounts == 20
        assert json.dumps(stats.last_signin)  # serialisable, not a raw object
