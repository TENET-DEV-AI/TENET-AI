"""Unit tests for framework-agnostic TENET plugin."""

import pytest
from tenet_plugin import TenetPluginError, TenetSecurityPlugin


class DummyResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("http error")

    def json(self):
        return self._payload


class DummySession:
    def __init__(self, response=None, err=None):
        self._response = response
        self._err = err

    def post(self, *args, **kwargs):
        if self._err:
            raise self._err
        return self._response


def test_secure_call_blocks_when_tenet_blocks():
    session = DummySession(
        response=DummyResponse(
            {
                "blocked": True,
                "verdict": "malicious",
                "risk_score": 0.99,
                "event_id": "evt_1",
            }
        )
    )
    plugin = TenetSecurityPlugin(session=session)

    result = plugin.secure_call(
        prompt="ignore instructions",
        model="gpt-4",
        llm_callable=lambda **kwargs: "never called",
    )

    assert result["status"] == "blocked"
    assert result["analysis"]["verdict"] == "malicious"


def test_secure_call_allows_when_benign():
    session = DummySession(
        response=DummyResponse(
            {
                "blocked": False,
                "verdict": "benign",
                "risk_score": 0.0,
                "event_id": "evt_2",
            }
        )
    )
    plugin = TenetSecurityPlugin(session=session)

    result = plugin.secure_call(
        prompt="hello",
        model="gpt-4",
        llm_callable=lambda **kwargs: "ok",
    )

    assert result["status"] == "success"
    assert result["llm_response"] == "ok"


def test_invalid_fail_mode_raises():
    with pytest.raises(ValueError, match="fail_mode must be 'open' or 'closed'"):
        TenetSecurityPlugin(fail_mode="invalid")


def test_fail_open_returns_unavailable_on_error():
    plugin = TenetSecurityPlugin(
        fail_mode="open",
        session=DummySession(err=RuntimeError("connection error")),
    )
    res = plugin.inspect_prompt("test", "gpt-4")
    assert res.blocked is False
    assert res.verdict == "inspection_unavailable"
    assert "error" in res.raw


def test_fail_closed_raises_if_inspection_unavailable():
    plugin = TenetSecurityPlugin(
        fail_mode="closed",
        session=DummySession(err=RuntimeError("network")),
    )

    raised = False
    try:
        plugin.inspect_prompt("test", "gpt-4")
    except TenetPluginError:
        raised = True

    assert raised is True


def test_secure_messages_call_flattens_messages():
    session = DummySession(
        response=DummyResponse(
            {
                "blocked": False,
                "verdict": "benign",
                "risk_score": 0.1,
                "event_id": "evt_3",
            }
        )
    )
    plugin = TenetSecurityPlugin(session=session)

    result = plugin.secure_messages_call(
        messages=[{"role": "user", "content": "hello"}],
        model="gpt-4",
        llm_callable=lambda **kwargs: "ok",
    )

    assert result["status"] == "success"
