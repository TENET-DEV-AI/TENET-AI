"""
Unit tests for metrics utilities and PrometheusMiddleware.
"""
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import Request

from services.utils.metrics import (
    DETECTION_COUNT,
    REQUEST_COUNT,
    PrometheusMiddleware,
    increment_detection,
)


class TestMetrics:
    """Tests for detection metrics helper."""

    def test_increment_detection_none_threat_type(self):
        before = DETECTION_COUNT.labels(
            service="test_service", threat_type="none", verdict="benign"
        )._value.get()
        increment_detection("test_service", threat_type=None, verdict="benign")
        after = DETECTION_COUNT.labels(
            service="test_service", threat_type="none", verdict="benign"
        )._value.get()
        assert after == before + 1

    def test_increment_detection_with_threat_type(self):
        before = DETECTION_COUNT.labels(
            service="test_service", threat_type="jailbreak", verdict="malicious"
        )._value.get()
        increment_detection("test_service", threat_type="jailbreak", verdict="malicious")
        after = DETECTION_COUNT.labels(
            service="test_service", threat_type="jailbreak", verdict="malicious"
        )._value.get()
        assert after == before + 1


class TestPrometheusMiddleware:
    """Tests for PrometheusMiddleware request counting and error handling."""

    @pytest.mark.asyncio
    async def test_dispatch_success(self):
        middleware = PrometheusMiddleware(app=MagicMock())
        request = MagicMock(spec=Request)
        request.method = "GET"
        request.scope = {"route": MagicMock(path="/api/test")}

        mock_response = MagicMock()
        mock_response.status_code = 200

        async def call_next(req):
            return mock_response

        before = REQUEST_COUNT.labels(
            method="GET", endpoint="/api/test", status="200"
        )._value.get()

        res = await middleware.dispatch(request, call_next)
        assert res.status_code == 200

        after = REQUEST_COUNT.labels(
            method="GET", endpoint="/api/test", status="200"
        )._value.get()
        assert after == before + 1

    @pytest.mark.asyncio
    async def test_dispatch_unhandled_exception_records_500(self):
        middleware = PrometheusMiddleware(app=MagicMock())
        request = MagicMock(spec=Request)
        request.method = "POST"
        request.scope = {"route": MagicMock(path="/api/fail")}

        async def call_next(req):
            raise RuntimeError("Internal crash")

        before = REQUEST_COUNT.labels(
            method="POST", endpoint="/api/fail", status="500"
        )._value.get()

        with pytest.raises(RuntimeError, match="Internal crash"):
            await middleware.dispatch(request, call_next)

        after = REQUEST_COUNT.labels(
            method="POST", endpoint="/api/fail", status="500"
        )._value.get()
        assert after == before + 1
