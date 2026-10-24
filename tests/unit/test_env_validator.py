"""
Unit tests for the environment variable validation utility.
"""

import pytest

from services.utils.env_validator import (
    EnvValidationError,
    SafeValueError,
    non_negative_float,
    port,
    positive_float,
    positive_int,
    probability,
    validate_env_vars,
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Make sure the variables used in these tests start unset."""
    for name in ("TEST_API_KEY", "TEST_HOST", "TEST_PORT", "TEST_TIMEOUT", "TEST_RETRIES"):
        monkeypatch.delenv(name, raising=False)


class TestPort:
    """Tests for the port converter."""

    def test_port_valid_returns_int(self):
        assert port("6379") == 6379

    @pytest.mark.parametrize("value", ["1", "65535"])
    def test_port_boundaries_accepted(self, value):
        assert port(value) == int(value)

    @pytest.mark.parametrize("value", ["0", "65536", "-1"])
    def test_port_out_of_range_raises(self, value):
        with pytest.raises(ValueError, match="between 1 and 65535"):
            port(value)

    def test_port_not_a_number_raises(self):
        with pytest.raises(ValueError):
            port("abc")


class TestValidateEnvVars:
    """Tests for validate_env_vars."""

    def test_validate_env_vars_required_present_returns_values(self, monkeypatch):
        monkeypatch.setenv("TEST_API_KEY", "secret")
        monkeypatch.setenv("TEST_HOST", "redis")

        result = validate_env_vars(["TEST_API_KEY", "TEST_HOST"])

        assert result == {"TEST_API_KEY": "secret", "TEST_HOST": "redis"}

    def test_validate_env_vars_missing_lists_all_missing(self):
        with pytest.raises(EnvValidationError) as exc_info:
            validate_env_vars(["TEST_API_KEY", "TEST_HOST"])

        assert exc_info.value.missing == ["TEST_API_KEY", "TEST_HOST"]
        assert "missing required variables: TEST_API_KEY, TEST_HOST" in str(exc_info.value)

    def test_validate_env_vars_empty_required_counts_as_missing(self, monkeypatch):
        monkeypatch.setenv("TEST_API_KEY", "   ")

        with pytest.raises(EnvValidationError) as exc_info:
            validate_env_vars(["TEST_API_KEY"])

        assert exc_info.value.missing == ["TEST_API_KEY"]

    def test_validate_env_vars_converts_types(self, monkeypatch):
        monkeypatch.setenv("TEST_PORT", "6380")
        monkeypatch.setenv("TEST_TIMEOUT", "2.5")
        monkeypatch.setenv("TEST_RETRIES", " 3 ")

        result = validate_env_vars(
            ["TEST_PORT", "TEST_TIMEOUT", "TEST_RETRIES"],
            types={"TEST_PORT": port, "TEST_TIMEOUT": float, "TEST_RETRIES": int},
        )

        assert result == {"TEST_PORT": 6380, "TEST_TIMEOUT": 2.5, "TEST_RETRIES": 3}

    def test_validate_env_vars_optional_unset_uses_default(self):
        result = validate_env_vars(
            [],
            optional_vars={"TEST_HOST": "localhost", "TEST_PORT": 6379},
            types={"TEST_PORT": port},
        )

        assert result == {"TEST_HOST": "localhost", "TEST_PORT": 6379}

    def test_validate_env_vars_optional_set_overrides_default(self, monkeypatch):
        monkeypatch.setenv("TEST_PORT", "7000")

        result = validate_env_vars([], optional_vars={"TEST_PORT": 6379}, types={"TEST_PORT": port})

        assert result == {"TEST_PORT": 7000}

    def test_validate_env_vars_invalid_port_has_readable_message(self, monkeypatch):
        monkeypatch.setenv("TEST_PORT", "abc")

        with pytest.raises(EnvValidationError) as exc_info:
            validate_env_vars([], optional_vars={"TEST_PORT": 6379}, types={"TEST_PORT": port})

        assert exc_info.value.invalid == {
            "TEST_PORT": "expected a port number (1-65535), got 'abc'"
        }

    def test_validate_env_vars_invalid_float_and_int_messages(self, monkeypatch):
        monkeypatch.setenv("TEST_TIMEOUT", "fast")
        monkeypatch.setenv("TEST_RETRIES", "1.5")

        with pytest.raises(EnvValidationError) as exc_info:
            validate_env_vars(
                [],
                optional_vars={"TEST_TIMEOUT": 2.0, "TEST_RETRIES": 3},
                types={"TEST_TIMEOUT": float, "TEST_RETRIES": int},
            )

        assert exc_info.value.invalid == {
            "TEST_TIMEOUT": "expected a number, got 'fast'",
            "TEST_RETRIES": "expected an integer, got '1.5'",
        }

    def test_validate_env_vars_reports_missing_and_invalid_together(self, monkeypatch):
        monkeypatch.setenv("TEST_PORT", "99999")

        with pytest.raises(EnvValidationError) as exc_info:
            validate_env_vars(["TEST_API_KEY", "TEST_PORT"], types={"TEST_PORT": port})

        message = str(exc_info.value)
        assert message.startswith("Invalid environment configuration:")
        assert "missing required variables: TEST_API_KEY" in message
        assert "TEST_PORT: expected a port number (1-65535), got '99999'" in message

    def test_validate_env_vars_custom_converter_does_not_echo_value(self, monkeypatch):
        monkeypatch.setenv("TEST_API_KEY", "short")

        def min_length(value):
            if len(value) < 32:
                raise SafeValueError("must be at least 32 characters")
            return value

        with pytest.raises(EnvValidationError) as exc_info:
            validate_env_vars(["TEST_API_KEY"], types={"TEST_API_KEY": min_length})

        assert exc_info.value.invalid == {"TEST_API_KEY": "must be at least 32 characters"}
        assert "short" not in str(exc_info.value)

    def test_validate_env_vars_custom_converter_empty_error_message(self, monkeypatch):
        monkeypatch.setenv("TEST_HOST", "x")

        def reject(value):
            raise ValueError()

        with pytest.raises(EnvValidationError) as exc_info:
            validate_env_vars(["TEST_HOST"], types={"TEST_HOST": reject})

        assert exc_info.value.invalid == {"TEST_HOST": "invalid value"}

    def test_validate_env_vars_name_in_both_lists_is_required(self):
        with pytest.raises(EnvValidationError) as exc_info:
            validate_env_vars(["TEST_HOST"], optional_vars={"TEST_HOST": "localhost"})

        assert exc_info.value.missing == ["TEST_HOST"]

    def test_env_validation_error_is_value_error(self):
        assert issubclass(EnvValidationError, ValueError)


class TestIngestIntegration:
    """The ingest service validates its config in the startup hook, not at import."""

    def test_load_config_applies_env_values(self, monkeypatch):
        import services.ingest.app as ingest_app

        monkeypatch.setenv("REDIS_PORT", "6380")
        monkeypatch.setenv("CB_FAILURE_THRESHOLD", "5")
        try:
            ingest_app.load_config()

            assert ingest_app.REDIS_PORT == 6380
            assert ingest_app.CB_FAILURE_THRESHOLD == 5
            assert ingest_app.redis_cb.failure_threshold == 5
        finally:
            # Clear only the vars this test set, then reload, so the host's own
            # environment can't change the outcome.
            monkeypatch.delenv("REDIS_PORT", raising=False)
            monkeypatch.delenv("CB_FAILURE_THRESHOLD", raising=False)
            ingest_app.load_config()

    def test_startup_fails_fast_on_bad_redis_port(self, monkeypatch):
        from fastapi.testclient import TestClient

        from services.ingest.app import app

        monkeypatch.setenv("REDIS_PORT", "abc")

        with (
            pytest.raises(EnvValidationError, match="REDIS_PORT: expected a port number"),
            TestClient(app),
        ):
            pass


class TestRangeConverters:
    @pytest.mark.parametrize("value", ["nan", "inf", "-inf", "0", "-1"])
    def test_positive_float_rejects_bad_values(self, value):
        with pytest.raises(ValueError):
            positive_float(value)

    def test_positive_float_accepts_positive(self):
        assert positive_float("2.5") == 2.5

    @pytest.mark.parametrize("value", ["nan", "inf", "-0.1"])
    def test_non_negative_float_rejects_bad_values(self, value):
        with pytest.raises(ValueError):
            non_negative_float(value)

    def test_non_negative_float_accepts_zero(self):
        assert non_negative_float("0") == 0.0

    @pytest.mark.parametrize("value", ["nan", "2", "-0.1", "1.01"])
    def test_probability_rejects_bad_values(self, value):
        with pytest.raises(ValueError):
            probability(value)

    @pytest.mark.parametrize("value", ["0", "0.75", "1"])
    def test_probability_accepts_range(self, value):
        assert probability(value) == float(value)

    @pytest.mark.parametrize("value", ["0", "-3"])
    def test_positive_int_rejects_below_one(self, value):
        with pytest.raises(ValueError):
            positive_int(value)

    def test_error_names_the_variable_and_range(self, monkeypatch):
        monkeypatch.setenv("TEST_P", "2")
        with pytest.raises(EnvValidationError, match="TEST_P: expected a number between 0 and 1"):
            validate_env_vars([], optional_vars={"TEST_P": 0.5}, types={"TEST_P": probability})

    def test_custom_converter_error_does_not_leak_value(self, monkeypatch):
        def bad(value: str) -> str:
            raise ValueError(f"bad token {value}")

        monkeypatch.setenv("TEST_SECRET", "hunter2")
        with pytest.raises(EnvValidationError) as exc_info:
            validate_env_vars(["TEST_SECRET"], types={"TEST_SECRET": bad})

        assert "hunter2" not in str(exc_info.value)
        assert exc_info.value.invalid == {"TEST_SECRET": "invalid value"}


class TestAnalyzerIntegration:
    def test_load_config_rejects_bad_threshold(self, monkeypatch):
        import services.analyzer.app as analyzer_app

        monkeypatch.setenv("PROMPT_INJECTION_THRESHOLD", "nan")
        with pytest.raises(EnvValidationError, match="PROMPT_INJECTION_THRESHOLD"):
            analyzer_app.load_config()

    def test_benchmark_runner_applies_env_config(self, monkeypatch, tmp_path):
        import services.analyzer.app as analyzer_app
        from services.analyzer.benchmark.runner import DetectionBenchmarkRunner

        # load_config() checks every analyzer setting, so start from a clean slate.
        for name in analyzer_app._ENV_DEFAULTS:
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("PROMPT_INJECTION_THRESHOLD", "0.9")
        monkeypatch.setenv("MODEL_PATH", str(tmp_path))
        try:
            DetectionBenchmarkRunner(str(tmp_path / "dataset.json"))

            assert analyzer_app.PROMPT_INJECTION_THRESHOLD == 0.9
        finally:
            monkeypatch.delenv("PROMPT_INJECTION_THRESHOLD", raising=False)
            monkeypatch.delenv("MODEL_PATH", raising=False)
            analyzer_app.load_config()
