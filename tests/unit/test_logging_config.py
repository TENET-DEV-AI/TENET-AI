"""
Unit tests for the logging configuration utility module.
"""
import logging
import os
import pytest
from unittest.mock import patch
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "services" / "utils"))

from logging_config import setup_logging


class TestSetupLogging:
    """Tests for the setup_logging function."""

    def test_returns_logger_instance(self):
        """Test that setup_logging returns a logging.Logger instance."""
        logger = setup_logging("test_logger")
        assert isinstance(logger, logging.Logger)

    def test_logger_has_correct_name(self):
        """Test that the logger is created with the correct name."""
        logger = setup_logging("my_service")
        assert logger.name == "my_service"

    def test_default_log_level_is_info(self):
        """Test that default log level is INFO when LOG_LEVEL env var is not set."""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("LOG_LEVEL", None)
            logger = setup_logging("test_default_level")
            assert logger.level == logging.INFO

    def test_log_level_from_environment(self):
        """Test that log level is set from LOG_LEVEL environment variable."""
        with patch.dict(os.environ, {"LOG_LEVEL": "DEBUG"}):
            logger = setup_logging("test_debug_level")
            assert logger.level == logging.DEBUG

    def test_log_level_warning_from_environment(self):
        """Test that WARNING log level is set correctly from environment."""
        with patch.dict(os.environ, {"LOG_LEVEL": "WARNING"}):
            logger = setup_logging("test_warning_level")
            assert logger.level == logging.WARNING

    def test_log_level_error_from_environment(self):
        """Test that ERROR log level is set correctly from environment."""
        with patch.dict(os.environ, {"LOG_LEVEL": "ERROR"}):
            logger = setup_logging("test_error_level")
            assert logger.level == logging.ERROR

    def test_invalid_log_level_defaults_to_info(self):
        """Test that invalid LOG_LEVEL defaults to INFO."""
        with patch.dict(os.environ, {"LOG_LEVEL": "INVALID_LEVEL"}):
            logger = setup_logging("test_invalid_level")
            assert logger.level == logging.INFO

    def test_logger_has_handlers(self):
        """Test that the logger has handlers attached."""
        logger = setup_logging("test_handlers")
        assert len(logger.handlers) > 0

    def test_logger_has_console_handler(self):
        """Test that a StreamHandler (console) is attached to the logger."""
        logger = setup_logging("test_console_handler")
        handler_types = [type(h) for h in logger.handlers]
        assert logging.StreamHandler in handler_types

    def test_logger_has_file_handler(self):
        """Test that a RotatingFileHandler is attached to the logger."""
        from logging.handlers import RotatingFileHandler
        logger = setup_logging("test_file_handler")
        handler_types = [type(h) for h in logger.handlers]
        assert RotatingFileHandler in handler_types

    def test_logger_propagate_is_false(self):
        """Test that logger propagation is disabled."""
        logger = setup_logging("test_propagate")
        assert logger.propagate is False

    def test_same_logger_no_duplicate_handlers(self):
        """Test that calling setup_logging twice does not duplicate handlers."""
        logger1 = setup_logging("test_same_logger")
        handler_count = len(logger1.handlers)
        logger2 = setup_logging("test_same_logger")
        assert len(logger2.handlers) == handler_count

    def test_logs_directory_created(self):
        """Test that the logs directory is created."""
        setup_logging("test_logs_dir")
        assert os.path.exists("logs")


class TestSensitiveDataLogging:
    """Tests to ensure sensitive data handling."""

    def test_logger_name_not_sensitive(self):
        """Test that setup_logging accepts safe logger names without modification."""
        safe_name = "test_service"
        logger = setup_logging(safe_name)
        assert logger.name == safe_name
        # Document: callers must not pass sensitive data as logger names
        # as setup_logging accepts the name verbatim without sanitization

    def test_logger_functional_for_normal_messages(self):
        """Test that logger works normally without raising exceptions."""
        logger = setup_logging("test_sensitive")
        logger.info("User logged in successfully")
        logger.warning("Test warning")
        logger.error("Test error")


class TestLogLevelCaseInsensitive:
    """Tests for case insensitivity of LOG_LEVEL env variable."""

    def test_lowercase_log_level(self):
        """Test that lowercase log level env var is handled correctly."""
        with patch.dict(os.environ, {"LOG_LEVEL": "debug"}):
            logger = setup_logging("test_lowercase")
            assert logger.level == logging.DEBUG

    def test_mixed_case_log_level(self):
        """Test that mixed case log level env var is handled correctly."""
        with patch.dict(os.environ, {"LOG_LEVEL": "Warning"}):
            logger = setup_logging("test_mixed_case")
            assert logger.level == logging.WARNING


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


class TestJSONFormatter:
    """Tests for JSONFormatter including exception formatting and correlation ID."""

    def test_json_formatter_with_exc_info(self):
        import json
        from logging_config import JSONFormatter

        formatter = JSONFormatter()
        try:
            raise ValueError("Something broke")
        except ValueError:
            import sys
            record = logging.LogRecord(
                name="test_exc",
                level=logging.ERROR,
                pathname="test.py",
                lineno=10,
                msg="An error occurred",
                args=(),
                exc_info=sys.exc_info(),
            )
            output = formatter.format(record)
            data = json.loads(output)
            assert "exception" in data
            assert "ValueError: Something broke" in data["exception"]
