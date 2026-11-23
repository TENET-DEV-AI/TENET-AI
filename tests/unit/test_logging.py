"""
Unit tests for the centralized logging configuration.
"""
import logging
import os
from logging.handlers import RotatingFileHandler
import pytest

from services.utils.logging_config import setup_logging

class TestLoggingConfig:
    """Tests for the setup_logging function."""

    def test_logger_creation_and_defaults(self):
        """Test that the logger is created with correct defaults."""
        # Arrange & Act
        logger = setup_logging("test_default_logger")
        
        # Assert
        assert logger.name == "test_default_logger"
        assert logger.level == logging.INFO  # INFO is the default
        assert logger.propagate is False
        
        # Should have 2 handlers: StreamHandler and RotatingFileHandler
        assert len(logger.handlers) == 2
        
        handler_types = [type(h) for h in logger.handlers]
        assert logging.StreamHandler in handler_types
        assert RotatingFileHandler in handler_types

    def test_log_level_from_environment(self, monkeypatch):
        """Test that LOG_LEVEL environment variable sets the correct level."""
        # Arrange: Mock the environment variable
        monkeypatch.setenv("LOG_LEVEL", "DEBUG")
        
        # Act
        logger = setup_logging("test_env_logger")
        
        # Assert
        assert logger.level == logging.DEBUG

    def test_prevents_duplicate_handlers(self):
        """Test that calling setup_logging twice doesn't duplicate handlers."""
        # Arrange
        logger_name = "test_duplicate_logger"
        
        # Act
        logger1 = setup_logging(logger_name)
        logger2 = setup_logging(logger_name)
        
        # Assert
        assert logger1 is logger2  # It's the exact same object
        assert len(logger2.handlers) == 2  # Still only 2 handlers, not 4!

    def test_json_formatter_structure(self):
        """Test that the logger outputs valid JSON with the correct keys."""
        import json
        from io import StringIO
        import uuid
        from services.utils.logging_config import JSONFormatter, correlation_id_var
        
        log_stream = StringIO()
        logger = logging.getLogger("test_json_logger")
        logger.setLevel(logging.INFO)
        logger.handlers.clear()
        
        handler = logging.StreamHandler(log_stream)
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
        
        test_id = str(uuid.uuid4())
        token = correlation_id_var.set(test_id)
        
        logger.info("Test message for JSON logger")
        correlation_id_var.reset(token)
        
        log_output = log_stream.getvalue().strip()
        assert log_output != "", "Log output should not be empty"
        
        log_data = json.loads(log_output)
        assert log_data.get("logger") == "test_json_logger"
        assert log_data.get("level") == "INFO"
        assert log_data.get("message") == "Test message for JSON logger"
        assert log_data.get("correlation_id") == test_id
        assert "timestamp" in log_data

    def test_correlation_id_empty(self):
        """Test JSON logger behavior when correlation ID is not set."""
        import json
        from io import StringIO
        from services.utils.logging_config import JSONFormatter, correlation_id_var
        
        log_stream = StringIO()
        logger = logging.getLogger("test_json_no_id")
        logger.setLevel(logging.INFO)
        logger.handlers.clear()
        
        handler = logging.StreamHandler(log_stream)
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
        
        token = correlation_id_var.set(None)
        logger.warning("No correlation ID here")
        correlation_id_var.reset(token)
        
        log_output = log_stream.getvalue().strip()
        log_data = json.loads(log_output)
        
        assert log_data.get("message") == "No correlation ID here"
        assert log_data.get("correlation_id") is None