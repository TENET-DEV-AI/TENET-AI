"""
Unit tests for the centralized logging configuration.
"""
import logging
import os
from logging.handlers import RotatingFileHandler
import pytest

# Add project root to sys.path to find the module
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

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