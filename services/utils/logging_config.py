import logging
import os
from logging.handlers import RotatingFileHandler

def setup_logging(name: str) -> logging.Logger:
    """
    Set up logging configuration for a service.
    
    Args:
        name: Name of the logger (usually __name__)
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)

    # Configure logging format with timestamps
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    return logger