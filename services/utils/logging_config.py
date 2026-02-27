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

    if not logger.handlers:

        # Configure logging format with timestamps
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

        # Set up console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        # Set up file handler
        os.makedirs("logs", exist_ok=True)
        file_handler = RotatingFileHandler(
            filename=os.path.join("logs", "tenet.log"),
            maxBytes=5 * 1024 * 1024,
            backupCount=3
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        logger.propagate = False
    
    return logger