"""Base generator interface."""

import logging
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger(__name__)


class BaseGenerator(ABC):
    """
    Abstract base class for generators.
    
    Generators transform data between formats.
    """
    
    @abstractmethod
    def generate(self, data: Any, config: dict = None) -> Any:
        """
        Generate output from input.
        
        Args:
            data: Input data
            config: Generation config
            
        Returns:
            Generated output
        """
        pass
    
    def validate(self, data: Any) -> bool:
        """
        Validate generated output.
        
        Args:
            data: Data to validate
            
        Returns:
            True if valid
        """
        return data is not None
    
    def transform_config(self, config: dict) -> dict:
        """Transform config with defaults."""
        return {
            "batch_size": 100,
            "max_length": 5000,
            "min_steps": 3,
            "max_steps": 50,
            **config
        }