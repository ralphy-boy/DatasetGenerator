"""Base normalizer interface."""

import logging
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger(__name__)


class BaseNormalizer(ABC):
    """
    Abstract base class for content normalizers.
    
    Normalizers convert raw content into structured formats
    suitable for agent trajectory generation.
    """
    
    @abstractmethod
    def normalize(self, content: Any) -> Any:
        """
        Normalize content.
        
        Args:
            content: Raw content to normalize
            
        Returns:
            Normalized content
        """
        pass
    
    def validate(self, content: Any) -> bool:
        """
        Validate normalized content.
        
        Args:
            content: Normalized content
            
        Returns:
            True if valid
        """
        return True
    
    def clean(self, text: str) -> str:
        """
        Clean text content.
        
        Args:
            text: Text to clean
            
        Returns:
            Cleaned text
        """
        import re
        
        # Remove control characters
        text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
        
        # Normalize whitespace
        text = re.sub(r"\s+", " ", text)
        
        # Remove common artifacts
        text = re.sub(r"\[.*?\]", "", text)
        text = re.sub(r"\(.*?\)", "", text)
        
        return text.strip()
    
    def truncate(self, text: str, max_length: int = 5000) -> str:
        """Truncate text to max length."""
        if len(text) <= max_length:
            return text
        
        # Try to truncate at sentence boundary
        import re
        sentences = re.split(r"([.!?])", text)
        
        result = ""
        for sent in sentences:
            if len(result) + len(sent) > max_length:
                break
            result += sent
        
        return result.strip()[:max_length]