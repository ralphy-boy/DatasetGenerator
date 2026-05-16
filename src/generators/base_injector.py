"""Base classes for generators."""

logger = __import__("logging").getLogger(__name__)


class BaseGenerator:
    """Base generator."""
    
    def generate(self, data, config=None):
        """Generate output from input."""
        raise NotImplementedError


class BaseInjector:
    """Base injector."""
    
    def inject(self, trajectory, config=None):
        """Inject into trajectory."""
        raise NotImplementedError


class BaseValidator:
    """Base validator."""
    
    def validate(self, trajectory, config=None):
        """Validate trajectory."""
        return {"passed": True, "score": 1.0}


# Import logging
import logging