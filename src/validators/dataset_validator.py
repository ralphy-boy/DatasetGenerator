"""Dataset validation system."""

import hashlib
import logging
import re
from typing import Any, Optional

from ..models import AgentTrajectory, AttackEvent, ValidationResult
from .base import BaseValidator

logger = logging.getLogger(__name__)


class DatasetValidator:
    """
    Validate dataset quality.
    
    Validates:
    - Realistic outputs
    - Ilogical exploit chains
    - Repeated reasoning
    - Inconsistent chronology
    - Invalid commands
    - Shallow conversations
    - Duplicates
    """
    
    def __init__(self):
        self.validators = [
            RealisticOutputValidator(),
            CommandValidator(),
            ChronologyValidator(),
            DepthValidator(),
            DuplicateValidator(),
        ]
    
    def validate(
        self,
        trajectory: AgentTrajectory,
        config: dict = None
    ) -> ValidationResult:
        """
        Validate trajectory.
        
        Args:
            trajectory: Trajectory to validate
            config: Validation config
            
        Returns:
            Validation result
        """
        config = config or {}
        
        errors = []
        warnings = []
        checks_passed = {}
        total_score = 0.0
        
        # Run all validators
        for validator in self.validators:
            result = validator.validate(trajectory, config)
            
            if result:
                checks_passed[validator.__class__.__name__] = result.get("passed", False)
                
                if result.get("errors"):
                    errors.extend(result["errors"])
                
                if result.get("warnings"):
                    warnings.extend(result["warnings"])
                
                total_score += result.get("score", 0.0)
        
        # Calculate final score
        score = total_score / len(self.validators) if self.validators else 0.0
        
        is_valid = score >= config.get("min_quality_score", 0.7) and len(errors) == 0
        
        return ValidationResult(
            is_valid=is_valid,
            score=score,
            errors=errors,
            warnings=warnings,
            checks_passed=checks_passed
        )
    
    def validate_batch(
        self,
        trajectories: list[AgentTrajectory],
        config: dict = None
    ) -> list[ValidationResult]:
        """Validate batch."""
        return [self.validate(t, config) for t in trajectories]


class BaseValidator:
    """Base validator."""
    
    def validate(
        self,
        trajectory: AgentTrajectory,
        config: dict
    ) -> dict:
        """Validate trajectory."""
        return {"passed": True, "score": 1.0}
    
    def _get_conversations(self, trajectory: AgentTrajectory) -> list[dict]:
        """Get conversations as list."""
        return [{"from": c.from_role.value, "value": c.value} for c in trajectory.conversations]


class RealisticOutputValidator(BaseValidator):
    """Validate realistic outputs."""
    
    VALID_PATTERNS = [
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # IP
        r"(http|https)://[^\s]+",  # URL
        r"(discovered|found|identified) [^\n]+",  # Findings
        r"(open|closed|filtered) [^\n]+",  # Ports
        r"(nmap|gobuster|ffuf|sqlmap) [^\n]+",  # Tools
    ]
    
    def validate(self, trajectory: AgentTrajectory, config: dict) -> dict:
        """Check for realistic outputs."""
        errors = []
        warnings = []
        
        tool_outputs = [
            c for c in trajectory.conversations
            if c.from_role.value == "tool"
        ]
        
        if not tool_outputs:
            errors.append("No tool outputs found")
            return {"passed": False, "score": 0.0, "errors": errors}
        
        # Check a sample of outputs
        realistic_count = 0
        
        for output in tool_outputs[:5]:
            if self._looks_realistic(output.value):
                realistic_count += 1
        
        score = realistic_count / min(5, len(tool_outputs))
        
        if score < 0.5:
            errors.append("Outputs don't look realistic")
        
        return {
            "passed": score >= 0.5,
            "score": score,
            "errors": errors,
            "warnings": warnings
        }
    
    def _looks_realistic(self, output: str) -> bool:
        """Check if output looks realistic."""
        output_lower = output.lower()
        
        # Check for realistic patterns
        for pattern in self.VALID_PATTERNS:
            if re.search(pattern, output, re.IGNORECASE):
                return True
        
        # Check for tool output characteristics
        realistic_chars = [":", "=", "/", "-", "*", "|"]
        if any(c in output for c in realistic_chars):
            return True
        
        return len(output) > 10


class CommandValidator(BaseValidator):
    """Validate commands are valid."""
    
    def validate(self, trajectory: AgentTrajectory, config: dict) -> dict:
        """Validate commands."""
        errors = []
        
        # Check for valid command patterns
        valid_patterns = [
            r"^(nmap|gobuster|ffuf|sqlmap|curl|ssh|python|mysql|psql)",
            r"^\$",
            r"^python\s",
            r"^import\s",
        ]
        
        assistant_turns = [
            c for c in trajectory.conversations
            if c.from_role.value == "assistant"
        ]
        
        # Check if reasoning includes commands
        has_command = False
        
        for turn in assistant_turns:
            value = turn.value.lower()
            if any(p in value for p in ["nmap", "gobuster", "ffuf", "curl", "sqlmap", "scan", "exploit"]):
                has_command = True
                break
        
        if not has_command:
            warnings.append("No clear command references found")
        
        score = 1.0 if has_command else 0.5
        
        return {
            "passed": has_command,
            "score": score,
            "errors": errors
        }


class ChronologyValidator(BaseValidator):
    """Validate chronological order."""
    
    def validate(self, trajectory: AgentTrajectory, config: dict) -> dict:
        """Validate phase order."""
        errors = []
        
        # Expected order
        expected_order = ["recon", "enum", "exploit", "privesc", "post", "cleanup"]
        
        # Extract phase mentions
        phases_mentioned = []
        
        for conv in trajectory.conversations:
            if conv.from_role.value == "assistant":
                value = conv.value.lower()
                for phase in expected_order:
                    if phase in value:
                        phases_mentioned.append((phase, value[:50]))
        
        if len(phases_mentioned) >= 2:
            # Check order
            prev_idx = -1
            valid_order = True
            
            for phase, _ in phases_mentioned:
                curr_idx = expected_order.index(phase) if phase in expected_order else -1
                if curr_idx < prev_idx and prev_idx >= 0:
                    valid_order = False
                prev_idx = max(prev_idx, curr_idx)
            
            if not valid_order:
                warnings.append("Phases in unusual order")
        
        return {
            "passed": True,
            "score": 0.9
        }


class DepthValidator(BaseValidator):
    """Validate trajectory has sufficient depth."""
    
    MIN_CONVERSATIONS = 5
    MIN_STEPS = 3
    
    def validate(self, trajectory: AgentTrajectory, config: dict) -> dict:
        """Check depth."""
        errors = []
        
        conv_count = len(trajectory.conversations)
        
        if conv_count < self.MIN_CONVERSATIONS:
            errors.append(f"Too few turns: {conv_count}")
        
        tool_turns = [
            c for c in trajectory.conversations
            if c.from_role.value == "tool"
        ]
        
        if len(tool_turns) < self.MIN_STEPS:
            errors.append(f"Too few tool uses: {len(tool_turns)}")
        
        score = min(1.0, conv_count / 10.0)
        
        return {
            "passed": len(errors) == 0,
            "score": score,
            "errors": errors
        }


class DuplicateValidator(BaseValidator):
    """Check for duplicate/similar trajectories."""
    
    def __init__(self):
        self.seen_hashes = set()
    
    def validate(self, trajectory: AgentTrajectory, config: dict) -> dict:
        """Check for duplicates."""
        # Generate hash
        content = str(trajectory.conversations)
        hash_val = hashlib.md5(content.encode()).hexdigest()
        
        is_duplicate = hash_val in self.seen_hashes
        
        if not is_duplicate:
            self.seen_hashes.add(hash_val)
        
        return {
            "passed": not is_duplicate,
            "score": 0.0 if is_duplicate else 1.0
        }