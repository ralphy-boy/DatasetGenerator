"""Failure injection system for creating imperfect trajectories."""

import logging
import random
from typing import Any, Optional

from ..models import AgentTrajectory, AttackEvent, AttackEvent, StepType
from .base_injector import BaseFailureInjector

logger = logging.getLogger(__name__)


class FailureInjector:
    """
    Inject imperfect trajectories.
    
    Injects:
    - Failed exploits
    - Dead ends
    - Incorrect assumptions
    - Noisy enumeration
    - False positives
    - Retries
    - Alternate paths
    """
    
    def __init__(self, failure_rate: float = 0.35):
        self.failure_rate = failure_rate
        
        self.injectors = [
            FailedExploitInjector(),
            DeadEndInjector(),
            NoisyEnumerationInjector(),
            FalsePositiveInjector(),
            RetryInjector(),
            WrongToolInjector(),
            IncorrectAssumptionInjector(),
        ]
    
    def inject(
        self,
        trajectory: AgentTrajectory,
        config: dict = None
    ) -> AgentTrajectory:
        """
        Inject failures into trajectory.
        
        Args:
            trajectory: Input trajectory
            config: Configuration
            
        Returns:
            Trajectory with injected failures
        """
        if random.random() > self.failure_rate:
            return trajectory
        
        config = config or {}
        
        # Select injector
        injector = random.choice(self.injectors)
        
        try:
            return injector.inject(trajectory, config)
        except Exception as e:
            logger.warning(f"Failed to inject failure: {e}")
            return trajectory
    
    def inject_batch(
        self,
        trajectories: list[AgentTrajectory],
        config: dict = None
    ) -> list[AgentTrajectory]:
        """Inject failures into batch."""
        return [self.inject(t, config) for t in trajectories]


class BaseFailureInjector:
    """Base class for failure injectors."""
    
    def inject(
        self,
        trajectory: AgentTrajectory,
        config: dict
    ) -> AgentTrajectory:
        """Inject failure."""
        raise NotImplementedError


class FailedExploitInjector(BaseFailureInjector):
    """Inject failed exploitation attempt."""
    
    def inject(
        self,
        trajectory: AgentTrajectory,
        config: dict
    ) -> AgentTrajectory:
        """Inject failed exploit."""
        # Find exploitation phase
        for i, conv in enumerate(trajectory.conversations):
            if conv.from_role.value == "assistant" and "exploit" in conv.value.lower():
                # Modify to indicate failure
                trajectory.conversations[i].value += " The exploit failed to execute."
                
                # Update tool output to show failure
                next_idx = i + 1
                if next_idx < len(trajectory.conversations):
                    if trajectory.conversations[next_idx].from_role.value == "tool":
                        trajectory.conversations[next_idx].value = "Exploit failed: connection refused"
                
                break
        
        trajectory.metadata["failure_injected"] = True
        trajectory.metadata["failure_type"] = "exploit_failed"
        trajectory.success = False
        
        return trajectory


class DeadEndInjector(BaseFailureInjector):
    """Inject dead end after reaching a stopping point."""
    
    def inject(
        self,
        trajectory: AgentTrajectory,
        config: dict
    ) -> AgentTrajectory:
        """Inject dead end."""
        # Add "stuck" message near middle
        mid = len(trajectory.conversations) // 2
        
        if mid > 0:
            trajectory.conversations.insert(
                mid,
                ConversationTurn(
                    from_role=ConversationRole.ASSISTANT,
                    value="No further vectors identified. The path appears dead."
                )
            )
        
        trajectory.metadata["failure_injected"] = True
        trajectory.metadata["failure_type"] = "dead_end"
        
        return trajectory


class NoisyEnumerationInjector(BaseFailureInjector):
    """Inject noisy/false positive enumeration results."""
    
    def inject(
        self,
        trajectory: AgentTrajectory,
        config: dict
    ) -> AgentTrajectory:
        """Inject noisy results."""
        for i, conv in enumerate(trajectory.conversations):
            if conv.from_role.value == "tool":
                # Add noise to output
                lines = conv.value.split("\n")
                noise_lines = [
                    "Scanning: [noisy output]",
                    "Found: suspicious file",
                    "WARNING: ambiguous results"
                ]
                
                # Randomly modify output
                if random.random() < 0.5:
                    for line in noise_lines[:2]:
                        lines.insert(random.randint(0, len(lines)), line)
                
                trajectory.conversations[i].value = "\n".join(lines)
        
        trajectory.metadata["failure_injected"] = True
        trajectory.metadata["failure_type"] = "noisy_enumeration"
        
        return trajectory


class FalsePositiveInjector(BaseFailureInjector):
    """Inject false positive findings."""
    
    def inject(
        self,
        trajectory: AgentTrajectory,
        config: dict
    ) -> AgentTrajectory:
        """Inject false positives."""
        for i, conv in enumerate(trajectory.conversations):
            if conv.from_role.value == "tool":
                # Add false positives
                fp = [
                    "Found vulnerability: CVE-9999-9999 (false positive)",
                    "Admin panel: /admin (redirects to login)"
                ]
                
                if random.random() < 0.3:
                    lines = conv.value.split("\n")
                    lines.insert(1, random.choice(fp))
                    trajectory.conversations[i].value = "\n".join(lines)
        
        trajectory.metadata["failure_injected"] = True
        trajectory.metadata["failure_type"] = "false_positive"
        
        return trajectory


class RetryInjector(BaseFailureInjector):
    """Inject retry after failed attempt."""
    
    def inject(
        self,
        trajectory: AgentTrajectory,
        config: dict
    ) -> AgentTrajectory:
        """Inject retry sequence."""
        # Find a failed step and add retry
        for i, conv in enumerate(trajectory.conversations):
            if conv.from_role.value == "tool" and any(err in conv.value.lower() for err in ["failed", "denied", "error"]):
                # Add retry message
                retry_msg = ConversationTurn(
                    from_role=ConversationRole.ASSISTANT,
                    value="Attempting with alternative parameters..."
                )
                
                trajectory.conversations.insert(i, retry_msg)
                break
        
        trajectory.metadata["failure_injected"] = True
        trajectory.metadata["failure_type"] = "retry"
        
        return trajectory


class WrongToolInjector(BaseFailureInjector):
    """Inject wrong tool usage."""
    
    def inject(
        self,
        trajectory: AgentTrajectory,
        config: dict
    ) -> AgentTrajectory:
        """Inject wrong tool."""
        for i, conv in enumerate(trajectory.conversations):
            if conv.from_role.value == "assistant":
                # Change tool recommendation
                if "nmap" in conv.value.lower():
                    conv.value = conv.value.replace("nmap", "masscan")
                elif "gobuster" in conv.value.lower():
                    conv.value = conv.value.replace("gobuster", "dirb")
        
        trajectory.metadata["failure_injected"] = True
        trajectory.metadata["failure_type"] = "wrong_tool"
        
        return trajectory


class IncorrectAssumptionInjector(BaseFailureInjector):
    """Inject incorrect assumption."""
    
    def inject(
        self,
        trajectory: AgentTrajectory,
        config: dict
    ) -> AgentTrajectory:
        """Inject incorrect assumption."""
        assumptions = [
            "Assumed vulnerability in outdated Apache",
            "Believed SSH was available, it wasn't",
            "Thought admin panel was exposed, it wasn't",
            "Assumed database was MySQL, was PostgreSQL",
        ]
        
        for i, conv in enumerate(trajectory.conversations):
            if conv.from_role.value == "assistant":
                conv.value += f" (Assumption: {random.choice(assumptions)})"
                break
        
        trajectory.metadata["failure_injected"] = True
        trajectory.metadata["failure_type"] = "incorrect_assumption"
        
        return trajectory


from ..models import ConversationTurn, ConversationRole