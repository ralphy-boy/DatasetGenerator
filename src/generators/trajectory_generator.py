"""Agent trajectory generation - converting events to Agent-FLAN format."""

import hashlib
import json
import logging
import uuid
from datetime import datetime
from typing import Any, Optional

from ..models import (
    AgentTrajectory,
    AttackCategory,
    AttackEvent,
    ConversationRole,
    ConversationTurn,
    Difficulty,
    ToolName
)
from .base import BaseGenerator

logger = logging.getLogger(__name__)


class TrajectoryGenerator(BaseGenerator):
    """
    Generate agent trajectories in Agent-FLAN format.
    
    Converts normalized attack events into conversational
    trajectories with reasoning, tool calls, and outputs.
    
    Output format (Agent-FLAN compatible):
    {
      "id": "sample_123",
      "conversations": [
        {"from": "human", "value": "Task description"},
        {"from": "assistant", "value": "Thought + action"},
        {"from": "tool", "value": "Tool output"}
      ]
    }
    """
    
    def __init__(self):
        self.template_engine = ReasoningTemplateEngine()
        
    def generate(
        self,
        events: list[AttackEvent],
        config: Optional[dict] = None
    ) -> list[AgentTrajectory]:
        """
        Generate trajectories from attack events.
        
        Args:
            events: List of attack events
            config: Generation config
            
        Returns:
            List of agent trajectories
        """
        if not events:
            return []
        
        config = config or {}
        
        # Group events into trajectories
        grouped = self._group_events(events, config)
        
        trajectories = []
        
        for group in grouped:
            trajectory = self._create_trajectory(group, config)
            if trajectory:
                trajectories.append(trajectory)
        
        return trajectories
    
    def _group_events(
        self, 
        events: list[AttackEvent],
        config: dict
    ) -> list[list[AttackEvent]]:
        """
        Group events into trajectories.
        
        Groups by category or sequential flow.
        """
        min_steps = config.get("min_steps", 3)
        max_steps = config.get("max_steps", 50)
        
        if len(events) <= max_steps:
            if len(events) >= min_steps:
                return [events]
            return []
        
        # Split into multiple trajectories
        groups = []
        current = []
        
        for event in events:
            current.append(event)
            
            if len(current) >= min_steps:
                # Check for good stopping point
                if event.step_type.name in ["POST_EXPLOITATION", "CLEANUP", "DATA_EXFILTRATION"]:
                    groups.append(current)
                    current = []
        
        if current and len(current) >= min_steps:
            groups.append(current)
        
        return groups
    
    def _create_trajectory(
        self,
        events: list[AttackEvent],
        config: dict
    ) -> Optional[AgentTrajectory]:
        """Create trajectory from events."""
        if len(events) < 3:
            return None
        
        # Generate unique ID
        sample_id = self._generate_id(events)
        
        # Build conversation turns
        turns = []
        
        # Initial human message
        initial = self._create_initial_message(events, config)
        turns.append(ConversationTurn(
            from_role=ConversationRole.HUMAN,
            value=initial
        ))
        
        # Convert events to turns
        for i, event in enumerate(events):
            # Assistant reasoning + action
            assistant_turn = self._create_assistant_turn(event, i, events)
            turns.append(ConversationTurn(
                from_role=ConversationRole.ASSISTANT,
                value=assistant_turn
            ))
            
            # Tool output
            tool_turn = self._create_tool_turn(event)
            if tool_turn:
                turns.append(ConversationTurn(
                    from_role=ConversationRole.TOOL,
                    value=tool_turn
                ))
        
        # Calculate metadata
        metadata = self._extract_metadata(events, config)
        
        trajectory = AgentTrajectory(
            id=sample_id,
            conversations=turns,
            metadata=metadata,
            difficulty=metadata.get("difficulty"),
            category=metadata.get("category"),
            tools_used=metadata.get("tools_used", []),
            attack_phases=metadata.get("attack_phases", []),
            source_origin=metadata.get("source"),
            success=metadata.get("success", True),
            total_steps=len(events)
        )
        
        return trajectory
    
    def _create_initial_message(
        self,
        events: list[AttackEvent],
        config: dict
    ) -> str:
        """Create initial human message."""
        first_event = events[0]
        target = first_event.target or "the target"
        
        # Try to determine challenge context
        source = first_event.metadata.get("source", "")
        
        messages = [
            f"Target: {target}. Start the penetration test.",
            f"I need to {first_event.step_type.value} on {target}.",
            f"Begin assessment on {target}. What do you find?",
        ]
        
        return messages[0]
    
    def _create_assistant_turn(
        self,
        event: AttackEvent,
        index: int,
        events: list[AttackEvent]
    ) -> str:
        """Create assistant turn with reasoning."""
        # Get previous events context
        prev_reasoning = ""
        if index > 0:
            prev_reasoning = events[index - 1].reasoning
        
        # Build reasoning
        reasoning = self.template_engine.build_reasoning(
            event=event,
            index=index,
            total=len(events),
            prev_reasoning=prev_reasoning
        )
        
        return reasoning
    
    def _create_tool_turn(self, event: AttackEvent) -> str:
        """Create tool output turn."""
        output = event.output
        
        if not output:
            return f"Tool {event.tool_used.value if event.tool_used else 'executed'} completed."
        
        # Clean output
        output = output.strip()
        
        # Truncate if too long
        if len(output) > 500:
            output = output[:500] + "\n... [output truncated]"
        
        return output
    
    def _generate_id(self, events: list[AttackEvent]) -> str:
        """Generate unique trajectory ID."""
        # Use timestamp and sample of events
        content = f"{datetime.utcnow().isoformat()}{events[0].command[:50]}"
        hash_id = hashlib.md5(content.encode()).hexdigest()[:12]
        
        return f"traj_{hash_id}"
    
    def _extract_metadata(
        self,
        events: list[AttackEvent],
        config: dict
    ) -> dict:
        """Extract metadata from events."""
        # Extract tools used
        tools = list(set(
            e.tool_used for e in events 
            if e.tool_used
        ))
        
        # Extract phases
        phases = list(set(e.step_type for e in events))
        
        # Determine success
        has_failure = any(not e.success for e in events)
        
        # Determine category
        category = None
        for e in events:
            if category_meta := e.metadata.get("category"):
                try:
                    category = AttackCategory(category_meta)
                    break
                except ValueError:
                    pass
        
        # Determine difficulty
        difficulty = self._estimate_difficulty(events, tools, has_failure)
        
        # Get source
        source = events[0].metadata.get("source", "unknown") if events else "unknown"
        
        return {
            "difficulty": difficulty,
            "category": category,
            "tools_used": tools,
            "attack_phases": phases,
            "success": not has_failure,
            "source": source,
            "total_events": len(events)
        }
    
    def _estimate_difficulty(
        self,
        events: list[AttackEvent],
        tools: list[ToolName],
        has_failure: bool
    ) -> Difficulty:
        """Estimate difficulty from events."""
        step_count = len(events)
        
        # Use tool complexity
        advanced_tools = {
            ToolName.MIMIKATZ,
            ToolName.BLOODHOUND,
            ToolName.KERBEROAST,
            ToolName.CRACKMAPEXEC,
            ToolName.IMPACKET,
        }
        
        has_advanced = any(t for t in tools if t in advanced_tools)
        
        if step_count > 20 and has_advanced:
            return Difficulty.EXPERT
        elif step_count > 15:
            return Difficulty.ADVANCED
        elif step_count > 8:
            return Difficulty.INTERMEDIATE
        else:
            return Difficulty.BEGINNER


class ReasoningTemplateEngine:
    """Engine for generating reasoning templates."""
    
    # Reasoning templates for different phases
    TEMPLATES = {
        "enumeration": [
            "I need to enumerate {target} to discover open ports and services. {tool} will help identify attack surface.",
            "Starting with {tool} scan to find accessible endpoints. This will reveal potential entry points.",
            "Using {tool} to discover directories and files that might contain vulnerabilities.",
            "Let's run {tool} to fingerprint the service and identify version-specific weaknesses.",
        ],
        "exploitation": [
            "Based on enumeration, {target} appears vulnerable. Attempting exploitation with {tool}.",
            "The discovered {service} has a known exploit. Using {tool} to leverage it.",
            "I found {finding}. Let me try exploiting this with {tool} to gain access.",
            "This looks exploitable. Using {tool} to {action}.",
        ],
        "privesc": [
            "Now I have foothold. Checking for privilege escalation vectors with {tool}.",
            "The current user has limited privileges. Searching for privesc paths using {tool}.",
            "Found potential privesc vector. Exploiting with {tool} to gain root.",
            "Using {tool} to enumerate privilege escalation opportunities.",
        ],
        "lateral": [
            "Validating access on {target}. Searching for lateral movement paths using {tool}.",
            "Time to move laterally. Using {tool} to access other systems.",
            "Found credentials. Using {tool} to pivot to {target}.",
            "Attempting lateral movement with {tool} using obtained credentials.",
        ],
        "post_exploitation": [
            "Now I have access. Let's gather credentials and maintain persistence.",
            "Focusing on looting. Using {tool} to extract sensitive data.",
            "Post-exploitation with {tool} to gather evidence and maintain access.",
            "Time for post-exploitation. Using {tool} to find valuable data.",
        ],
        "recon": [
            "Starting passive reconnaissance on {target}.",
            "Gathering initial information about the target.",
            "Let me collect OSINT on the target before active scanning.",
            "Beginning reconnaissance to understand the target environment.",
        ],
        "pivot": [
            "Initial approach failed. Pivoting to alternative {technique}.",
            "That didn't work. Let me try a different {technique} instead.",
            "Switching tactics after failed attempt.",
        ],
        "retry": [
            "Initial attempt unsuccessful. Retrying with modified parameters.",
            "That exploitation failed. Let me try again with different options.",
            "Attempt failed. Retrying with adjusted settings.",
        ],
        "failed": [
            "The attempt was unsuccessful. Need to try a different approach.",
            "That didn't work. Let me reconsider the attack vector.",
            "The exploit failed. I should try an alternative method.",
        ],
    }
    
    def build_reasoning(
        self,
        event: AttackEvent,
        index: int,
        total: int,
        prev_reasoning: str = ""
    ) -> str:
        """Build reasoning string."""
        step_type = event.step_type.value
        
        # Get success status
        if not event.success:
            if event.step_type == StepType.RETRY:
                step_type = "retry"
            else:
                step_type = "failed"
        
        # Get templates
        templates = self.TEMPLATES.get(step_type, self.TEMPLATES["enumeration"])
        
        # Select template based on index
        template = templates[index % len(templates)]
        
        # Fill in variables
        tool = event.tool_used.value if event.tool_used else "tool"
        target = event.target or "target"
        output = event.output
        
        # Extract finding from output
        finding = ""
        if output and len(output) > 10:
            lines = output.split("\n")
            finding = lines[0][:50]
        
        reasoning = template.format(
            tool=tool,
            target=target,
            finding=finding,
            action=event.observation[:50] if event.observation else "action",
            service="service",
            technique=event.step_type.value
        )
        
        return reasoning


from ..models import StepType