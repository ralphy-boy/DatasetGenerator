"""
ReAct-style trajectory generator for penetration testing agents.
Produces the exact "Thought/Action" conversational format.
"""

import hashlib
import json
import logging
import random
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
    StepType,
    ToolName
)
from .base import BaseGenerator

logger = logging.getLogger(__name__)

# Available hacking actions for the prompt
HACKING_ACTIONS = [
    {"name": "nmap", "description": "scan ports"},
    {"name": "gobuster", "description": "directory brute-force"},
    {"name": "searchsploit", "description": "search exploits"},
    {"name": "sqlmap", "description": "SQL injection"},
    {"name": "hydra", "description": "password brute-force"},
    {"name": "metasploit", "description": "run exploit"},
    {"name": "click", "description": "click on a button/link in a web app"},
    {"name": "submit", "description": "submit a form or command"},
    {"name": "curl", "description": "make HTTP request"},
    {"name": "wget", "description": "download files"},
    {"name": "ssh", "description": "SSH connection"},
    {"name": "python", "description": "run Python script"},
    {"name": "bash", "description": "run bash command"},
    {"name": "linpeas", "description": "Linux privilege escalation enumeration"},
    {"name": "winpeas", "description": "Windows privilege escalation enumeration"},
    {"name": "bloodhound", "description": "Active Directory enumeration"},
    {"name": "kerberoast", "description": "Kerberoasting attack"},
    {"name": "responder", "description": "Lateral movement via responder"},
]
"""


class ReActTrajectoryGenerator(BaseGenerator):
    """
    Generate ReAct-style trajectories for penetration testing.
    
    Produces conversations in this exact format:
    
    User: 
    Instruction: ...
    Observation: ...
    
    Agent:
    Thought: ...
    Action: tool[args]
    
    User:
    Observation: ...
    
    (repeats until shell obtained or trajectory ends)
    """
    
    def __init__(self):
        self.reasoning_engine = ReActReasoningEngine()
        
    def generate(
        self,
        events: list[AttackEvent],
        config: dict = None
    ) -> list[AgentTrajectory]:
        """
        Generate ReAct-style trajectories from attack events.
        
        Args:
            events: List of structured attack events
            config: Generation config
            
        Returns:
            List of agent trajectories
        """
        if not events:
            return []
        
        config = config or {}
        
        # Group events into trajectories based on continuity
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
        """Group events into trajectories."""
        min_steps = config.get("min_steps", 3)
        max_steps = config.get("max_steps", 30)
        
        if len(events) <= max_steps:
            if len(events) >= min_steps:
                return [events]
            return []
        
        # Split into multiple trajectories
        groups = []
        current = []
        
        for event in events:
            # Group by continuity - same or related target
            if current and event.target != current[-1].target:
                if len(current) >= min_steps:
                    groups.append(current)
                current = []
            
            current.append(event)
            
            if len(current) >= max_steps:
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
        """Create ReAct trajectory from events."""
        if len(events) < 2:
            return None
        
        sample_id = self._generate_id(events)
        
        turns = []
        
        # First user message contains instruction
        first_event = events[0]
        target = first_event.target or first_event.metadata.get("target", "the target")
        instruction = self._create_instruction(events, config)
        
        turns.append(ConversationTurn(
            from_role=ConversationRole.HUMAN,
            value=f"Instruction: {instruction}\n\nObservation: {first_event.metadata.get('initial_obs', 'Target is alive. No prior knowledge.')}"
        ))
        
        # Convert each event to Thought/Action cycles
        for i, event in enumerate(events):
            # Assistant: Thought + Action
            thought, action = self._create_thought_action(event, i, events)
            
            turns.append(ConversationTurn(
                from_role=ConversationRole.ASSISTANT,
                value=f"Thought: {thought}\nAction: {action}"
            ))
            
            # User: Observation (tool output)
            if event.output:
                obs = self._format_observation(event)
            else:
                obs = f"Command executed. {'Success' if event.success else 'Failed'}: {event.command}"
            
            turns.append(ConversationTurn(
                from_role=ConversationRole.HUMAN,
                value=f"Observation: {obs}"
            ))
        
        # Add final state message if needed
        if events[-1].step_type in [StepType.POST_EXPLOITATION, StepType.DATA_EXFILTRATION]:
            turns.append(ConversationTurn(
                from_role=ConversationRole.HUMAN,
                value="Observation:目标已渗透完成。获得了管理员权限/敏感数据。"
            ))
        
        # Extract metadata
        metadata = self._extract_metadata(events, config)
        
        return AgentTrajectory(
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
    
    def _create_instruction(
        self,
        events: list[AttackEvent],
        config: dict
    ) -> str:
        """Create penetration testing instruction."""
        first_event = events[0]
        target = first_event.target or "the target"
        
        # Determine attack type from events
        attack_types = set()
        for event in events:
            step = event.step_type
            if step == StepType.ENUMERATION or step == StepType.RECON:
                attack_types.add("enumerate")
            elif step == StepType.EXPLOITATION:
                attack_types.add("exploit")
            elif step == StepType.PRIVILEGE_ESCALATION:
                attack_types.add("escalate privileges")
            elif step == StepType.LATERAL_MOVEMENT:
                attack_types.add("move laterally")
        
        if not attack_types:
            attack_types.add("enumerate")
        
        verbs = " then ".join(list(attack_types)[:2])
        
        return f"{verbs.capitalize()} on {target}, find vulnerabilities, and get a shell."
    
    def _create_thought_action(
        self,
        event: AttackEvent,
        index: int,
        events: list[AttackEvent]
    ) -> tuple[str, str]:
        """Create Thought and Action from event."""
        # Get tool name
        tool = event.tool_used.value if event.tool_used else self._infer_tool(event.command)
        
        # Get arguments from command
        args = self._extract_args(event.command, tool)
        
        # Generate thought using reasoning engine
        thought = self.reasoning_engine.generate(
            event=event,
            index=index,
            total=len(events)
        )
        
        # Format action
        action = f"{tool}[{args}]" if args else tool
        
        return thought, action
    
    def _infer_tool(self, command: str) -> str:
        """Infer tool name from command."""
        cmd_lower = command.lower().strip()
        
        # Check common tools
        if cmd_lower.startswith("nmap"):
            return "nmap"
        elif cmd_lower.startswith("gobuster"):
            return "gobuster"
        elif "gobuster" in cmd_lower:
            return "gobuster"
        elif any(x in cmd_lower for x in ["ffuf", "dirb", "dirbuster"]):
            return "gobuster"
        elif cmd_lower.startswith("sqlmap"):
            return "sqlmap"
        elif cmd_lower.startswith("hydra"):
            return "hydra"
        elif cmd_lower.startswith("searchsploit"):
            return "searchsploit"
        elif "linpeas" in cmd_lower:
            return "linpeas"
        elif "winpeas" in cmd_lower:
            return "winpeas"
        elif "bloodhound" in cmd_lower:
            return "bloodhound"
        elif "curl" in cmd_lower:
            return "curl"
        elif "wget" in cmd_lower:
            return "wget"
        elif "ssh" in cmd_lower:
            return "ssh"
        elif "python" in cmd_lower:
            return "python"
        elif cmd_lower.startswith("msfconsole") or "msf" in cmd_lower:
            return "metasploit"
        
        # Default
        return "nmap"
    
    def _extract_args(self, command: str, tool: str) -> str:
        """Extract arguments from command."""
        # Remove the tool name prefix
        cmd = command.strip()
        
        if tool in cmd:
            args = cmd[len(tool):].strip()
            # Clean up leading symbols
            if args.startswith("-"):
                return args
            elif args:
                return args
        
        # Extract important parts
        parts = []
        
        # IP addresses
        import re
        ip_match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", command)
        if ip_match:
            parts.append(ip_match.group(1))
        
        # Ports
        port_match = re.search(r"-p\s*([\d,\-]+)", command)
        if port_match:
            parts.append(f"-p {port_match.group(1)}")
        
        # URLs
        url_match = re.search(r"(https?://[^\s]+)", command)
        if url_match:
            parts.append(url_match.group(1))
        
        return " ".join(parts[:2]) if parts else command[:50]
    
    def _format_observation(self, event: AttackEvent) -> str:
        """Format tool output as observation."""
        output = event.output
        
        if not output:
            return "Command executed."
        
        # Clean and truncate
        lines = output.strip().split("\n")[:10]
        
        # Format key info
        formatted = []
        for line in lines:
            line = line.strip()
            if line and len(line) > 3:
                formatted.append(line)
        
        if formatted:
            return "\n".join(formatted)[:300]
        
        return f"Output: {output[:100]}"
    
    def _generate_id(self, events: list[AttackEvent]) -> str:
        """Generate unique trajectory ID."""
        content = f"{datetime.utcnow().isoformat()}{events[0].command[:50]}"
        hash_id = hashlib.md5(content.encode()).hexdigest()[:12]
        
        return f"hack_{hash_id}"
    
    def _extract_metadata(
        self,
        events: list[AttackEvent],
        config: dict
    ) -> dict:
        """Extract metadata from events."""
        tools = list(set(
            e.tool_used for e in events
            if e.tool_used
        ))
        
        phases = list(set(e.step_type for e in events))
        
        has_failure = any(not e.success for e in events)
        
        # Determine category
        category = self._determine_category(events)
        
        # Determine difficulty
        difficulty = self._estimate_difficulty(events, tools, has_failure)
        
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
    
    def _determine_category(self, events: list[AttackEvent]) -> Optional[AttackCategory]:
        """Determine attack category."""
        step_types = [e.step_type for e in events]
        
        if StepType.EXPLOITATION in step_types:
            # Check web vs AD
            for event in events:
                cmd = event.command.lower()
                if any(x in cmd for x in ["sqlmap", "xss", "ssti", "ssrf", "curl"]):
                    return AttackCategory.WEB_EXPLOITATION
                if any(x in cmd for x in ["kerberoast", "bloodhound", "responder"]):
                    return AttackCategory.ACTIVE_DIRECTORY
        
        if StepType.PRIVILEGE_ESCALATION in step_types:
            for event in events:
                cmd = event.command.lower()
                if "linpeas" in cmd or "linux" in cmd:
                    return AttackCategory.LINUX_PRIVESC
                if "winpeas" in cmd or "windows" in cmd:
                    return AttackCategory.WINDOWS_PRIVESC
        
        if StepType.LATERAL_MOVEMENT in step_types:
            return AttackCategory.LATERAL_MOVEMENT
        
        return AttackCategory.WEB_EXPLOITATION
    
    def _estimate_difficulty(
        self,
        events: list[AttackEvent],
        tools: list[ToolName],
        has_failure: bool
    ) -> Difficulty:
        """Estimate difficulty."""
        step_count = len(events)
        
        advanced_tools = {ToolName.MIMIKATZ, ToolName.BLOODHOUND, ToolName.KERBEROAST}
        has_advanced = any(t for t in tools if t in advanced_tools)
        
        if step_count > 15 and has_advanced:
            return Difficulty.EXPERT
        elif step_count > 10:
            return Difficulty.ADVANCED
        elif step_count > 5:
            return Difficulty.INTERMEDIATE
        return Difficulty.BEGINNER


class ReActReasoningEngine:
    """Engine for generating Thought reasoning."""
    
    # Reasoning templates by step type
    REASONING_TEMPLATES = {
        StepType.RECON: [
            "I need to gather initial information about the target before proceeding.",
            "Starting with reconnaissance to understand the target environment.",
            "Let me collect basic information about the target first.",
            "Beginning with passive reconnaissance to avoid detection.",
        ],
        StepType.ENUMERATION: [
            "I should enumerate the target to discover open ports and running services.",
            "Let me scan for open ports to identify potential attack surfaces.",
            "Scanning the target to find accessible services.",
            "I need to find what services are running on the target.",
        ],
        StepType.EXPLOITATION: [
            "Based on the enumeration, I found a potential vulnerability. Let me try to exploit it.",
            "I found a potentially vulnerable service. Attempting exploitation.",
            "Let me attempt to exploit the discovered vulnerability.",
            "This service appears vulnerable. I'll try to exploit it.",
        ],
        StepType.PRIVILEGE_ESCALATION: [
            "I have initial access. Now I need to escalate privileges to root.",
            "I need to escalate my privileges to gain root access.",
            "Let me check for privilege escalation opportunities.",
            "Searching for ways to escalate to root/administrator.",
        ],
        StepType.LATERAL_MOVEMENT: [
            "Now I need to move laterally to other systems.",
            "Let me attempt to pivot to other machines in the network.",
            "I need to spread access to other systems.",
            "Searching for lateral movement opportunities.",
        ],
        StepType.POST_EXPLOITATION: [
            "I've gained access. Now let me gather sensitive data.",
            "Let me collect valuable information from the target.",
            "Searching for sensitive data and credentials.",
            "Time to loot the target for useful information.",
        ],
        "retry": [
            "The previous attempt failed. Let me try a different approach.",
            "That didn't work. I'll try an alternative method.",
            "Let me adjust my approach and retry.",
        ],
        "failed": [
            "That didn't succeed. I need to reconsider my approach.",
            "The exploit failed. Let me analyze why and try again.",
            "Let me try a different vector.",
        ],
        "pivot": [
            "The current approach isn't working. I need to pivot to a different strategy.",
            "Let me try a different attack vector.",
            "Switching to alternative approach.",
        ],
    }
    
    def generate(
        self,
        event: AttackEvent,
        index: int,
        total: int
    ) -> str:
        """Generate reasoning for an event."""
        step_type = event.step_type
        
        # Check for failure
        if not event.success:
            if StepType.RETRY in [e.step_type for e in [event]]:
                step_type = "retry"
            else:
                step_type = "failed"
        
        # Check for pivot in reasoning
        if "but" in event.reasoning.lower() or "however" in event.reasoning.lower():
            step_type = "pivot"
        
        # Get templates
        templates = self.REASONING_TEMPLATES.get(
            step_type,
            self.REASONING_TEMPLATES[StepType.ENUMERATION]
        )
        
        # Select based on position
        template = templates[index % len(templates)]
        
        return template


class FailureInjector:
    """Inject failures into trajectories."""
    
    def __init__(self, failure_rate: float = 0.35):
        self.failure_rate = failure_rate
    
    def inject(
        self,
        trajectory: AgentTrajectory
    ) -> AgentTrajectory:
        """Inject failure into trajectory."""
        import random
        if random.random() > self.failure_rate:
            return trajectory
        
        # Find an action and make it fail
        for conv in trajectory.conversations:
            if conv.from_role == ConversationRole.ASSISTANT:
                if "Action:" in conv.value:
                    # Add failure indicator
                    conv.value = conv.value.replace(
                        "Action:",
                        "Thought: The command seems to have failed. Let me analyze the output and try a different approach.\nAction:"
                    )
                    break
        
        # Update last observation to show failure
        if trajectory.conversations:
            last_conv = trajectory.conversations[-1]
            if last_conv.from_role == ConversationRole.HUMAN:
                last_conv.value = "Observation: Command failed. Connection refused / Access denied."
        
        trajectory.success = False
        return trajectory