"""Content normalization - converting raw content to structured attack events."""

import hashlib
import logging
import re
from datetime import datetime
from typing import Any, Optional

from ..models import (
    AttackEvent,
    AttackCategory,
    ScrapedContent,
    StepType,
    ToolName
)
from .base import BaseNormalizer
from .attack_phases import AttackPhaseClassifier

logger = logging.getLogger(__name__)


class ContentNormalizer(BaseNormalizer):
    """
    Normalize scraped content into structured attack events.
    
    Converts raw markdown/HTML/text content into structured events with:
    - step_type: enumeration, exploitation, privesc, etc.
    - observation: What was observed
    - command: Command executed
    - output: Command output
    - reasoning: Why action was taken
    """
    
    def __init__(self):
        self.phase_classifier = AttackPhaseClassifier()
        
        # Command extraction patterns
        self.command_patterns = self._compile_command_patterns()
        
        # Tool detection
        self.tool_patterns = self._compile_tool_patterns()
        
        # Output extraction
        self.output_patterns = self._compile_output_patterns()
    
    def _compile_command_patterns(self) -> re.Pattern:
        """Compile patterns for extracting commands."""
        patterns = [
            r"\$\s*([^\n]+(?:\n(?!\$)[^\n]+)*)",  # $ commands
            r"#\s*([^\n]+(?:\n(?![#$])[^\n]+)*)",  # # comments/root
            r">\s*([^\n]+(?:\n[^\$#>][^\n]+)*)",   # > prompts
            r"(?:nmap|gobuster|ffuf|sqlmap|hydra|cme|smbclient|enum4linux|curl|wget|ssh|python)\s+[^\n]+",
        ]
        return re.compile("|".join(patterns), re.MULTILINE)
    
    def _compile_tool_patterns(self) -> dict[str, re.Pattern]:
        """Compile patterns for tool detection."""
        return {
            "nmap": re.compile(r"\bnmap\b", re.IGNORECASE),
            "gobuster": re.compile(r"\bgobuster\b", re.IGNORECASE),
            "ffuf": re.compile(r"\bffuf\b", re.IGNORECASE),
            "sqlmap": re.compile(r"\bsqlmap\b", re.IGNORECASE),
            "hydra": re.compile(r"\bhydra\b", re.IGNORECASE),
            "crackmapexec": re.compile(r"\bcrackmapexec\b|\bcme\b", re.IGNORECASE),
            "smbclient": re.compile(r"\bsmbclient\b", re.IGNORECASE),
            "enum4linux": re.compile(r"\benum4linux\b", re.IGNORECASE),
            "impacket": re.compile(r"\bimpacket\b", re.IGNORECASE),
            "linpeas": re.compile(r"\blinpeas\b", re.IGNORECASE),
            "winpeas": re.compile(r"\bwinpeas\b", re.IGNORECASE),
            "bloodhound": re.compile(r"\bbloodhound\b", re.IGNORECASE),
            "netcat": re.compile(r"\bnc\b|\bnetcat\b", re.IGNORECASE),
            "curl": re.compile(r"\bcurl\b", re.IGNORECASE),
            "wget": re.compile(r"\bwget\b", re.IGNORECASE),
            "ssh": re.compile(r"\bssh\b", re.IGNORECASE),
            "mimikatz": re.compile(r"\bmimikatz\b", re.IGNORECASE),
            "responder": re.compile(r"\bresponder\b", re.IGNORECASE),
            "kerberoast": re.compile(r"\bkerberoast\b", re.IGNORECASE),
        }
    
    def _compile_output_patterns(self) -> re.Pattern:
        """Compile patterns for extracting command outputs."""
        return re.compile(
            r"(?:Starting|Discovered|Scanned|Nmap|Found|Service)\s*[^\n]+",
            re.IGNORECASE
        )
    
    def normalize(self, content: ScrapedContent) -> list[AttackEvent]:
        """
        Normalize content into attack events.
        
        Args:
            content: Scraped content
            
        Returns:
            List of structured attack events
        """
        text = content.content
        
        if not text or len(text) < 200:
            return []
        
        # Split into potential steps
        steps = self._split_into_steps(text)
        
        events = []
        prev_event: Optional[AttackEvent] = None
        
        for i, step_text in enumerate(steps):
            # Extract command from step
            command = self._extract_command(step_text)
            if not command:
                continue
            
            # Detect tool used
            tool = self._detect_tool(command)
            
            # Extract output
            output = self._extract_output(step_text, command)
            
            # Classify step type
            step_type = self._classify_step_type(step_text, command)
            
            # Generate observation
            observation = self._generate_observation(step_text, command, output)
            
            # Generate reasoning
            reasoning = self._generate_reasoning(step_text, step_type, prev_event)
            
            event = AttackEvent(
                step_type=step_type,
                observation=observation,
                command=command,
                output=output,
                reasoning=reasoning,
                tool_used=tool,
                target=self._extract_target(command),
                success=self._is_success(step_text),
                metadata={
                    "source_url": content.url,
                    "source_title": content.title,
                    "source": content.source,
                }
            )
            
            events.append(event)
            prev_event = event
        
        # Classify overall attack category
        category = self._classify_attack_category(text)
        
        return events
    
    def _split_into_steps(self, text: str) -> list[str]:
        """Split text into potential attack steps."""
        steps = []
        
        # Split by common delimiters
        split_patterns = [
            r"\n##?\s+",  # Markdown headers
            r"\n\d+[\).\]\s]",  # Numbered steps
            r"\n\*\s+",  # Bullet points
            r"\n-\s+",  # Dash bullets
        ]
        
        current = text
        for pattern in split_patterns:
            parts = re.split(pattern, current)
            if len(parts) > len(steps) if steps else len(parts) > 1:
                current = "\n".join(parts)
                steps = [s.strip() for s in parts if s.strip()]
        
        if not steps:
            # Fallback: split by paragraphs
            steps = [p.strip() for p in text.split("\n\n") if p.strip()]
        
        # Filter to steps with commands
        filtered = []
        for step in steps:
            if self._contains_command(step):
                filtered.append(step)
        
        return filtered
    
    def _contains_command(self, text: str) -> bool:
        """Check if text contains a command."""
        return bool(re.search(r"(\$|#|>|nmap|gobuster|ffuf|curl|wget|ssh|python)", text, re.IGNORECASE))
    
    def _extract_command(self, text: str) -> str:
        """Extract command from text."""
        # Pattern for shell commands
        patterns = [
            r"\$\s*([^\n]+)",  # $ command
            r"root@[^#]*#\s*([^\n]+)",  # root prompt
            r">\s*([^\n]+)",  # prompt
            r"(nmap|gobuster|ffuf|sqlmap|hydra|cme|smbclient|enum4linux|curl|wget|ssh|python|mysql)\s+[^\n]+",
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
            if match:
                return match.group(0).strip()
        
        return ""
    
    def _detect_tool(self, command: str) -> Optional[ToolName]:
        """Detect which tool was used."""
        command_lower = command.lower()
        
        for tool_name, pattern in self.tool_patterns.items():
            if pattern.search(command):
                try:
                    return ToolName(tool_name)
                except ValueError:
                    pass
        
        # Generic detection
        if command_lower.startswith("nmap"):
            return ToolName.NMAP
        elif command_lower.startswith("gobuster"):
            return ToolName.GOBUSTER
        elif command_lower.startswith("ffuf"):
            return ToolName.FFUF
        elif command_lower.startswith("sqlmap"):
            return ToolName.SQLMAP
        elif command_lower.startswith("curl"):
            return ToolName.CURL
        
        return None
    
    def _extract_output(self, text: str, command: str) -> str:
        """Extract output from command execution."""
        # Get text after command
        command_index = text.find(command)
        if command_index >= 0:
            after = text[command_index + len(command):]
            # Clean and truncate
            lines = after.strip().split("\n")[:20]  # Limit lines
            output = "\n".join(lines).strip()
            
            # Remove common artifacts
            output = re.sub(r"^[\[\(].*?[\]\)]", "", output)
            output = output[:1000]  # Limit output length
            
            return output
        
        return ""
    
    def _classify_step_type(self, text: str, command: str) -> StepType:
        """Classify step type from text and command."""
        text_lower = text.lower()
        
        # Enumeration patterns
        enum_keywords = ["scan", "enum", "discover", "gobuster", "nmap", "ffuf", "dir", "search"]
        if any(kw in text_lower for kw in enum_keywords):
            return StepType.ENUMERATION
        
        # Exploitation patterns
        exploit_keywords = ["exploit", "payload", "inject", "sqli", "xss", "rce", "upload"]
        if any(kw in text_lower for kw in exploit_keywords):
            return StepType.EXPLOITATION
        
        # Privilege escalation
        privesc_keywords = ["privesc", "sudo", "suid", "kernel", "linpeas", "winpeas"]
        if any(kw in text_lower for kw in privesc_keywords):
            return StepType.PRIVILEGE_ESCALATION
        
        # Lateral movement
        lateral_keywords = ["lateral", "pivot", "smb", "winexe", "psexec", "pass"]
        if any(kw in text_lower for kw in lateral_keywords):
            return StepType.LATERAL_MOVEMENT
        
        # Command-based detection
        if "nmap" in command.lower():
            return StepType.ENUMERATION
        elif "gobuster" in command.lower() or "ffuf" in command.lower():
            return StepType.ENUMERATION
        elif "linpeas" in command.lower() or "winpeas" in command.lower():
            return StepType.PRIVILEGE_ESCALATION
        elif "sqlmap" in command.lower():
            return StepType.EXPLOITATION
        
        return StepType.RECON
    
    def _generate_observation(self, text: str, command: str, output: str) -> str:
        """Generate observation from step text."""
        # Try to extract observation sentence
        sentences = re.split(r"[.!?]", text)
        
        for sentence in sentences[:3]:
            sentence = sentence.strip()
            # Look for observation-like statements
            if any(kw in sentence.lower() for kw in ["found", "discovered", "identified", "observed", "detected"]):
                return sentence
        
        # Generate from command and output
        if output:
            # Extract key findings from output
            lines = output.split("\n")
            key_lines = [l for l in lines if l.strip() and not l.startswith("==")][:3]
            return " | ".join(key_lines)
        
        # Default
        tool = self._detect_tool(command)
        return f"Executed {tool.value if tool else 'command'}: {command[:50]}"
    
    def _generate_reasoning(self, text: str, step_type: StepType, prev_event: Optional[AttackEvent]) -> str:
        """Generate reasoning for action."""
        reasoning_templates = {
            StepType.ENUMERATION: "Performing {phase} to discover {target}...",
            StepType.RECON: "Gathering initial information about the target...",
            StepType.EXPLOITATION: "Attempting to {action} on discovered {target}...",
            StepType.PRIVILEGE_ESCALATION: "Escalating privileges to gain root access...",
            StepType.LATERAL_MOVEMENT: "Moving laterally to {target}...",
        }
        
        template = reasoning_templates.get(step_type, "Executing attack step...")
        
        # Add context from previous step if available
        if prev_event:
            prev_type = prev_event.step_type.value
            template = template.replace("{phase}", prev_type)
            template = template.replace("{previous}", prev_type)
        else:
            template = template.replace("{phase}", "enumeration")
        
        return template
    
    def _extract_target(self, command: str) -> str:
        """Extract target from command."""
        # IP addresses
        ip_match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", command)
        if ip_match:
            return ip_match.group(1)
        
        # Hostnames
        host_match = re.search(r"-i\s+([^\s]+)", command)
        if host_match:
            return host_match.group(1)
        
        # URLs
        url_match = re.search(r"(https?://[^\s]+)", command)
        if url_match:
            return url_match.group(1)
        
        return ""
    
    def _is_success(self, text: str) -> bool:
        """Check if step appears successful."""
        text_lower = text.lower()
        
        # Failure indicators
        if any(kw in text_lower for kw in ["failed", "error", "denied", "refused", "not found", "timed out"]):
            if "but" not in text_lower and "however" not in text_lower:
                return False
        
        # Success indicators
        success_keywords = ["found", "obtained", "gained", "success", "owned", "root", "admin", "meterpreter"]
        return any(kw in text_lower for kw in success_keywords)
    
    def _classify_attack_category(self, text: str) -> Optional[AttackCategory]:
        """Classify overall attack category."""
        text_lower = text.lower()
        
        # Web exploitation
        if any(kw in text_lower for kw in ["sql", "sqli", "injection", "xss", "ssti", "ssrf", "file upload", "deserialization"]):
            return AttackCategory.WEB_EXPLOITATION
        
        # Active Directory
        if any(kw in text_lower for kw in ["kerberos", "ntlm", "ldap", "smb", "gold ticket", " DCSync", "bloodhound"]):
            return AttackCategory.ACTIVE_DIRECTORY
        
        # Linux privesc
        if any(kw in text_lower for kw in ["linux", "ubuntu", "debian", "suid", "sudo", "cron"]):
            return AttackCategory.LINUX_PRIVESC
        
        # Windows privesc
        if any(kw in text_lower for kw in ["windows", "win32", "kerberoast", "mimikatz", "seimpersonate"]):
            return AttackCategory.WINDOWS_PRIVESC
        
        # Cloud
        if any(kw in text_lower for kw in ["aws", "azure", "gcp", "s3 bucket", "iam"]):
            return AttackCategory.CLOUD_EXPLOITATION
        
        # Docker
        if any(kw in text_lower for kw in ["docker", "container", "cgroups"]):
            return AttackCategory.DOCKER_ESCAPE
        
        return None