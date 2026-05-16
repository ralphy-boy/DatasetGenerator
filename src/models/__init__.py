"""Core data models for the cybersecurity dataset generation system."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


class StepType(str, Enum):
    """Attack phase step types."""
    ENUMERATION = "enumeration"
    RECON = "recon"
    EXPLOITATION = "exploitation"
    PRIVILEGE_ESCALATION = "privesc"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    DATA_EXFILTRATION = "data_exfiltration"
    POST_EXPLOITATION = "post_exploitation"
    CLEANUP = "cleanup"
    FAILED_ATTEMPT = "failed_attempt"
    RETRY = "retry"
    PIVOT = "pivot"


class ToolName(str, Enum):
    """Supported penetration testing tools."""
    NMAP = "nmap"
    GOBUSTER = "gobuster"
    FFUF = "ffuf"
    SQLMAP = "sqlmap"
    HYDRA = "hydra"
    CRACKMAPEXEC = "crackmapexec"
    SMBCLIENT = "smbclient"
    ENUM4LINUX = "enum4linux"
    IMPACKET = "impacket"
    LINPEAS = "linpeas"
    WINPEAS = "winpeas"
    BLOODHOUND = "bloodhound"
    NETCAD = "netcat"
    CURL = "curl"
    WGET = "wget"
    SSH = "ssh"
    SMBMOUNT = "smbmount"
    LDAPSEARCH = "ldapsearch"
    KERBEROAST = "kerberoast"
    MIMIKATZ = "mimikatz"
    RESPONDER = "responder"
    POWERSHELL = "powershell"
    BASH = "bash"
    PYTHON = "python"
    WIRESHARK = "wireshark"
    METASPLOIT = "metasploit"


class AttackCategory(str, Enum):
    """Attack categories for dataset diversity."""
    WEB_EXPLOITATION = "web_exploitation"
    ACTIVE_DIRECTORY = "active_directory"
    LINUX_PRIVESC = "linux_privesc"
    WINDOWS_PRIVESC = "windows_privesc"
    CLOUD_EXPLOITATION = "cloud_exploitation"
    DOCKER_ESCAPE = "docker_escape"
    KUBERNETES_ATTACK = "kubernetes_attack"
    API_EXPLOITATION = "api_exploitation"
    LATERAL_MOVEMENT = "lateral_movement"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    SSRF = "ssrf"
    SSTI = "ssti"
    DESERIALIZATION = "deserialization"


class Difficulty(str, Enum):
    """Challenge difficulty levels."""
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"


class ConversationRole(str, Enum):
    """Conversation participant roles."""
    HUMAN = "human"
    ASSISTANT = "assistant"
    TOOL = "tool"


# Data models for different phases

class AttackEvent(BaseModel):
    """Structured attack event from normalized content."""
    step_type: StepType
    observation: str = Field(..., description="What was observed")
    command: str = Field(..., description="Command executed")
    output: str = Field(..., description="Command output")
    reasoning: str = Field(..., description="Why this action was taken")
    timestamp: Optional[datetime] = None
    tool_used: Optional[ToolName] = None
    target: Optional[str] = None
    success: bool = True
    error_message: Optional[str] = None
    metadata: dict = Field(default_factory=dict)


class ConversationTurn(BaseModel):
    """Single turn in agent conversation."""
    from_role: ConversationRole
    value: str
    tool_name: Optional[ToolName] = None
    tool_call_id: Optional[str] = None


class AgentTrajectory(BaseModel):
    """Complete agent trajectory in Agent-FLAN format."""
    id: str
    conversations: list[ConversationTurn]
    metadata: dict = Field(default_factory=dict)
    
    # Extended metadata
    difficulty: Optional[Difficulty] = None
    category: Optional[AttackCategory] = None
    tools_used: list[ToolName] = Field(default_factory=list)
    attack_phases: list[StepType] = Field(default_factory=list)
    source_origin: Optional[str] = None
    success: bool = True
    total_steps: int = 0


class ScrapedContent(BaseModel):
    """Raw scraped content from web sources."""
    url: str
    content_type: str
    content: str
    title: Optional[str] = None
    author: Optional[str] = None
    date: Optional[datetime] = None
    source: str
    raw_html: Optional[str] = None
    extracted_at: datetime = Field(default_factory=datetime.utcnow)


class ValidationResult(BaseModel):
    """Dataset validation result."""
    is_valid: bool
    score: float = Field(..., ge=0, le=1)
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    checks_passed: dict = Field(default_factory=dict)


@dataclass
class DatasetStats:
    """Statistics for generated dataset."""
    total_samples: int = 0
    successful_trajectories: int = 0
    failed_trajectories: int = 0
    average_steps: float = 0.0
    category_distribution: dict = None
    tool_usage_distribution: dict = None
    difficulty_distribution: dict = None
    
    def __post_init__(self):
        if self.category_distribution is None:
            self.category_distribution = {}
        if self.tool_usage_distribution is None:
            self.tool_usage_distribution = {}
        if self.difficulty_distribution is None:
            self.difficulty_distribution = {}


# Message types for multi-turn conversations

class ToolCallMessage(BaseModel):
    """Tool call message for agent."""
    name: ToolName
    arguments: dict = Field(default_factory=dict)
    call_id: str


class ToolResultMessage(BaseModel):
    """Tool result message."""
    call_id: str
    output: str
    error: Optional[str] = None
    success: bool = True


class ReasoningMessage(BaseModel):
    """Reasoning/thinking message."""
    thought: str
    action: str
    observation: str
    reasoning: str


# Export formats

class ExportMetadata(BaseModel):
    """Metadata for dataset export."""
    version: str = "1.0.0"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    total_samples: int
    format: str
    categories: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    difficulty: list[str] = Field(default_factory=list)


class HuggingFaceDataset(BaseModel):
    """HuggingFace datasets format."""
    id: str
    conversations: list[dict]
    metadata: dict


class ShareGPTFormat(BaseModel):
    """ShareGPT conversation format."""
    id: str
    conversations: list[dict]
    system_message: Optional[str] = None


class ReActFormat(BaseModel):
    """ReAct trajectory format."""
    id: str
    steps: list[dict]
    finalAnswer: str