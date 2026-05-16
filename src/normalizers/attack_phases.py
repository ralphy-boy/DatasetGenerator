"""Attack phase classification for normalizing content."""

import logging
import re
from typing import Optional

from ..models import AttackCategory, StepType, ToolName

logger = logging.getLogger(__name__)


class AttackPhaseClassifier:
    """
    Classify attack phases and categories from content.
    
    Uses keyword patterns, tool signatures, and context
    to identify attack stages.
    """
    
    # Phase keywords for classification
    PHASE_KEYWORDS = {
        StepType.RECON: [
            "recon", "reconaissance", "information gathering", "passive",
            "whois", "dns", "subdomain", "osint"
        ],
        StepType.ENUMERATION: [
            "enum", "enumerate", "scan", "nmap", "discover", "gobuster",
            "ffuf", "directory", "brute", "force", "listing", "discovered",
            "services", "ports", "open", "running"
        ],
        StepType.EXPLOITATION: [
            "exploit", "attack", "payload", "inject", "upload", "reverse shell",
            "shell", "rce", "code execution", "vulnerability", "sqli",
            "sql injection", "xss", "cross-site", "csrf"
        ],
        StepType.PRIVILEGE_ESCALATION: [
            "privesc", "privilege", "escalat", "root", "admin", "sudo",
            "suid", "kernel", "exploit", "linpeas", "winpeas",
            "gtfobins", "capabilities"
        ],
        StepType.LATERAL_MOVEMENT: [
            "lateral", "pivot", "move", "smb", "winrm", "psexec",
            "winexe", "rmi", "jmx", "ldap", "kerberos"
        ],
        StepType.PERSISTENCE: [
            "persist", "backdoor", "cron", "service", "startup",
            "registry", "ssh key", "authorized_keys"
        ],
        StepType.DATA_EXFILTRATION: [
            "data", "exfiltrat", "download", "dump", "credentials",
            "password", "hash", "sam", "lsass"
        ],
        StepType.POST_EXPLOITATION: [
            "post", "post-exploit", "loot", "local.txt", "user.txt",
            "proof", "flag", "maintain"
        ],
        StepType.CLEANUP: [
            "cleanup", "remove", "delete", "clear", "erase", "cover tracks"
        ]
    }
    
    # Category keywords
    CATEGORY_KEYWORDS = {
        AttackCategory.WEB_EXPLOITATION: [
            "sql", "sqli", "injection", "xss", "ssti", "ssrf", "xxe",
            "deserialization", "jacob", "gadget", "ysoserial", "upload",
            "rce", "remote code", "exec", "php", "jsp", "asp", "ssti",
            "template", "jinja", "freemarker", "velocity"
        ],
        AttackCategory.ACTIVE_DIRECTORY: [
            "active directory", "ad", "kerberos", "ntlm", "ldap",
            "silver ticket", "golden ticket", "diamond ticket", " DCSync",
            "dcsync", "pass-the-hash", "pass-the-ticket", "ptt",
            "over-pass-the-hash", "asktgt", "kerberoasting", "asrep",
            "bloodhound", "sharphound", "responder", "mitm6", "ntlmrelay"
        ],
        AttackCategory.LINUX_PRIVESC: [
            "linux", "ubuntu", "debian", "centos", "fedora", "unix",
            "cron", "sudo", "suid", "sgid", "capabilities",
            "ld_preload", "environ", "nfs", "sudoedit", "doas"
        ],
        AttackCategory.WINDOWS_PRIVESC: [
            "windows", "win32", "win64", "nt", "mimikatz", "lsass",
            "sam", "seimpersonate", "sebackupprivilege", "selogin",
            "rottenpotato", "badpotato", "printspoofer", "dll hijack",
            "dll hijacking", "uac", "bypassuac", "令牌"
        ],
        AttackCategory.CLOUD_EXPLOITATION: [
            "aws", "amazon", "azure", "gcp", "google cloud", "s3", "iam",
            "ec2", "lambda", "container", "orchestrator"
        ],
        AttackCategory.DOCKER_ESCAPE: [
            "docker", "container", "cgroups", "namespaces", "crictl",
            "containerd", "podman", "docker.sock", "dockersh"
        ],
        AttackCategory.KUBERNETES_ATTACK: [
            "kubernetes", "k8s", "kubectl", "helm", "istio",
            "service mesh", "pod", "ingress", "kubelet", "kubeconfig"
        ],
        AttackCategory.API_EXPLOITATION: [
            "api", "rest", "graphql", "endpoint", "jwt", "oauth",
            "authentication", "authorization", "bearer", "token"
        ],
        AttackCategory.LATERAL_MOVEMENT: [
            "lateral", "pivot", "winrm", "smb", "wmi", " psecec",
            "at", "schtasks", "scheduler", "wmi", "dcom"
        ]
    }
    
    # Tool to phase mapping
    TOOL_PHASE_MAPPING = {
        ToolName.NMAP: StepType.ENUMERATION,
        ToolName.GOBUSTER: StepType.ENUMERATION,
        ToolName.FFUF: StepType.ENUMERATION,
        ToolName.SQLMAP: StepType.EXPLOITATION,
        ToolName.LINPEAS: StepType.PRIVILEGE_ESCALATION,
        ToolName.WINPEAS: StepType.PRIVILEGE_ESCALATION,
        ToolName.BLOODHOUND: StepType.ENUMERATION,
        ToolName.CRACKMAPEXEC: StepType.LATERAL_MOVEMENT,
        ToolName.SMBLIENT: StepType.LATERAL_MOVEMENT,
        ToolName.ENUM4LINUX: StepType.ENUMERATION,
        ToolName.MIMIKATZ: StepType.POST_EXPLOITATION,
        ToolName.KERBEROAST: StepType.EXPLOITATION,
        ToolName.RESPONDER: StepType.ENUMERATION,
    }
    
    # Tool to category mapping  
    TOOL_CATEGORY_MAPPING = {
        ToolName.NMAP: [AttackCategory.WEB_EXPLOITATION, AttackCategory.ACTIVE_DIRECTORY],
        ToolName.GOBUSTER: [AttackCategory.WEB_EXPLOITATION],
        ToolName.FFUF: [AttackCategory.WEB_EXPLOITATION],
        ToolName.SQLMAP: [AttackCategory.WEB_EXPLOITATION],
        ToolName.LINPEAS: [AttackCategory.LINUX_PRIVESC],
        ToolName.WINPEAS: [AttackCategory.WINDOWS_PRIVESC],
        ToolName.BLOODHOUND: [AttackCategory.ACTIVE_DIRECTORY],
        ToolName.CRACKMAPEXEC: [AttackCategory.ACTIVE_DIRECTORY, AttackCategory.LATERAL_MOVEMENT],
        ToolName.LDAPSEARCH: [AttackCategory.ACTIVE_DIRECTORY],
        ToolName.KERBEROAST: [AttackCategory.ACTIVE_DIRECTORY],
    }
    
    def classify_phase(self, text: str) -> StepType:
        """
        Classify step type from text.
        
        Args:
            text: Step text
            
        Returns:
            Classified step type
        """
        text_lower = text.lower()
        
        # Check each phase
        best_match = StepType.RECON
        best_count = 0
        
        for phase, keywords in self.PHASE_KEYWORDS.items():
            count = sum(1 for kw in keywords if kw in text_lower)
            if count > best_count:
                best_count = count
                best_match = phase
        
        return best_match
    
    def classify_category(self, text: str) -> Optional[AttackCategory]:
        """
        Classify attack category from text.
        
        Args:
            text: Content text
            
        Returns:
            Classified category
        """
        text_lower = text.lower()
        
        # Check each category
        best_match: Optional[AttackCategory] = None
        best_count = 0
        
        for category, keywords in self.CATEGORY_KEYWORDS.items():
            count = sum(1 for kw in keywords if kw in text_lower)
            if count > best_count:
                best_count = count
                best_match = category
        
        return best_match
    
    def get_tool_phase(self, tool: ToolName) -> StepType:
        """Get phase for tool."""
        return self.TOOL_PHASE_MAPPING.get(tool, StepType.ENUMERATION)
    
    def get_tool_categories(self, tool: ToolName) -> list[AttackCategory]:
        """Get categories for tool."""
        return self.TOOL_CATEGORY_MAPPING.get(tool, [])
    
    def get_attack_chain_order(self, events: list) -> list[StepType]:
        """
        Get expected attack chain order.
        
        Args:
            events: List of attack events
            
        Returns:
            List of step types in order
        """
        seen = set()
        order = []
        
        for event in events:
            step_type = event.step_type if hasattr(event, 'step_type') else event.get('step_type')
            if step_type and step_type not in seen:
                seen.add(step_type)
                order.append(step_type)
        
        # Add missing standard phases
        standard_order = [
            StepType.RECON,
            StepType.ENUMERATION,
            StepType.EXPLOITATION,
            StepType.PRIVILEGE_ESCALATION,
            StepType.LATERAL_MOVEMENT,
            StepType.PERSISTENCE,
            StepType.DATA_EXFILTRATION,
            StepType.POST_EXPLOITATION,
        ]
        
        for phase in standard_order:
            if phase not in order:
                order.append(phase)
        
        return order
    
    def validate_attack_chain(self, phases: list[StepType]) -> bool:
        """
        Validate attack chain makes logical sense.
        
        Args:
            phases: List of phases
            
        Returns:
            True if valid
        """
        if not phases:
            return False
        
        # Check for required phases
        has_enum = StepType.ENUMERATION in phases or StepType.RECON in phases
        has_exploit = StepType.EXPLOITATION in phases or StepType.PRIVILEGE_ESCALATION in phases
        
        if not (has_enum and has_exploit):
            return False
        
        # Check order - enumeration should come before exploitation
        try:
            enum_idx = phases.index(StepType.ENUMERATION)
            exploit_idx = phases.index(StepType.EXPLOITATION)
            if exploit_idx < enum_idx:
                return False
        except ValueError:
            pass
        
        return True