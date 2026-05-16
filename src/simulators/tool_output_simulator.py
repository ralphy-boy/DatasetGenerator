"""Tool output simulator for realistic terminal output."""

import hashlib
import logging
import random
import re
from datetime import datetime
from typing import Any, Optional

from ..models import ToolName

logger = logging.getLogger(__name__)


class ToolOutputSimulator:
    """
    Simulate realistic tool outputs.
    
    Generates outputs for:
    - nmap, gobuster, ffuf, sqlmap
    - hydra, crackmapexec, smbclient
    - enum4linux, impacket
    - linpeas, winpeas, bloodhound
    """
    
    def __init__(self):
        self.nmap_engine = NmapOutputEngine()
        self.gobuster_engine = GobusterOutputEngine()
        self.ffuf_engine = FfufOutputEngine()
        self.sqlmap_engine = SqlmapOutputEngine()
        self.linpeas_engine = LinpeasOutputEngine()
        self.winpeas_engine = WinpeasOutputEngine()
        self.cme_engine = CrackMapExecEngine()
        self.bloodhound_engine = BloodHoundEngine()
    
    def simulate(
        self,
        tool: ToolName,
        command: str,
        config: dict = None
    ) -> str:
        """
        Simulate tool output.
        
        Args:
            tool: Tool name
            command: Command executed
            config: Simulation config
            
        Returns:
            Simulated output
        """
        config = config or {}
        
        # Add noise/errors based on config
        add_noise = config.get("add_noise", False)
        add_errors = config.get("add_errors", False)
        
        # Generate output based on tool
        output = self._generate_output(tool, command, config)
        
        if add_noise:
            output = self._add_noise(output)
        
        if add_errors:
            output = self._add_errors(output)
        
        return output
    
    def _generate_output(
        self,
        tool: ToolName,
        command: str,
        config: dict
    ) -> str:
        """Generate output for tool."""
        handlers = {
            ToolName.NMAP: self.nmap_engine.generate,
            ToolName.GOBUSTER: self.gobuster_engine.generate,
            ToolName.FFUF: self.ffuf_engine.generate,
            ToolName.SQLMAP: self.sqlmap_engine.generate,
            ToolName.LINPEAS: self.linpeas_engine.generate,
            ToolName.WINPEAS: self.winpeas_engine.generate,
            ToolName.CRACKMAPEXEC: self.cme_engine.generate,
            ToolName.BLOODHOUND: self.bloodhound_engine.generate,
        }
        
        handler = handlers.get(tool)
        if handler:
            return handler(command, config)
        
        return self._generate_generic_output(tool, command)
    
    def _generate_generic_output(self, tool: ToolName, command: str) -> str:
        """Generate generic output for unknown tools."""
        return f"[{tool.value}] executed: {command[:100]}\n\ncompleted"


class BaseToolOutputEngine:
    """Base class for tool output engines."""
    
    def generate(self, command: str, config: dict) -> str:
        """Generate output."""
        raise NotImplementedError
    
    def _random_delay(self) -> str:
        """Generate random delay output."""
        delay = random.uniform(0.001, 2.0)
        return f"[{delay:.3f}s]"


class NmapOutputEngine(BaseToolOutputEngine):
    """Generate nmap output."""
    
    # Sample service fingerprints
    SERVICES = [
        ("22/tcp", "ssh", "OpenSSH 8.2p1 Ubuntu 4ubuntu0.2"),
        ("80/tcp", "http", "Apache httpd 2.4.41"),
        ("443/tcp", "https", "Apache httpd 2.4.41"),
        ("3306/tcp", "mysql", "MySQL 8.0.23"),
        ("5432/tcp", "postgresql", "PostgreSQL DB"),
        ("8080/tcp", "http-proxy", "Apache Tomcat"),
        ("21/tcp", "ftp", "vsftpd 3.0.3"),
        ("25/tcp", "smtp", "Postfix smtpd"),
        ("53/tcp", "domain", "Bind 9"),
        ("445/tcp", "microsoft-ds", "Samba smbd 4.x"),
    ]
    
    def generate(self, command: str, config: dict) -> str:
        """Generate nmap output."""
        # Determine scan type
        is_udp = "-sU" in command
        is_service = "-sV" in command
        is_os = "-O" in command
        
        output_lines = []
        
        # Header
        output_lines.append(f"Starting Nmap 7.92 at {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        output_lines.append(f"Nmap scan report for {config.get('target', 'target')}")
        output_lines.append("Host is up (0.0012 latency.")
        
        # Ports
        output_lines.append("PORT     STATE SERVICE")
        
        # Select random subset of services
        services = random.sample(self.SERVICES, k=random.randint(2, 5))
        
        for port, state, service in services:
            if is_service:
                output_lines.append(f"{port}  {state}  {service}")
            else:
                output_lines.append(f"{port}  {state}  {service.split()[0]}")
        
        # OS detection if requested
        if is_os:
            output_lines.append("\nOS detection:")
            output_lines.append("Linux 5.4 (Ubuntu)")
        
        # Statistics
        output_lines.append(f"\nNmap done: 1 IP address (1 host up) scanned in {random.uniform(0.5, 2.0):.2f} seconds")
        
        return "\n".join(output_lines)


class GobusterOutputEngine(BaseToolOutputEngine):
    """Generate gobuster output."""
    
    # Common web paths
    PATHS = [
        ("/admin", "Status: 200"),
        ("/api", "Status: 200"),
        ("/backup", "Status: 301"),
        ("/config", "Status: 403"),
        ("/css", "Status: 200"),
        ("/dashboard", "Status: 200"),
        ("/database", "Status: 403"),
        ("/docs", "Status: 200"),
        ("/hidden", "Status: 401"),
        ("/images", "Status: 200"),
        ("/includes", "Status: 200"),
        ("/js", "Status: 200"),
        ("/login", "Status: 200"),
        ("/phpmyadmin", "Status: 403"),
        ("/server-status", "Status: 403"),
        ("/uploads", "Status: 200"),
        ("/wp-admin", "Status: 200"),
        ("/wp-content", "Status: 200"),
    ]
    
    def generate(self, command: str, config: dict) -> str:
        """Generate gobuster output."""
        output_lines = []
        
        # Progress
        output_lines.append("Gobuster v3.1.0")
        output_lines.append('by OJ Reeves (@TheColonial) + andy (@gmail.com)')
        output_lines.append("==============================================================")
        
        # Output found paths
        output_lines.append("\nProgress: [===] 100% (1000/1000) [1000 reqs] 0s")
        output_lines.append("\n=======================================================")
        
        # Found directories
        paths = random.sample(self.PATHS, k=random.randint(5, 12))
        
        for path, status in paths:
            output_lines.append(f"Progress: {path:<40} {status}")
        
        output_lines.append("\n=======================================================")
        output_lines.append(f"Finished                      5000 requests")
        
        return "\n".join(output_lines)


class FfufOutputEngine(BaseToolOutputEngine):
    """Generate ffuf output."""
    
    HTTP_CODES = [200, 301, 302, 401, 403, 404, 500]
    
    def generate(self, command: str, config: dict) -> str:
        """Generate ffuf output."""
        status_codes = random.choices(
            self.HTTP_CODES, 
            weights=[50, 20, 10, 5, 10, 3, 2],
            k=random.randint(8, 15)
        )
        
        output_lines = []
        output_lines.append("Progress         [===============================] 100% 10000")
        output_lines.append("VHOST MODE: [Disabled]");
        output_lines.append("");
        
        # Results
        output_lines.append("Progress          STATUS      SIZE      TIME");
        output_lines.append("=========================================");
        
        for i in range(len(status_codes)):
            status = status_codes[i]
            status_str = f"HTTP {status}"
            size = random.randint(100, 50000)
            time_ms = random.randint(10, 500)
            output_lines.append(f"Progress /{i:<20} {status_str:<10} {size:<8} {time_ms}ms")
        
        output_lines.append("=========================================");
        output_lines.append(f"Progress  Done: 10000 URLs, 5000 words, 10000 bytes");
        
        return "\n".join(output_lines)


class SqlmapOutputEngine(BaseToolOutputEngine):
    """Generate sqlmap output."""
    
    # Vulnerability types
    VULNS = [
        "and AND 1=1--",
        "and AND 1=1 AND '1'='1",
        "or 1=1--",
        "' OR '1'='1",
    ]
    
    def generate(self, command: str, config: dict) -> str:
        """Generate sqlmap output."""
        output_lines = []
        
        output_lines.append("       __")
        output_lines.append("       / \\  __")
        output_lines.append("       |\\ ||");
        output_lines.append("       |_||_  ,__");
        output_lines.append("       /  \\");
        output_lines.append("sqlmap/1.6.12#stable")
        
        # Running info
        target = config.get("target", "http://target.com")
        output_lines.append("\n[11:23:45] [INFO] testing connection to target");
        output_lines.append(f"[11:23:45] [INFO] target: {target}");
        output_lines.append("[11:23:45] [INFO] testing GET parameter");
        
        # Vulnerable parameter
        output_lines.append("[11:23:46] [INFO] heuristic: testing for SQL injection");
        output_lines.append("[11:23:47] [INFO] The parameter is vulnerable");
        
        # Payload
        output_lines.append("\n[11:23:47] [INFO] testing 'MySQL >5.0.12 OR time-based");
        output_lines.append("[11:23:51] [PAYLOAD] id=1' AND SLEEP(5)--");
        
        # Results
        output_lines.append("\n[11:23:52] [INFO] extracting database");
        output_lines.append("[11:23:52] [INFO] the database management system is MySQL");
        output_lines.append("[11:23:52] [INFO] fetching database: 'webapp'");
        output_lines.append("[11:23:52] [INFO] fetching tables: 'users'");
        
        output_lines.append("\n[11:23:53] [INFO] table 'users' exported");
        output_lines.append("Database: webapp");
        output_lines.append("Table: users");
        output_lines.append("[2 columns]");
        output_lines.append("+--------+----------+");
        output_lines.append("| Column | Type     |");
        output_lines.append("+--------+----------+");
        output_lines.append("| id     | int     |");
        output_lines.append("| user   | varchar |");
        output_lines.append("| pass   | varchar |");
        output_lines.append("+--------+----------+");
        
        return "\n".join(output_lines)


class LinpeasOutputEngine(BaseToolOutputEngine):
    """Generate linpeas output."""
    
    def generate(self, command: str, config: dict) -> str:
        """Generate linpeas output."""
        output_lines = []
        
        output_lines.append("╔═════════════════════════════════════════════════════════════╗")
        output_lines.append("║     LinPEAS v3.1.1 by carlospolop (auth by github)      ║")
        output_lines.append("╚═════════════════════════════════════════════════════════════╝")
        
        # Processing info
        output_lines.append("\n[+] Information of interest");
        output_lines.append(" ═══════════════")
        output_lines.append("╔═════════════════════════════════════════════════════════════╗")
        outputLines.append("║ File System                                             ║")
        output_lines.append("╚═════════════════════════════════════════════════════════════╝")
        
        # Sudo version
        output_lines.append("\n SUDO version: 1.8.31p2");
        
        # Capabilities
        output_lines.append("\n Capabilities");
        output_lines.append("cap_chown: off");
        output_lines.append("cap_net_raw: on");
        
        # Cron jobs
        output_lines.append("\n Cron jobs");
        output_lines.append("No Cron jobs found");
        
        # Writable paths
        output_lines.append("\n[!] Writable home rpc");
        output_lines.append("drwxr-xr-x 5 user user 4096 /home/user/.local");
        
        # SUID binaries
        output_lines.append("\n[-] SUID - Privesc: false positives");
        output_lines.append("╔═════════════════════════════════════════════════════════════╗");
        output_lines.append("/usr/bin/mount (N) -> Might help you to mount some device");
        output_lines.append("/usr/bin/passwd (N) -> /usr/bin/passw ---> You can change a password");
        
        output_lines.append("\n[+] Exploitable Linux version");
        output_lines.append("╔═════════════════════════════════════════════════════════════════════╗");
        output_lines.append("[-] VULNERABLE ( CVE-2021-4034 )");
        output_lines.append("PwnKit RCE exploit");
        
        return "\n".join(output_lines)


class WinpeasOutputEngine(BaseToolOutputEngine):
    """Generate winpeas output."""
    
    def generate(self, command: str, config: dict) -> str:
        """Generate winpeas output."""
        # Similar to linpeas but for Windows
        output_lines = []
        
        output_lines.append("╔═════════════════════════════════════════════════════════════╗");
        output_lines.append("║     WinPEAS v4.0.0 by carlospolop                      ║");
        output_lines.append("╚═════════════════════════════════════════════════════════════╝");
        
        # User info
        output_lines.append("\n[*] User Information");
        output_lines.append(" ═══════════════");
        output_lines.append("User: COMPROMISED\\user");
        output_lines.append("Is in the group: Remote Desktop Users, Users");
        
        # System info
        output_lines.append("\n[*] System Information");
        output_lines.append(" ═══════════");
        output_lines.append("Hostname: COMPROMISED");
        output_lines.append("OS: Windows Server 2019 Datacenter");
        output_lines.append("Architecture: x64");
        
        # Services
        output_lines.append("\n[*] Services Information");
        output_lines.append(" ═══════════════");
        output_lines.append("Looking for Modify Service binPath, Change service config");
        
        # Vulnerabilities
        output_lines.append("\n[!] Privesc突破口");
        output_lines.append(" ═══════════════");
        output_lines.append("SeImpersonatePrivilege: Available");
        
        return "\n".join(output_lines)


class CrackMapExecEngine(BaseToolOutputEngine):
    """Generate CrackMapExec output."""
    
    def generate(self, command: str, config: dict) -> str:
        """Generate cme output."""
        output_lines = []
        
        # SMB
        if "smb" in command.lower() or "--smb" in command:
            output_lines.append("CME: 6.0.12");
            output_lines.append("SMB    10.10.10.10   445    TARGET      [*] Windows Server 2016 Standard");
            output_lines.append("SMB    10.10.10.10   445    TARGET      [-] STATUS_LOGON_FAILURE");
        
        # WinRM
        elif "winrm" in command.lower():
            output_lines.append("WINRM  10.10.10.10  5985  TARGET   [+] target.test.local");
            output_lines.append("WINRM  10.10.10.10  5985  TARGET   [+] User: user:P@ssw0rd! (Pwn3d!)");
        
        return "\n".join(output_lines)


class BloodHoundEngine(BaseToolOutputEngine):
    """Generate BloodHound output."""
    
    def generate(self, command: str, config: dict) -> str:
        """Generate bloodhound output."""
        output_lines = []
        
        output_lines.append("BloodHound v4.0.0");
        output_lines.append("[*] Starting data collection");
        output_lines.append("[*] Using domain: test.local");
        output_lines.append("[*] Connecting to LDAP");
        output_lines.append("[*] Found 50 users");
        output_lines.append("[*] Found 10 groups");
        output_lines.append("[*] Found 100 computers");
        
        # Paths to shell
        if "collect" in command.lower():
            output_lines.append("\n[+] Analysis complete");
            output_lines.append("[*] 1 path toDomain Admin found");
            output_lines.append("  DOMAIN\\Admin@CRITICAL");
            output_lines.append("  1. KRBTGT has SPN (kerberoastable)");
        
        return "\n".join(output_lines)
    
    def _add_noise(self, output: str) -> str:
        """Add noise to output."""
        # Random timing variations
        lines = output.split("\n")
        
        for i, line in enumerate(lines):
            if random.random() < 0.1:
                lines[i] += " [noise]"
        
        return "\n".join(lines)
    
    def _add_errors(self, output: str) -> str:
        """Add occasional errors."""
        lines = output.split("\n")
        
        error_positions = random.sample(range(len(lines)), k=min(2, len(lines)))
        
        for pos in error_positions:
            lines[pos] = f"ERROR: {random.choice(['timeout', 'permission denied', 'connection refused'])}"
        
        return "\n".join(lines)