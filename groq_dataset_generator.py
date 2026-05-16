#!/usr/bin/env python3
"""
Cybersecurity Dataset Generator using Groq API
============================================

This script:
1. Reads hacking resources (URLs or local files)
2. Uses Groq API as LLM to generate ReAct-style trajectories  
3. Outputs JSONL format
4. Optionally uploads to HuggingFace

Usage:
    python groq_dataset_generator.py --urls "https://example.com/writeup1,https://example.com/writeup2"
    python groq_dataset_generator.py --files "/path/to/writeup1.md,/path/to/writeup2.md"
    python groq_dataset_generator.py --output /path/to/output.jsonl --upload --hf-token $HF_TOKEN

Requirements:
    pip install groq requests beautifulsoup4 trafilatura yt-dlp huggingface-hub datasets

Author: CyberAgent Dataset Generator
"""

import os
import re
import sys
import json
import logging
import hashlib
import argparse
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Optional, list, Dict, Any
from dataclasses import dataclass, field

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# =============================================================================
# DEPENDENCY CHECKS
# =============================================================================

REQUIRED_PACKAGES = [
    ('groq', 'groq'),
    ('requests', 'requests'),
    ('beautifulsoup4', 'bs4'),
    ('trafilatura', 'trafilatura'),
    ('huggingface_hub', 'huggingface_hub'),
    ('datasets', 'datasets'),
]

MISSING_PACKAGES = []
for pkg, import_name in REQUIRED_PACKAGES:
    try:
        __import__(import_name)
    except ImportError:
        MISSING_PACKAGES.append(pkg)

if MISSING_PACKAGES:
    logger.error(f"Missing packages: {MISSING_PACKAGES}")
    logger.info(f"Install with: pip install {' '.join(MISSING_PACKAGES)}")
    sys.exit(1)

# Import after check
import groq
import requests
from bs4 import BeautifulSoup
import trafilatura
from huggingface_hub import HfApi, login
from datasets import Dataset

# =============================================================================
# CONFIGURATION
# =============================================================================

# Available hacking actions for the prompt
HACKING_ACTIONS = [
    {"name": "nmap", "description": "scan ports"},
    {"name": "gobuster", "description": "directory brute-force"}, 
    {"name": "searchsploit", "description": "search exploits"},
    {"name": "sqlmap", "description": "SQL injection"},
    {"name": "hydra", "description": "password brute-force"},
    {"name": "metasploit", "description": "run Metasploit exploit"},
    {"name": "curl", "description": "make HTTP request"},
    {"name": "wget", "description": "download files"},
    {"name": "ssh", "description": "SSH connection"},
    {"name": "python", "description": "run Python script"},
    {"name": "bash", "description": "run bash command"},
    {"name": "linpeas", "description": "Linux privilege escalation enumeration"},
    {"name": "winpeas", "description": "Windows privilege escalation enumeration"},
    {"name": "bloodhound", "description": "Active Directory enumeration"},
    {"name": "kerberoast", "description": "Kerberoasting attack"},
]

# System prompt for the dataset generator agent
SYSTEM_PROMPT = """You are a dataset generator for training autonomous penetration testing agents.
Your task is to convert hacking walkthroughs into conversational trajectories in ReAct format.

CONVERSATIONAL FORMAT:
User:
You are a black-box penetration testing agent.
Available actions: {actions}
Instruction: <instruction from writeup>
Observation: <initial state>

Agent:
Thought: <why this action>
Action: <tool[parameters]>

User:
Observation: <tool output>

... (repeat until shell obtained or end of walkthrough)

REQUIREMENTS:
1. The conversation must be LONG and COMPLETE (8-20+ turns)
2. Include realistic FAILURES, RETRIES, and PIVOTS where appropriate 
3. Generate plausible "Thought" reasoning for each action
4. Include tool outputs that match what the real tool would produce
5. Cover: enumeration → exploitation → privilege escalation → persistence → exfiltration
6. Use realistic target IPs, ports, and findings from the writeup
7. Format actions as: tool[arguments] (e.g., nmap[192.168.1.10 -p- -sV])

Generate a valid JSON object with this structure:
{{
  "id": "unique_id",
  "conversations": [
    {{"role": "user", "content": "..."}},
    {{"role": "assistant", "content": "Thought: ...\\nAction: tool[...]"}},
    {{"role": "user", "content": "Observation: ..."}},
    ...
  ],
  "metadata": {{
    "source": "source_url_or_file",
    "category": "web_exploitation|linux_privesc|windows_privesc|active_directory|...",
    "success": true_or_false,
    "difficulty": "beginner|intermediate|advanced|expert"
  }}
}}

Output ONLY valid JSON, no markdown formatting.
"""

# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class AttackStep:
    """Represents a single attack step."""
    step_num: int
    command: str
    output: str
    phase: str  # enumeration, exploitation, privesc, etc.
    tool: str
    description: str
    success: bool = True
    target: str = ""

@dataclass
class GeneratedTrajectory:
    """Represents a generated trajectory."""
    id: str
    conversations: list[Dict[str, str]]
    metadata: Dict[str, Any]

# =============================================================================
# WEB FETCHER
# =============================================================================

class WebFetcher:
    """Fetch content from URLs and local files."""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def fetch_url(self, url: str, timeout: int = 30) -> Optional[str]:
        """Fetch and extract content from URL."""
        try:
            logger.info(f"Fetching: {url}")
            
            # Try trafilatura first for better extraction
            extracted = trafilatura.extract(
                url,
                include_tables=False,
                include_images=False,
                include_links=False
            )
            
            if extracted and len(extracted) > 200:
                return extracted
            
            # Fallback to BeautifulSoup
            response = self.session.get(url, timeout=timeout)
            response.raise_for_status()
            
            html = response.text
            soup = BeautifulSoup(html, 'lxml')
            
            # Remove unwanted elements
            for unwanted in soup(['script', 'style', 'nav', 'footer', 'header', 'aside']):
                unwanted.decompose()
            
            # Find main content
            content = (
                soup.find('article') or 
                soup.find('main') or
                soup.find('div', class_=re.compile(r'content|article|post|entry')) or
                soup.find('div', id=re.compile(r'content|article'))
            )
            
            if content:
                return content.get_text(separator='\n', strip=True)
            
            return soup.get_text(separator='\n', strip=True)
            
        except Exception as e:
            logger.warning(f"Failed to fetch {url}: {e}")
            return None
    
    def read_file(self, filepath: str) -> Optional[str]:
        """Read local file."""
        try:
            path = Path(filepath)
            if not path.exists():
                logger.warning(f"File not found: {filepath}")
                return None
            
            # Handle different encodings
            for encoding in ['utf-8', 'latin-1', 'cp1252']:
                try:
                    return path.read_text(encoding=encoding)
                except UnicodeDecodeError:
                    continue
            
            return None
            
        except Exception as e:
            logger.warning(f"Failed to read {filepath}: {e}")
            return None
    
    def extract_target(self, content: str) -> str:
        """Extract target IP/hostname from content."""
        # IP patterns
        ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', content)
        if ip_match:
            return ip_match.group(1)
        
        # Hostname patterns
        host_match = re.search(r'(?:target|host|vm|box)[:\s]+([a-zA-Z0-9.\-]+)', content, re.IGNORECASE)
        if host_match:
            return host_match.group(1)
        
        return "target"


# =============================================================================
# WRITEUP PARSER  
# =============================================================================

class WriteupParser:
    """Parse hacking writeups into structured steps."""
    
    # Command pattern - lines starting with $ or #, or tool invocations
    COMMAND_PATTERNS = [
        r'^\$\s*(.+)$',           # $ command
        r'^#\s*(.+)$',           # # root command
        r'^>\s*(.+)$',            # > prompt
        r'\$([a-zA-Z0-9/\-_]+)\s+[^\n]+',  # tool with path
    ]
    
    # Tool detection
    TOOL_PATTERNS = {
        'nmap': r'\bnmap\b',
        'gobuster': r'\bgobuster\b', 
        'ffuf': r'\bffuf\b',
        'sqlmap': r'\bsqlmap\b',
        'hydra': r'\bhydra\b',
        'searchsploit': r'\bsearchsploit\b',
        'curl': r'\bcurl\b',
        'wget': r'\bwget\b',
        'ssh': r'\bssh\b',
        'python': r'\bpython[23]?\b',
        'linpeas': r'\blinpeas\b',
        'winpeas': r'\bwinpeas\b',
        'bloodhound': r'\bbloodhound\b',
        'kerberoast': r'\bkerberoast\b',
        'responder': r'\bresponder\b',
        'metasploit': r'\bmetasploit\b|msfconsole',
    }
    
    def parse(self, content: str, source: str = "unknown") -> list[AttackStep]:
        """Parse writeup into structured steps."""
        steps = []
        
        if not content or len(content) < 100:
            return steps
        
        # Split into lines
        lines = content.split('\n')
        
        current_command = ""
        current_output = []
        step_num = 0
        
        for line in lines:
            line = line.rstrip()
            
            # Check if line is a command
            is_command = False
            detected_tool = None
            
            for pattern in self.COMMAND_PATTERNS:
                match = re.match(pattern, line)
                if match:
                    is_command = True
                    cmd = match.group(1).strip()
                    
                    # Detect tool
                    for tool, t_pattern in self.TOL_PATTERNS.items():
                        if re.search(t_pattern, cmd, re.IGNORECASE):
                            detected_tool = tool
                            break
                    break
            
            if is_command:
                # Save previous command/output if exists
                if current_command:
                    step = self._create_step(
                        step_num, current_command, 
                        '\n'.join(current_output),
                        detected_tool or "bash"
                    )
                    if step:
                        steps.append(step)
                        step_num += 1
                
                # Start new command
                current_command = line.lstrip('$#').strip()
                current_output = []
                
                # Detect tool if not already
                if not detected_tool:
                    for tool, t_pattern in self.TOOL_PATTERNS.items():
                        if re.search(t_pattern, current_command, re.IGNORECASE):
                            detected_tool = tool
                            break
            elif current_command and line.strip():
                # Add to output
                current_output.append(line)
        
        # Don't forget last command
        if current_command:
            step = self._create_step(
                step_num, current_command,
                '\n'.join(current_output),
                detected_tool or "bash"
            )
            if step:
                steps.append(step)
        
        # Filter to meaningful steps
        meaningful_steps = [s for s in steps if len(s.command) > 3]
        
        logger.info(f"Parsed {len(meaningful_steps)} steps from {source}")
        
        return meaningful_steps
    
    def _create_step(self, step_num: int, command: str, 
                    output: str, tool: str) -> Optional[AttackStep]:
        """Create an attack step."""
        command = command.strip()
        output = output.strip()
        
        if not command or len(command) < 3:
            return None
        
        # Classify phase
        phase = self._classify_phase(command, output)
        
        # Determine success
        success = self._is_success(command, output)
        
        # Extract target
        target = self._extract_target(command)
        
        return AttackStep(
            step_num=step_num,
            command=command,
            output=output[:500],  # Limit output length
            phase=phase,
            tool=tool,
            description=self._generate_description(command, output),
            success=success,
            target=target
        )
    
    def _classify_phase(self, command: str, output: str) -> str:
        """Classify attack phase."""
        text = f"{command} {output}".lower()
        
        if any(k in text for k in ['nmap', 'scan', 'enum', 'discover', 'gobuster', 'ffuf', 'dirb']):
            return "enumeration"
        elif any(k in text for k in ['exploit', 'inject', 'rce', 'shell', 'sqlmap', 'xss', 'sqli']):
            return "exploitation"
        elif any(k in text for k in ['privesc', 'sudo', 'suid', 'kernel', 'linpeas', 'winpeas']):
            return "privilege_escalation"
        elif any(k in text for k in ['lateral', 'pivot', 'smb', 'winrm', 'pass']):
            return "lateral_movement"
        elif any(k in text for k in ['persist', 'backdoor', 'cron', 'service']):
            return "persistence"
        elif any(k in text for k in ['dump', 'loot', 'credential', 'password', 'hash']):
            return "exfiltration"
        
        return "recon"
    
    def _is_success(self, command: str, output: str) -> bool:
        """Determine if step succeeded."""
        text = f"{command} {output}".lower()
        
        # Failure indicators
        if any(k in text for k in ['failed', 'error', 'denied', 'refused', 
                                  'not found', 'timeout', 'connection refused']):
            if 'but' not in text and 'however' not in text:
                return False
        
        return True
    
    def _extract_target(self, command: str) -> str:
        """Extract target from command."""
        # IP
        ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', command)
        if ip_match:
            return ip_match.group(1)
        
        # URL
        url_match = re.search(r'(https?://[^\s]+)', command)
        if url_match:
            return url_match.group(1)
        
        return "target"
    
    def _generate_description(self, command: str, output: str) -> str:
        """Generate step description."""
        # First line of output or command
        if output:
            first_line = output.split('\n')[0][:100]
            return first_line
        
        return command[:100]


# =============================================================================
# GROQ TRAJECTORY GENERATOR
# =============================================================================

class GroqTrajectoryGenerator:
    """Generate trajectories using Groq API."""
    
    def __init__(self, api_key: str):
        """Initialize Groq client."""
        self.client = groq.Groq(api_key=api_key)
        self.model = "llama3-70b-8192"  # Fast model with large context
    
    def generate(self, writeup_content: str, source: str) -> Optional[GeneratedTrajectory]:
        """Generate trajectory from writeup content."""
        
        # Truncate content if too long
        if len(writeup_content) > 8000:
            writeup_content = writeup_content[:8000]
        
        # Build user prompt
        actions_json = json.dumps(HACKING_ACTIONS)
        user_prompt = f"""Convert this hacking walkthrough into a ReAct-style trajectory:

{writeup_content}

---

Generate a conversational training trajectory following the format above. Include as many turns as needed to complete the walkthrough. Make it realistic with both successes and failures.
"""
        
        try:
            chat_completion = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT.format(actions=actions_json)},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.7,
                max_tokens=4000,
                response_format={"type": "json_object"}
            )
            
            response = chat_completion.choices[0].message.content
            
            # Parse JSON response
            data = json.loads(response)
            
            # Generate unique ID
            traj_id = hashlib.md5(
                f"{source}{datetime.utcnow().isoformat()}".encode()
            ).hexdigest()[:12]
            traj_id = f"hack_{traj_id}"
            
            # Ensure required fields
            if "conversations" not in data:
                data["conversations"] = []
            if "metadata" not in data:
                data["metadata"] = {}
            
            # Add source to metadata
            data["metadata"]["source"] = source
            
            return GeneratedTrajectory(
                id=data.get("id", traj_id),
                conversations=data["conversations"],
                metadata=data["metadata"]
            )
            
        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON from Groq: {e}")
            return None
        except Exception as e:
            logger.warning(f"Generation failed: {e}")
            return None
    
    def generate_from_steps(self, steps: list[AttackStep], source: str) -> Optional[GeneratedTrajectory]:
        """Generate trajectory from parsed steps."""
        
        # Convert steps to text
        steps_text = "\n\n".join([
            f"Step {s.step_num + 1}: {s.command}\nOutput: {s.output}"
            for s in steps[:15]  # Limit to 15 steps
        ])
        
        return self.generate(steps_text, source)


# =============================================================================
# HUGGINGFACE UPLOADER
# =============================================================================

class HuggingFaceUploader:
    """Upload dataset to HuggingFace."""
    
    def __init__(self, token: str):
        self.token = token
        self.api = HfApi(token=token)
    
    def upload(self, dataset: list[Dict], repo_id: str, 
               repo_type: str = "dataset") -> bool:
        """Upload dataset to HuggingFace."""
        try:
            # Create dataset object
            ds = Dataset.from_list(dataset)
            
            # Upload
            ds.push_to_hub(
                repo_id=repo_id,
                token=self.token,
                repo_type=repo_type,
                commit_message=f"Add {len(dataset)} trajectories"
            )
            
            logger.info(f"Uploaded to https://huggingface.co/{repo_id}")
            return True
            
        except Exception as e:
            logger.warning(f"Upload failed: {e}")
            return False


# =============================================================================
# MAIN PIPELINE
# =============================================================================

class DatasetGeneratorPipeline:
    """Main pipeline for dataset generation."""
    
    def __init__(self, groq_api_key: str, hf_token: Optional[str] = None):
        self.fetcher = WebFetcher()
        self.parser = WriteupParser()
        self.generator = GroqTrajectoryGenerator(groq_api_key)
        self.uploader = HuggingFaceUploader(hf_token) if hf_token else None
    
    def process_urls(self, urls: list[str], 
                   output_file: str = "trajectories.jsonl") -> list[Dict]:
        """Process URLs and generate trajectories."""
        trajectories = []
        
        for url in urls:
            logger.info(f"Processing: {url}")
            
            # Fetch content
            content = self.fetcher.fetch_url(url)
            if not content:
                logger.warning(f"Skipping {url} - fetch failed")
                continue
            
            # Generate trajectory
            trajectory = self.generator.generate(content, url)
            
            if trajectory:
                trajectories.append({
                    "id": trajectory.id,
                    "conversations": trajectory.conversations,
                    "metadata": trajectory.metadata
                })
                logger.info(f"Generated: {trajectory.id}")
            else:
                logger.warning(f"Skipping {url} - generation failed")
            
            # Rate limiting
            import time
            time.sleep(1)
        
        # Save to JSONL
        if trajectories:
            self._save_jsonl(trajectories, output_file)
        
        return trajectories
    
    def process_files(self, filepaths: list[str],
                     output_file: str = "trajectories.jsonl") -> list[Dict]:
        """Process local files and generate trajectories."""
        trajectories = []
        
        for filepath in filepaths:
            logger.info(f"Processing: {filepath}")
            
            # Read file
            content = self.fetcher.read_file(filepath)
            if not content:
                logger.warning(f"Skipping {filepath} - read failed")
                continue
            
            # Generate trajectory
            trajectory = self.generator.generate(content, filepath)
            
            if trajectory:
                trajectories.append({
                    "id": trajectory.id,
                    "conversations": trajectory.conversations,
                    "metadata": trajectory.metadata
                })
                logger.info(f"Generated: {trajectory.id}")
        
        # Save to JSONL
        if trajectories:
            self._save_jsonl(trajectories, output_file)
        
        return trajectories
    
    def _save_jsonl(self, trajectories: list[Dict], output_file: str):
        """Save trajectories to JSONL."""
        with open(output_file, 'w') as f:
            for traj in trajectories:
                f.write(json.dumps(traj, ensure_ascii=False) + '\n')
        
        logger.info(f"Saved {len(trajectories)} trajectories to {output_file}")
    
    def upload_to_hf(self, trajectories: list[Dict], repo_id: str) -> bool:
        """Upload to HuggingFace."""
        if not self.uploader:
            logger.warning("No HuggingFace token - skipping upload")
            print("\n" + "=" * 60)
            print("To upload to HuggingFace:")
            print("1. Get token from https://huggingface.co/settings/tokens")
            print("2. Run with: python script.py --hf-token $HF_TOKEN")
            print("=" * 60)
            return False
        
        return self.uploader.upload(trajectories, repo_id)


# =============================================================================
# ENTRY POINT
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Generate ReAct trajectories from hacking writeups using Groq",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process URLs
  python groq_dataset_generator.py --urls "https://example.com/htb-writeup"

  # Process local files  
  python groq_dataset_generator.py --files "/path/to/writeup.md"

  # Generate and upload
  python groq_dataset_generator.py --urls "..." --output data.jsonl --upload --repo-id my-user/dataset
        """
    )
    
    parser.add_argument('--urls', type=str, 
                      help='Comma-separated list of URLs')
    parser.add_argument('--files', type=str,
                      help='Comma-separated list of local files')
    parser.add_argument('--output', type=str, default='trajectories.jsonl',
                      help='Output JSONL file')
    parser.add_argument('--groq-key', type=str, 
                      default=os.environ.get('GROQ_API_KEY'),
                      help='Groq API key (or set GROQ_API_KEY env)')
    parser.add_argument('--hf-token', type=str,
                      default=os.environ.get('HF_TOKEN'),
                      help='HuggingFace token for upload')
    parser.add_argument('--repo-id', type=str,
                      help='HuggingFace repo ID for upload')
    parser.add_argument('--upload', action='store_true',
                      help='Upload to HuggingFace')
    parser.add_argument('--verbose', action='store_true',
                      help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate Groq key
    groq_key = args.groq_key
    if not groq_key:
        print("\n" + "=" * 60)
        print("ERROR: Groq API key required")
        print("Get free key at: https://console.groq.com/")
        print("Set with: --groq-key KEY or GROQ_API_KEY=KEY")
        print("=" * 60)
        sys.exit(1)
    
    # Parse sources
    urls = []
    files = []
    
    if args.urls:
        urls = [u.strip() for u in args.urls.split(',') if u.strip()]
    if args.files:
        files = [f.strip() for f in args.files.split(',') if f.strip()]
    
    if not urls and not files:
        parser.print_help()
        sys.exit(1)
    
    # Initialize pipeline
    pipeline = DatasetGeneratorPipeline(groq_key, args.hf_token)
    
    # Process
    trajectories = []
    
    if urls:
        logger.info(f"Processing {len(urls)} URLs...")
        trajectories.extend(pipeline.process_urls(urls, args.output))
    
    if files:
        logger.info(f"Processing {len(files)} files...")
        trajectories.extend(pipeline.process_files(files, args.output))
    
    # Summary
    print("\n" + "=" * 60)
    print(f"Generated {len(trajectories)} trajectories")
    print(f"Output: {args.output}")
    print("=" * 60)
    
    # Upload if requested
    if args.upload and trajectories:
        if not args.repo_id:
            print("ERROR: --repo-id required for upload")
            sys.exit(1)
        
        success = pipeline.upload_to_hf(trajectories, args.repo_id)
        
        if success:
            print(f"Uploaded to: https://huggingface.co/{args.repo_id}")
        else:
            print("Upload failed")
    
    # Print first trajectory as example
    if trajectories:
        print("\n" + "=" * 60)
        print("Example trajectory:")
        print("=" * 60)
        example = trajectories[0]
        for conv in example['conversations'][:4]:
            role = conv['role']
            content = conv['content'][:150]
            print(f"\n[{role.upper()}]: {content}...")


if __name__ == "__main__":
    main()