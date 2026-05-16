"""HackTheBox collector for walkthroughs and challenges."""

import asyncio
import hashlib
import json
import logging
import re
from datetime import datetime
from typing import Any, AsyncGenerator, Optional
from urllib.parse import urljoin

import aiohttp
from bs4 import BeautifulSoup
from pydantic import BaseModel

from ..models import ScrapedContent
from .base import BaseCollector, CollectorConfig
from .config import HackTheBoxConfig

logger = logging.getLogger(__name__)


class HackTheBoxCollector(BaseCollector):
    """
    Collector for HackTheBox content.
    
    Collects:
    - Machine writeups
    - Challenge walkthroughs
    - User guides
    """
    
    def __init__(self, config: HackTheBoxConfig = HackTheBoxConfig()):
        super().__init__(CollectorConfig())
        self.config_htb = config
        self.base_url = config.base_url
        
    def get_source_name(self) -> str:
        return "hackthebox"
    
    def is_enabled(self) -> bool:
        return self.config_htb.enabled
    
    async def collect(
        self, 
        category: str = "writeups",
        limit: int = 100
    ) -> AsyncGenerator[ScrapedContent, None]:
        """
        Collect HackTheBox content.
        
        Args:
            category: Category to collect (writeups, challenge, user)
            limit: Maximum items to collect
            
        Yields:
            Scraped content
        """
        urls = await self._discover_urls(category, limit)
        
        async for content in self._collect_parallel(urls, self.config.max_workers):
            yield content
    
    async def _discover_urls(self, category: str, limit: int) -> list[str]:
        """Discover content URLs."""
        urls = []
        
        # Discover from API or pages
        if category == "writeups":
            urls = await self._discover_writeups(limit)
        elif category == "challenge":
            urls = await self._discover_challenges(limit)
        elif category == "user":
            urls = await self._discover_users(limit)
        
        return urls
    
    async def _discover_writeups(self, limit: int) -> list[str]:
        """Discover machine writeup URLs."""
        urls = []
        
        # Try profile page for user writeups
        profile_url = f"{self.base_url}/profile/machines/writeups"
        
        try:
            async with self.session.get(profile_url) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, "lxml")
                    
                    # Find writeup links
                    for link in soup.find_all("a", href=re.compile(r"/writeup/")):
                        href = link.get("href", "")
                        if href and "/writeup/" in href:
                            full_url = urljoin(self.base_url, href)
                            if full_url not in urls:
                                urls.append(full_url)
                                
        except Exception as e:
            logger.warning(f"Failed to discover writeups: {e}")
        
        return urls[:limit]
    
    async def _discover_challenges(self, limit: int) -> list[str]:
        """Discover challenge URLs."""
        urls = []
        
        # Challenge list page
        challenges_url = f"{self.base_url}/challenges"
        
        try:
            async with self.session.get(challenges_url) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, "lxml")
                    
                    for link in soup.find_all("a", href=re.compile(r"/challenge/")):
                        href = link.get("href", "")
                        if href:
                            full_url = urljoin(self.base_url, href)
                            if full_url not in urls:
                                urls.append(full_url)
                                
        except Exception as e:
            logger.warning(f"Failed to discover challenges: {e}")
        
        return urls[:limit]
    
    async def _discover_users(self, limit: int) -> list[str]:
        """Discover user profile URLs with public writeups."""
        urls = []
        
        # Search for users with writeups
        search_url = f"{self.base_url}/search"
        
        try:
            async with self.session.get(search_url) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, "lxml")
                    
                    for link in soup.find_all("a", href=re.compile(r"/profile/")):
                        href = link.get("href", "")
                        if href and not any(x in href for x in ["login", "register"]):
                            full_url = urljoin(self.base_url, href)
                            if full_url not in urls:
                                urls.append(full_url)
                                
        except Exception as e:
            logger.warning(f"Failed to discover users: {e}")
        
        return urls[:limit]
    
    async def _collect_single(self, url: str) -> Optional[ScrapedContent]:
        """Collect single writeup."""
        response = await self._fetch_with_retry(url)
        if not response:
            return None
        
        html = await response.text()
        
        # Extract content
        soup = BeautifulSoup(html, "lxml")
        
        # Remove scripts and styles
        for unwanted in soup(["script", "style", "nav", "header", "footer"]):
            unwanted.decompose()
        
        # Find main content
        content_div = (
            soup.find("div", class_=re.compile(r"content|article|writeup")) or
            soup.find("article") or
            soup.find("main")
        )
        
        if content_div:
            content = content_div.get_text(separator="\n", strip=True)
        else:
            content = soup.get_text(separator="\n", strip=True)
        
        # Extract title
        title = ""
        title_elem = soup.find("h1") or soup.find("title")
        if title_elem:
            title = title_elem.get_text(strip=True)
        
        return ScrapedContent(
            url=url,
            content_type="markdown",
            content=content,
            title=title,
            source="hackthebox",
            raw_html=html[:10000] if len(html) > 10000 else html
        )


class SearchResultParser:
    """Parse search results into walkthroughs."""
    
    # Common command patterns
    COMMAND_PATTERNS = [
        r"nmap\s+-[^-]",  # nmap commands
        r"gobuster\s+",   # gobuster
        r"ffuf\s+",       # ffuf
        r"sqlmap\s+",     # sqlmap
        r"python\s+-m\s+", # python module
        r"\$.*\.py",      # python script
        r"curl\s+",       # curl
        r"wget\s+",       # wget
        r"ssh\s+",        # ssh
        r"hydra\s+",      # hydra
    ]
    
    @classmethod
    def extract_commands(cls, content: str) -> list[str]:
        """Extract commands from content."""
        commands = []
        for line in content.split("\n"):
            line = line.strip()
            for pattern in cls.COMMAND_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    commands.append(line)
                    break
        return commands
    
    @classmethod
    def identify_attack_phases(cls, content: str) -> list[str]:
        """Identify attack phases from content."""
        phases = []
        content_lower = content.lower()
        
        phase_keywords = {
            "enumeration": ["enum", "scan", "nmap", "discovery", "gobuster", "ffuf"],
            "exploitation": ["exploit", "payload", "shell", "rce", "sqli", "inject"],
            "privesc": ["privesc", "privilege", "escalat", "sudo", "suid"],
            "persistence": ["persist", "backdoor", "cron", "service"],
            "lateral_movement": ["lateral", "pivot", "smb", "winexe", "psexec"],
        }
        
        for phase, keywords in phase_keywords.items():
            if any(kw in content_lower for kw in keywords):
                phases.append(phase)
        
        return phases