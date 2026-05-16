"""VulnHub collector for virtual machine walkthroughs."""

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
from .config import VulnHubConfig

logger = logging.getLogger(__name__)


class VulnHubCollector(BaseCollector):
    """
    Collector for VulnHub content.
    
    Collects:
    - VM entry walkthroughs
    - Challenge solutions
    - Download pages
    """
    
    def __init__(self, config: VulnHubConfig = VulnHubConfig()):
        super().__init__(CollectorConfig())
        self.config_vh = config
        self.base_url = config.base_url
        
    def get_source_name(self) -> str:
        return "vulnhub"
    
    def is_enabled(self) -> bool:
        return self.config_vh.enabled
    
    async def collect(
        self, 
        category: str = "entries",
        limit: int = 100
    ) -> AsyncGenerator[ScrapedContent, None]:
        """
        Collect VulnHub content.
        
        Args:
            category: Category to collect
            limit: Maximum items to collect
            
        Yields:
            Scraped content
        """
        urls = await self._discover_urls(category, limit)
        
        async for url in urls:
            content = await self._collect_single(url)
            if content:
                yield content
    
    async def _discover_urls(self, category: str, limit: int) -> list[str]:
        """Discover content URLs."""
        if category == "entries":
            return await self._discover_entries(limit)
        return []
    
    async def _discover_entries(self, limit: int) -> list[str]:
        """Discover VM entry URLs."""
        urls = []
        
        # Main entries page with pagination
        for page in range(1, (limit // 30) + 2):
            page_url = f"{self.base_url}/browse/comments:virtualbox/listed:true/page:{page}"
            
            try:
                async with self.session.get(page_url) as response:
                    if response.status != 200:
                        break
                        
                    html = await response.text()
                    soup = BeautifulSoup(html, "lxml")
                    
                    found_count = 0
                    for link in soup.find_all("a", href=re.compile(r"/entry/")):
                        href = link.get("href", "")
                        if href and "/entry/" in href:
                            full_url = urljoin(self.base_url, href)
                            if full_url not in urls:
                                urls.append(full_url)
                                found_count += 1
                    
                    if found_count == 0:
                        break
                        
            except Exception as e:
                logger.warning(f"Failed to discover entries: {e}")
                break
        
        return urls[:limit]
    
    async def _collect_single(self, url: str) -> Optional[ScrapedContent]:
        """Collect single VM entry."""
        response = await self._fetch_with_retry(url)
        if not response:
            return None
        
        html = await response.text()
        soup = BeautifulSoup(html, "lxml")
        
        # Remove unwanted elements
        for unwanted in soup(["script", "style", "nav", "header", "footer", "aside"]):
            unwanted.decompose()
        
        # Find main content area
        content_div = (
            soup.find("div", class_=re.compile(r"content|writeup|description")) or
            soup.find("article") or
            soup.find("div", id="content")
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
        
        # Find difficulty rating
        difficulty = "unknown"
        diff_elem = soup.find("span", class_=re.compile(r"difficulty"))
        if diff_elem:
            difficulty = diff_elem.get_text(strip=True)
        
        return ScrapedContent(
            url=url,
            content_type="markdown",
            content=content,
            title=title,
            source="vulnhub",
            raw_html=html[:10000] if len(html) > 10000 else html
        )


class VulnHubWriteupParser:
    """Parse VulnHub writeup content."""
    
    @classmethod
    def extract_techniques(cls, content: str) -> list[str]:
        """Extract exploitation techniques from content."""
        techniques = []
        
        technique_patterns = {
            "SQL Injection": r"sql\s*injection|sqli",
            "XSS": r"xss|cross[-\s]site",
            "Remote Code Execution": r"rce|remote\s*code|exec",
            "Format String": r"format\s*string",
            "Buffer Overflow": r"buffer\s*overflow|bof",
            "Privilege Escalation": r"privesc|privilege\s*escal",
            "Path Traversal": r"path\s*traversal|directory\s*traversal",
            "Command Injection": r"command\s*injection",
            "Deserialization": r"deserialize|gadget",
            "SSTI": r"ssti|server[-\s]side\s*template",
        }
        
        content_lower = content.lower()
        for technique, pattern in technique_patterns.items():
            if re.search(pattern, content_lower):
                techniques.append(technique)
        
        return techniques
    
    @classmethod
    def extract_tools(cls, content: str) -> list[str]:
        """Extract tools used from content."""
        tools = []
        
        tool_patterns = {
            "nmap": r"\bnmap\b",
            "gobuster": r"\bgobuster\b",
            "ffuf": r"\bffuf\b",
            "sqlmap": r"\bsqlmap\b",
            "hydra": r"\bhydra\b",
            "nikto": r"\bnikto\b",
            "dirb": r"\bdirb\b",
            "wpscan": r"\bwpscan\b",
            "wireshark": r"\bwireshark\b",
            "Burp Suite": r"burp[\s_-]?suite",
            "Metasploit": r"\bmetasploit\b",
        }
        
        content_lower = content.lower()
        for tool, pattern in tool_patterns.items():
            if re.search(pattern, content_lower):
                tools.append(tool)
        
        return tools