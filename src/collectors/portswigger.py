"""PortSwigger Web Security Academy collector."""

import asyncio
import logging
import re
from typing import Any, AsyncGenerator, Optional
from urllib.parse import urljoin

import aiohttp
from bs4 import BeautifulSoup

from ..models import ScrapedContent
from .base import BaseCollector, CollectorConfig
from .config import PortSwiggerConfig

logger = logging.getLogger(__name__)


class PortSwiggerCollector(BaseCollector):
    """
    Collector for PortSwigger Web Security Academy content.
    
    Collects:
    - Academy labs
    - Blog posts
    - Web security guides
    """
    
    def __init__(self, config: PortSwiggerConfig = PortSwiggerConfig()):
        super().__init__(CollectorConfig())
        self.config_ps = config
        self.base_url = config.base_url
        
    def get_source_name(self) -> str:
        return "portswigger"
    
    def is_enabled(self) -> bool:
        return self.config_ps.enabled
    
    async def collect(
        self, 
        category: str = "academy",
        limit: int = 100
    ) -> AsyncGenerator[ScrapedContent, None]:
        """
        Collect PortSwigger content.
        
        Args:
            category: Category (academy, blog)
            limit: Maximum items
            
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
        urls = []
        
        if category == "academy":
            urls = await self._discover_academy_labs(limit)
        elif category == "blog":
            urls = await self._discover_blog_posts(limit)
        
        return urls
    
    async def _discover_academy_labs(self, limit: int) -> list[str]:
        """Discover academy lab URLs."""
        urls = []
        
        categories = [
            "sql-injection",
            "xss", 
            "authentication",
            "web-shell",
            "server-side-request-forgery",
            "server-side-template-injection",
            "XXE",
            "broken-access-control",
            "deserialization"
        ]
        
        for cat in categories:
            lab_url = f"{self.base_url}/web-security/{cat}"
            
            try:
                async with self.session.get(lab_url) as response:
                    if response.status == 200:
                        html = await response.text()
                        soup = BeautifulSoup(html, "lxml")
                        
                        # Find lab links
                        for link in soup.find_all("a", href=re.compile(rf"/web-security/{cat}/")):
                            href = link.get("href", "")
                            if href:
                                full_url = urljoin(self.base_url, href)
                                if full_url not in urls:
                                    urls.append(full_url)
                                    
            except Exception as e:
                logger.debug(f"Failed to discover {cat}: {e}")
            
            if len(urls) >= limit:
                break
        
        return urls[:limit]
    
    async def _discover_blog_posts(self, limit: int) -> list[str]:
        """Discover blog post URLs."""
        urls = []
        
        blog_url = f"{self.base_url}/blog"
        
        try:
            async with self.session.get(blog_url) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, "lxml")
                    
                    for link in soup.find_all("a", href=re.compile(r"/blog/")):
                        href = link.get("href", "")
                        if href and "/blog/" in href:
                            full_url = urljoin(self.base_url, href)
                            if full_url not in urls:
                                urls.append(full_url)
                                
        except Exception as e:
            logger.warning(f"Failed to discover blog posts: {e}")
        
        return urls[:limit]
    
    async def _collect_single(self, url: str) -> Optional[ScrapedContent]:
        """Collect single page."""
        response = await self._fetch_with_retry(url)
        if not response:
            return None
        
        html = await response.text()
        soup = BeautifulSoup(html, "lxml")
        
        # Remove unwanted elements
        for unwanted in soup(["script", "style", "nav", "footer", "header", "aside"]):
            unwanted.decompose()
        
        # Find main content
        content_div = (
            soup.find("article") or
            soup.find("div", class_=re.compile(r"content|article|post")) or
            soup.find("main")
        )
        
        if content_div:
            content = content_div.get_text(separator="\n", strip=True)
        else:
            content = soup.get_text(separator="\n", strip=True)
        
        # Extract title
        title = ""
        title_elem = soup.find("h1")
        if title_elem:
            title = title_elem.get_text(strip=True)
        
        return ScrapedContent(
            url=url,
            content_type="markdown",
            content=content,
            title=title,
            source="portswigger",
            raw_html=html[:10000]
        )


class LabParser:
    """Parse PortSwigger lab content."""
    
    @classmethod
    def extract_solution(cls, content: str) -> dict:
        """Extract solution steps from lab."""
        result = {
            "steps": [],
            "tools": [],
            "commands": [],
            "vulnerability": None
        }
        
        # Extract vulnerability
        vuln_match = re.search(r"(SQL injection|XSS|SSRF|XXE|SSTI)", content, re.IGNORECASE)
        if vuln_match:
            result["vulnerability"] = vuln_match.group(1)
        
        # Extract commands
        cmd_patterns = [
            r"curl\s+[^\n]+",
            r"sqlmap\s+[^\n]+",
            r"python\s+[^\n]+",
        ]
        
        for pattern in cmd_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            result["commands"].extend(matches)
        
        return result