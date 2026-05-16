"""Deep Research Engine - Web research and intelligence gathering."""

import asyncio
import hashlib
import logging
import re
from datetime import datetime
from typing import Any, AsyncGenerator, Optional
from urllib.parse import urljoin, urlparse

import aiohttp
import httpx
import trafilatura
from bs4 import BeautifulSoup
from tqdm import tqdm

from ..models import ScrapedContent
from .base import BaseCollector
from .config import ScrapingConfig

logger = logging.getLogger(__name__)


class DeepResearchEngine:
    """
    Deep research engine for gathering cybersecurity content from multiple sources.
    
    Collects walkthroughs, tutorials, and offensive security content from:
    - HackTheBox writeups
    - VulnHub walkthroughs
    - PortSwigger Academy labs
    - OWASP guides
    - CTF writeups
    - GitHub offensive repos
    - IppSec transcripts
    - Pentesting blogs
    """

    def __init__(self, config: ScrapingConfig):
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self.discovered_urls: set = set()
        self.visited_urls: set = set()
        self.results: list[ScrapedContent] = []
        
        # Source patterns for different platforms
        self.source_patterns = {
            "hackthebox": {
                "base_url": "https://www.hackthebox.com",
                "writeups": r"https://www\.hackthebox\.com/(?:home|profile)/(?:writeups|challenge)",
                "category": "hackthebox"
            },
            "vulnhub": {
                "base_url": "https://www.vulnhub.com",
                "entries": r"https://www\.vulnhub\.com/entry/",
                "category": "vulnhub"
            },
            "portswigger": {
                "base_url": "https://portswigger.net",
                "academy": r"https://portswigger\.net/web-security/(?:lab|vulnerability)",
                "blog": r"https://portswigger\.net/blog",
                "category": "portswigger"
            },
            "owasp": {
                "base_url": "https://owasp.org",
                "guides": r"https://owasp\.org/(?:www-|www\.staging-)",
                "category": "owasp"
            },
            "ctftime": {
                "base_url": "https://ctftime.org",
                "writeups": r"https://ctftime\.org/writeup/",
                "category": "ctf"
            },
            "github": {
                "base_url": "https://github.com",
                "repos": r"https://github\.com/[^/]+/[^/]+",
                "category": "github"
            },
            "Medium": {
                "base_url": "https://medium.com",
                "posts": r"https://medium\.com/[^/]+",
                "category": "blog"
            },
            "dev": {
                "base_url": "https://dev.to",
                "posts": r"https://dev\.to/[^/]+",
                "category": "blog"
            }
        }

    async def __aenter__(self):
        headers = {
            "User-Agent": self.config.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        
        timeout = aiohttp.ClientTimeout(
            total=self.config.request_timeout,
            connect=10,
            sock_read=self.config.request_timeout
        )
        
        self.session = aiohttp.ClientSession(
            headers=headers,
            timeout=timeout,
            connector=aiohttp.TCPConnector(
                limit=self.config.max_workers,
                limit_per_host=self.config.rate_limit
            )
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def research_topic(
        self, 
        topic: str, 
        max_sources: int = 100
    ) -> list[ScrapedContent]:
        """
        Research a specific topic across all configured sources.
        
        Args:
            topic: Topic to research (e.g., "SQL injection", "privilege escalation")
            max_sources: Maximum number of sources to collect
            
        Returns:
            List of scraped content
        """
        logger.info(f"Starting deep research on topic: {topic}")
        
        # Research query
        search_queries = [
            f"{topic} pentest walkthrough",
            f"{topic} exploitation guide",
            f"{topic} hack the box",
            f"{topic} vulnhub walkthrough",
            f"{topic} penetration testing",
        ]
        
        # Collect from search engines
        for query in search_queries:
            urls = await self._search_for_urls(query, limit=20)
            for url in urls:
                if len(self.results) >= max_sources:
                    break
                try:
                    content = await self.collect_from_url(url)
                    if content:
                        self.results.append(content)
                except Exception as e:
                    logger.warning(f"Failed to collect from {url}: {e}")
            
            await asyncio.sleep(self.config.download_delay)
        
        logger.info(f"Research complete. Collected {len(self.results)} items")
        return self.results

    async def _search_for_urls(self, query: str, limit: int = 20) -> list[str]:
        """
        Search for URLs using DuckDuckGo API.
        
        Args:
            query: Search query
            limit: Maximum results
            
        Returns:
            List of URLs
        """
        urls = []
        
        # Use DuckDuckGo HTML search
        search_url = "https://html.duckduckgo.com/html/"
        data = {"q": query, "b": limit}
        
        try:
            async with self.session.post(search_url, data=data) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, "lxml")
                    
                    for result in soup.select(".result__a"):
                        url = result.get("href", "")
                        if url and url.startswith("http"):
                            urls.append(url)
                            
        except Exception as e:
            logger.warning(f"Search failed for {query}: {e}")
        
        return urls[:limit]

    async def collect_from_url(self, url: str) -> Optional[ScrapedContent]:
        """
        Collect content from a specific URL.
        
        Args:
            url: URL to collect from
            
        Returns:
            Scraped content or None
        """
        if url in self.visited_urls:
            return None
            
        self.visited_urls.add(url)
        
        # Skip non-HTML content
        parsed = urlparse(url)
        if parsed.path.endswith((".pdf", ".zip", ".tar", ".gz", ".png", ".jpg", ".jpeg")):
            return None
        
        try:
            async with self.session.get(url) as response:
                if response.status != 200:
                    return None
                    
                content_type = response.headers.get("content-type", "")
                if "text/html" not in content_type and "text/plain" not in content_type:
                    return None
                
                html = await response.text()
                
                # Extract using trafilatura for better content extraction
                content = trafilatura.extract(
                    html,
                    include_tables=True,
                    include_images=False,
                    include_links=False
                )
                
                if not content or len(content) < 500:
                    # Fallback to BeautifulSoup
                    content = self._extract_with_bs4(html)
                
                if not content or len(content) < 500:
                    return None
                
                # Determine source category
                source = self._categorize_url(url)
                
                return ScrapedContent(
                    url=url,
                    content_type="markdown" if content else "html",
                    content=content or html[:5000],
                    source=source,
                    raw_html=html[:10000] if len(html) > 10000 else html
                )
                
        except Exception as e:
            logger.debug(f"Failed to collect {url}: {e}")
            return None

    def _extract_with_bs4(self, html: str) -> str:
        """Extract content using BeautifulSoup."""
        soup = BeautifulSoup(html, "lxml")
        
        # Remove unwanted elements
        for unwanted in soup(["script", "style", "nav", "header", "footer", "aside", "iframe"]):
            unwanted.decompose()
        
        # Try to find main content areas
        content = (
            soup.find("article") or 
            soup.find("main") or 
            soup.find("div", class_=re.compile(r"content|article|post|entry")) or
            soup.find("div", id=re.compile(r"content|article|post|entry"))
        )
        
        if content:
            return content.get_text(separator="\n", strip=True)
        
        return soup.get_text(separator="\n", strip=True)

    def _categorize_url(self, url: str) -> str:
        """Categorize URL by source."""
        for name, pattern in self.source_patterns.items():
            if "base_url" in pattern:
                if pattern["base_url"] in url:
                    return pattern["category"]
        
        # Generic categorization
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        if "github" in domain:
            return "github"
        elif "medium" in domain:
            return "blog"
        elif "youtube" in domain:
            return "video"
        
        return "unknown"

    async def discover_links(
        self, 
        url: str, 
        max_depth: int = 2
    ) -> AsyncGenerator[str, None]:
        """
        Recursively discover links from a starting URL.
        
        Args:
            url: Starting URL
            max_depth: Maximum crawl depth
            
        Yields:
            URLs discovered
        """
        await self._discover_links_recursive(url, 0, max_depth)
        
        for discovered_url in self.discovered_urls:
            yield discovered_url

    async def _discover_links_recursive(
        self, 
        url: str, 
        depth: int, 
        max_depth: int
    ):
        """Recursively discover links."""
        if depth >= max_depth or url in self.visited_urls:
            return
            
        self.visited_urls.add(url)
        
        try:
            async with self.session.get(url) as response:
                if response.status != 200:
                    return
                    
                html = await response.text()
                soup = BeautifulSoup(html, "lxml")
                
                for link in soup.find_all("a", href=True):
                    href = link["href"]
                    full_url = urljoin(url, href)
                    
                    # Filter to relevant URLs
                    if self._is_relevant_url(full_url):
                        self.discovered_urls.add(full_url)
                        
                        # Recurse
                        if depth < max_depth - 1:
                            await self._discover_links_recursive(full_url, depth + 1, max_depth)
                            
        except Exception as e:
            logger.debug(f"Failed to discover links from {url}: {e}")

    def _is_relevant_url(self, url: str) -> bool:
        """Check if URL is relevant for cybersecurity content."""
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        # Keywords for relevant content
        relevant_keywords = [
            "hack", "pentest", "exploit", "vulnerability", "ctf", "walkthrough",
            "writeup", "guide", "tutorial", "lab", "challenge", "privesc",
            "privilege", "escalation", "ad", "active", "directory", "kerberos",
            "sqli", "injection", "xss", "ssrf", "ssti", "rce"
        ]
        
        return any(keyword in path for keyword in relevant_keywords)

    async def collect_from_sitemap(self, url: str) -> list[str]:
        """
        Collect URLs from sitemap.xml
        
        Args:
            url: Base URL to fetch sitemap from
            
        Returns:
            List of URLs from sitemap
        """
        urls = []
        sitemap_url = urljoin(url, "/sitemap.xml")
        
        try:
            async with self.session.get(sitemap_url) as response:
                if response.status != 200:
                    # Try common sitemap locations
                    for loc in ["/sitemap_index.xml", "/sitemap1.xml"]:
                        sitemap_url = urljoin(url, loc)
                        async with self.session.get(sitemap_url) as resp:
                            if resp.status == 200:
                                break
                    else:
                        return []
                        
                xml = await response.text()
                soup = BeautifulSoup(xml, "xml")
                
                for loc in soup.find_all("loc"):
                    url_text = loc.get_text()
                    if self._is_relevant_url(url_text):
                        urls.append(url_text)
                        
        except Exception as e:
            logger.debug(f"Failed to collect sitemap from {url}: {e}")
        
        return urls


class ResearchQueryBuilder:
    """Build research queries for different sources."""
    
    # Attack technique keywords
    ATTACK_TECHNIQUES = [
        "sql injection", "xss", "cross-site scripting", "csrf", "ssrf",
        "server-side request forgery", "ssti", "template injection",
        "deserialization", "rce", "remote code execution",
        "privilege escalation", "privesc", "linux privesc", "windows privesc",
        "active directory", "kerberoasting", "pass-the-hash", "golden ticket",
        "lateral movement", "pivot", "persistence", "backdoor",
        "docker escape", "container escape", "/kubernetes/",
        "aws exploitation", "cloud pentest", "azure exploit",
        "api exploitation", "rest api", "graphql"
    ]
    
    # Source-specific queries
    SOURCE_QUERIES = {
        "hackthebox": [
            "{technique} hackthebox walkthrough",
            "{technique} hackthebox solution",
            "htb {technique} writeup"
        ],
        "vulnhub": [
            "{technique} vulnhub walkthrough",
            "vulnhub {technique} solution"
        ],
        "portswigger": [
            "{technique} portswigger academy",
            "{technique} burp suite lab"
        ],
        "ctf": [
            "{technique} ctf writeup",
            "{technique} ctf solution"
        ],
        "github": [
            "{technique} exploit github",
            "{technique} pentest tool"
        ]
    }
    
    @classmethod
    def build_queries(
        cls, 
        technique: Optional[str] = None,
        source: Optional[str] = None,
        limit: int = 50
    ) -> list[str]:
        """
        Build research queries.
        
        Args:
            technique: Specific technique (if None, uses all)
            source: Specific source (if None, uses all)
            limit: Maximum number of queries
            
        Returns:
            List of queries
        """
        queries = []
        
        techniques = [technique] if technique else cls.ATTACK_TECHNIQUES
        
        for tech in techniques:
            if source and source in cls.SOURCE_QUERIES:
                for template in cls.SOURCE_QUERIES[source]:
                    queries.append(template.format(technique=tech))
            elif not source:
                for src, templates in cls.SOURCE_QUERIES.items():
                    for template in templates:
                        queries.append(template.format(technique=tech))
        
        return queries[:limit]
    
    @classmethod
    def get_all_techniques(cls) -> list[str]:
        """Get all attack techniques."""
        return cls.ATTACK_TECHNIQUES.copy()[:]