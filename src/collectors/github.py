"""GitHub collector for offensive security repositories."""

import asyncio
import hashlib
import json
import logging
import re
from datetime import datetime
from typing import Any, AsyncGenerator, Optional

import aiohttp
from bs4 import BeautifulSoup

from ..models import ScrapedContent
from .base import BaseCollector, CollectorConfig
from .config import GitHubConfig

logger = logging.getLogger(__name__)


class GitHubCollector(BaseCollector):
    """
    GitHub collector for offensive security repos.
    
    Collects from:
    - Pentesting tool repositories
    - Exploit code
    - Privilege escalation scripts
    - Red team tools
    """
    
    def __init__(self, config: GitHubConfig = GitHubConfig()):
        super().__init__(CollectorConfig())
        self.config_gh = config
        self.api_base = config.base_url
        self.search_keywords = config.search_keywords
        
        # Add GitHub token if provided
        if config.search_keywords:
            self.session.headers["Authorization"] = f"token {config.search_keywords}"
        
    def get_source_name(self) -> str:
        return "github"
    
    def is_enabled(self) -> bool:
        return self.config_gh.enabled
    
    async def collect(
        self, 
        keyword: Optional[str] = None,
        limit: int = 100
    ) -> AsyncGenerator[ScrapedContent, None]:
        """
        Collect GitHub repositories.
        
        Args:
            keyword: Search keyword
            limit: Maximum items
            
        Yields:
            Scraped content
        """
        repos = await self._search_repos(keyword or "pentest", limit)
        
        for repo in repos:
            content = await self._collect_repo(repo)
            if content:
                yield content
    
    async def _search_repos(self, keyword: str, limit: int) -> list[dict]:
        """Search GitHub repositories."""
        repos = []
        
        # Use GitHub Search API
        search_url = f"{self.api_base}/search/repositories"
        params = {
            "q": f"{keyword} language:python",
            "sort": "stars",
            "order": "desc",
            "per_page": min(100, limit)
        }
        
        try:
            response = await self._fetch_with_retry(search_url, "GET")
            if response:
                data = await response.json()
                repos = data.get("items", [])[:limit]
                
        except Exception as e:
            logger.warning(f"GitHub search failed: {e}")
        
        return repos
    
    async def _collect_repo(self, repo: dict) -> Optional[ScrapedContent]:
        """Collect repository README and code."""
        repo_url = repo.get("html_url", "")
        if not repo_url:
            return None
        
        # Get README
        readme_url = f"{repo_url}/blob/master/README.md"
        readme_raw = f"{repo_url}/raw/master/README.md"
        
        content_parts = []
        content_parts.append(f"# {repo.get('full_name', '')}")
        content_parts.append(repo.get("description", ""))
        
        # Try to fetch README
        try:
            response = await self._fetch_with_retry(readme_raw)
            if response and response.status == 200:
                readme_content = await response.text()
                content_parts.append("\n## README\n")
                content_parts.append(readme_content[:5000])
        except Exception:
            pass
        
        # Get file listing
        try:
            tree_url = f"{repo.get('url', '')}/git/trees/main?recursive=1"
            response = await self._fetch_with_retry(tree_url)
            if response and response.status == 200:
                tree_data = await response.json()
                tree = tree_data.get("tree", [])
                
                # Get relevant files
                relevant_files = []
                for item in tree[:50]:  # Limit to first 50 files
                    path = item.get("path", "")
                    if any(keyword in path.lower() for keyword in ["exploit", "privesc", "scan", "enum", "attack"]):
                        relevant_files.append(path)
                
                content_parts.append("\n## Files\n")
                content_parts.append("\n".join(f"- {f}" for f in relevant_files[:20]))
                
        except Exception as e:
            logger.debug(f"Failed to get repo tree: {e}")
        
        full_content = "\n".join(content_parts)
        
        return ScrapedContent(
            url=repo_url,
            content_type="markdown",
            content=full_content,
            title=repo.get("full_name", ""),
            source="github"
        )


class GitHubSearchParser:
    """Parse GitHub search results."""
    
    @classmethod
    def extract_readme(cls, readme_html: str) -> str:
        """Extract and clean README content."""
        soup = BeautifulSoup(readme_html, "lxml")
        
        # Remove code blocks that are too long
        for pre in soup.find_all("pre"):
            code = pre.get_text()
            if len(code) > 2000:
                code = code[:2000] + "\n... [truncated]"
                pre.clear()
                pre.string = code
        
        return soup.get_text(separator="\n", strip=True)
    
    @classmethod
    def classify_repo(cls, repo: dict) -> list[str]:
        """Classify repository by attack category."""
        categories = []
        
        topics = repo.get("topics", [])
        name = repo.get("name", "").lower()
        description = repo.get("description", "").lower()
        full_text = f"{name} {description}"
        
        if any(kw in full_text for kw in ["ad", "active directory", "kerberos", "ldap"]):
            categories.append("active_directory")
        if any(kw in full_text for kw in ["linux", "unix", "privesc"]):
            categories.append("linux_privesc")
        if any(kw in full_text for kw in ["windows", "win", "ntlm"]):
            categories.append("windows_privesc")
        if any(kw in full_text for kw in ["web", "http", "sql", "xss", "ssti"]):
            categories.append("web_exploitation")
        if any(kw in full_text for kw in ["cloud", "aws", "azure", "gcp"]):
            categories.append("cloud_exploitation")
        if any(kw in full_text for kw in ["docker", "container"]):
            categories.append("docker_escape")
        if any(kw in full_text for kw in ["api", "rest", "graphql"]):
            categories.append("api_exploitation")
        
        return categories or ["general"]