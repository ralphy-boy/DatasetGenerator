"""Base collector interface."""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Any, AsyncGenerator, Optional

import aiohttp
from pydantic import BaseModel
from tqdm import tqdm

logger = logging.getLogger(__name__)


class CollectorConfig(BaseModel):
    """Base configuration for collectors."""
    max_workers: int = 10
    request_timeout: int = 30
    retry_attempts: int = 3
    retry_delay: int = 5
    rate_limit: float = 2.0  # requests per second
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    obey_robots_txt: bool = True
    max_depth: int = 3
    download_delay: float = 1.0


class BaseCollector(ABC):
    """
    Abstract base class for web content collectors.
    
    All collectors must implement:
    - collect(): Main collection method
    - get_source_name(): Source identifier
    - is_enabled(): Whether collector is enabled
    """
    
    def __init__(self, config: CollectorConfig):
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self.items_collected: int = 0
        
    async def __aenter__(self):
        headers = {
            "User-Agent": self.config.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
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
                limit_per_host=int(self.config.rate_limit)
            )
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    @abstractmethod
    async def collect(self, **kwargs) -> AsyncGenerator[dict, None]:
        """
        Collect content from source.
        
        Yields:
            Collected content items
        """
        pass
    
    @abstractmethod
    def get_source_name(self) -> str:
        """Get source name."""
        pass
    
    @abstractmethod
    def is_enabled(self) -> bool:
        """Check if collector is enabled."""
        pass
    
    async def _fetch_with_retry(
        self, 
        url: str, 
        method: str = "GET",
        data: Optional[dict] = None,
        json: bool = False
    ) -> Optional[aiohttp.ClientResponse]:
        """
        Fetch URL with retry logic.
        
        Args:
            url: URL to fetch
            method: HTTP method
            data: Request data
            json: Use JSON request
            
        Returns:
            Response or None
        """
        for attempt in range(self.config.retry_attempts):
            try:
                if method == "GET":
                    async with self.session.get(url) as response:
                        if response.status == 200:
                            return response
                elif method == "POST":
                    if json:
                        async with self.session.post(url, json=data) as response:
                            if response.status in (200, 201):
                                return response
                    else:
                        async with self.session.post(url, data=data) as response:
                            if response.status in (200, 201):
                                return response
                            
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.debug(f"Attempt {attempt + 1} failed for {url}: {e}")
                await asyncio.sleep(self.config.retry_delay * (attempt + 1))
        
        return None
    
    async def _collect_parallel(
        self, 
        urls: list[str],
        concurrency: int = 5
    ) -> AsyncGenerator[dict, None]:
        """
        Collect from multiple URLs in parallel.
        
        Args:
            urls: URLs to collect from
            concurrency: Number of concurrent collections
            
        Yields:
            Collected items
        """
        semaphore = asyncio.Semaphore(concurrency)
        
        async def collect_one(url: str) -> Optional[dict]:
            async with semaphore:
                try:
                    return await self._collect_single(url)
                except Exception as e:
                    logger.warning(f"Failed to collect {url}: {e}")
                    return None
        
        tasks = [collect_one(url) for url in urls]
        
        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result:
                self.items_collected += 1
                yield result
    
    async def _collect_single(self, url: str) -> Optional[dict]:
        """Collect from single URL."""
        response = await self._fetch_with_retry(url)
        if response:
            return await self._parse_response(url, response)
        return None
    
    async def _parse_response(
        self, 
        url: str, 
        response: aiohttp.ClientResponse
    ) -> dict:
        """Parse response into normalized format."""
        content_type = response.headers.get("content-type", "")
        
        if "json" in content_type:
            return await response.json()
        else:
            text = await response.text()
            return {
                "url": url,
                "content": text,
                "content_type": "html"
            }
    
    def _rate_limit(self):
        """Apply rate limiting."""
        return asyncio.sleep(1.0 / self.config.rate_limit)