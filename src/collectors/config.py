"""Configuration model for scraping."""

from typing import Optional
from pydantic import BaseModel, Field


class ScrapingConfig(BaseModel):
    """Configuration for web scraping."""
    max_workers: int = Field(default=10, ge=1, le=50)
    request_timeout: int = Field(default=30, ge=5, le=120)
    retry_attempts: int = Field(default=3, ge=0, le=10)
    retry_delay: int = Field(default=5, ge=1, le=60)
    rate_limit: float = Field(default=2.0, ge=0.1, le=20)
    user_agent: str = Field(default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
    obey_robots_txt: bool = Field(default=True)
    max_depth: int = Field(default=3, ge=1, le=10)
    download_delay: float = Field(default=1.0, ge=0, le=10)
    
    # GitHub specific
    github_token: Optional[str] = None
    
    # YouTube specific
    youtube_api_key: Optional[str] = None


class SourceConfig(BaseModel):
    """Configuration for a specific source."""
    enabled: bool = True
    base_url: str
    categories: list[str] = Field(default_factory=list)
    rate_limit: float = Field(default=5.0)
    max_items: int = Field(default=100)
    priority: int = Field(default=0)


class HackTheBoxConfig(SourceConfig):
    """HackTheBox source configuration."""
    base_url: str = "https://www.hackthebox.com"
    categories: list[str] = ["writeups", "challenge", "user"]
    enabled: bool = True


class VulnHubConfig(SourceConfig):
    """VulnHub source configuration."""
    base_url: str = "https://www.vulnhub.com"
    enabled: bool = True


class PortSwiggerConfig(SourceConfig):
    """PortSwigger source configuration."""
    base_url: str = "https://portswigger.net"
    categories: list[str] = ["web-security", "blog"]
    enabled: bool = True


class OWASPConfig(SourceConfig):
    """OWASP source configuration."""
    base_url: str = "https://owasp.org"
    categories: list[str] = ["www-project"]
    enabled: bool = True


class GitHubConfig(SourceConfig):
    """GitHub source configuration."""
    base_url: str = "https://api.github.com"
    search_keywords: list[str] = Field(default_factory=lambda: ["pentest", "exploit", "privesc"])
    enabled: bool = True


class YouTubeConfig(SourceConfig):
    """YouTube source configuration."""
    channels: list[str] = Field(default_factory=lambda: ["IppSec", "LiveOverflow", "S3cur3Th1s"])
    use_ytdlp: bool = True
    enabled: bool = True