"""Web content collectors for cybersecurity dataset generation."""

from .base import BaseCollector, CollectorConfig
from .config import (
    ScrapingConfig,
    SourceConfig,
    HackTheBoxConfig,
    VulnHubConfig,
    PortSwiggerConfig,
    OWASPConfig,
    GitHubConfig,
    YouTubeConfig
)
from .research_engine import DeepResearchEngine, ResearchQueryBuilder
from .hackthebox import HackTheBoxCollector, SearchResultParser
from .vulnhub import VulnHubCollector, VulnHubWriteupParser
from .github import GitHubCollector, GitHubSearchParser
from .portswigger import PortSwiggerCollector, LabParser
from .youtube import YouTubeCollector, TranscriptParser

__all__ = [
    # Base
    "BaseCollector",
    "CollectorConfig",
    
    # Configs
    "ScrapingConfig",
    "SourceConfig",
    "HackTheBoxConfig",
    "VulnHubConfig", 
    "PortSwiggerConfig",
    "OWASPConfig",
    "GitHubConfig",
    "YouTubeConfig",
    
    # Collectors
    "DeepResearchEngine",
    "ResearchQueryBuilder",
    "HackTheBoxCollector",
    "VulnHubCollector",
    "GitHubCollector",
    "PortSwiggerCollector",
    "YouTubeCollector",
    
    # Parsers
    "SearchResultParser",
    "VulnHubWriteupParser",
    "GitHubSearchParser",
    "LabParser",
    "TranscriptParser",
]