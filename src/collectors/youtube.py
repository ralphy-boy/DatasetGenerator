"""YouTube transcript collector using yt-dlp."""

import asyncio
import hashlib
import json
import logging
import os
import re
from datetime import datetime
from typing import Any, AsyncGenerator, Optional
from pathlib import Path

import aiohttp

from ..models import ScrapedContent

logger = logging.getLogger(__name__)

# Try to import yt-dlp
try:
    import yt_dlp
    YTDL_AVAILABLE = True
except ImportError:
    YTDL_AVAILABLE = False
    logger.warning("yt-dlp not available, YouTube collection disabled")


class YouTubeCollector:
    """
    Collector for YouTube video transcripts.
    
    Collects from:
    - IppSec
    - LiveOverflow
    - Various pentesting channels
    """
    
    def __init__(self, channels: Optional[list[str]] = None):
        self.channels = channels or ["IppSec", "LiveOverflow", "S3cur3Th1s"]
        self.base_url = "https://www.youtube.com"
        
    def get_source_name(self) -> str:
        return "youtube"
    
    def is_enabled(self) -> bool:
        return YTDL_AVAILABLE
    
    async def collect(
        self, 
        channel: Optional[str] = None,
        limit: int = 50,
        max_duration: int = 1800  # 30 minutes max
    ) -> AsyncGenerator[ScrapedContent, None]:
        """
        Collect YouTube video transcripts.
        
        Args:
            channel: Specific channel (if None, uses all)
            limit: Maximum videos to collect
            max_duration: Maximum video duration in seconds
            
        Yields:
            Scraped content
        """
        channels = [channel] if channel else self.channels
        
        for ch in channels:
            videos = await self._get_channel_videos(ch, limit)
            
            for video in videos[:limit]:
                if video.get("duration", 0) <= max_duration:
                    content = await self._collect_transcript(video)
                    if content:
                        yield content
                    
                    await asyncio.sleep(1)
    
    async def _get_channel_videos(self, channel: str, limit: int) -> list[dict]:
        """Get channel video list."""
        if not YTDL_AVAILABLE:
            return []
        
        videos = []
        
        ydl_opts = {
            "quiet": True,
            "extract_flat": True,
            "ignoreerrors": True,
            "no_download": True,
        }
        
        channel_url = f"https://www.youtube.com/@{channel}/videos"
        
        try:
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(channel_url, download=False)
                
                if info and "entries" in info:
                    for entry in info["entries"][:limit]:
                        videos.append({
                            "id": entry.get("id", ""),
                            "title": entry.get("title", ""),
                            "url": f"https://www.youtube.com/watch?v={entry.get('id')}",
                            "duration": entry.get("duration", 0),
                            "upload_date": entry.get("upload_date", ""),
                            "description": entry.get("description", ""),
                        })
                        
        except Exception as e:
            logger.warning(f"Failed to get videos from {channel}: {e}")
        
        return videos
    
    async def _collect_transcript(self, video: dict) -> Optional[ScrapedContent]:
        """Collect video transcript."""
        if not YTDL_AVAILABLE:
            return None
        
        video_url = video.get("url", "")
        if not video_url:
            return None
        
        ydl_opts = {
            "quiet": True,
            "skip_download": True,
            "writeinfojson": False,
            "gettitle": True,
            "getdescription": True,
        }
        
        try:
            # First, get video info with transcript availability
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(video_url, download=False)
                
                if not info:
                    return None
                
                # Try to get transcripts
                subtitles = info.get("subtitles", {}) or info.get("automatic_captions", {})
                
                transcript_text = ""
                
                if subtitles:
                    # Try to fetch English (en) transcript
                    lang = "en"
                    if lang in subtitles:
                        # Get transcript
                        transcript_data = await self._fetch_transcript(video_url, lang)
                        if transcript_data:
                            transcript_text = transcript_data
                
                if not transcript_text:
                    # Fallback to video description
                    transcript_text = video.get("description", "")
                    if not transcript_text:
                        # Get from info
                        transcript_text = info.get("description", "")
                
                if not transcript_text or len(transcript_text) < 100:
                    return None
                
                return ScrapedContent(
                    url=video_url,
                    content_type="transcript",
                    content=transcript_text,
                    title=info.get("title", ""),
                    source="youtube"
                )
                
        except Exception as e:
            logger.debug(f"Failed to get transcript: {e}")
            return None
    
    async def _fetch_transcript(self, video_url: str, lang: str = "en") -> str:
        """Fetch transcript using yt-dlp."""
        if not YTDL_AVAILABLE:
            return ""
        
        transcript = []
        
        ydl_opts = {
            "quiet": True,
            "skip_download": True,
            "writeautomaticsub": True,
            "subtitlesformat": "srt",
        }
        
        try:
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(video_url, download=False)
                
                # Try getting subtitles/captions
                for sub_lang, sub_data in (info.get("subtitles", {}) or {}).items():
                    if sub_lang.startswith(lang):
                        # Get transcript text
                        for sub_item in sub_data:
                            if "data" in sub_item:
                                # Extract text from srt format
                                text = re.sub(r"^\d+\n[\d:,]+\n", "", sub_item["data"])
                                text = re.sub(r"\n\d+\n", "\n", text)
                                transcript.append(text.strip())
        
        except Exception as e:
            logger.debug(f"Failed to fetch transcript: {e}")
        
        return "\n".join(transcript[:5000])  # Limit transcript length


class TranscriptParser:
    """Parse YouTube transcript content."""
    
    TIMESTAMP_PATTERN = re.compile(r"\[?(\d{1,2}:\d{2}(:\d{2})?)\]?")
    
    @classmethod
    def parse_transcript(cls, transcript: str) -> list[dict]:
        """
        Parse transcript into structured format.
        
        Returns list of timestamps with text.
        """
        segments = []
        
        for line in transcript.split("\n"):
            line = line.strip()
            if not line:
                continue
            
            # Try to extract timestamp
            ts_match = cls.TIMESTAMP_PATTERN.search(line[:20])
            timestamp = ts_match.group(1) if ts_match else None
            
            # Remove timestamp from text
            text = cls.TIMESTAMP_PATTERN.sub("", line).strip()
            
            if text:
                segments.append({
                    "timestamp": timestamp,
                    "text": text
                })
        
        return segments
    
    @classmethod
    def extract_commands(cls, transcript: str) -> list[str]:
        """Extract commands from transcript."""
        commands = []
        
        # Common command patterns
        cmd_patterns = [
            r"\$[^$\n]+",
            r">[^>\n]+",
            r"#[^#\n]+",
            r"nmap\s+[^\n]+",
            r"gobuster\s+[^\n]+",
            r"curl\s+[^\n]+",
            r"python\s+[^\n]+",
        ]
        
        for pattern in cmd_patterns:
            matches = re.findall(pattern, transcript)
            commands.extend(matches)
        
        return commands
    
    @classmethod
    def extract_walkthrough_steps(cls, transcript: str) -> list[dict]:
        """Extract walkthrough steps from transcript."""
        steps = []
        
        # Find sections like "Step 1:", "Phase:", etc.
        step_markers = [
            r"step\s+(\d+)",
            r"phase\s+(\d+)",
            r"stage\s+(\d+)",
            r"(\d+)\)[\s:]+([^\n]+)",
        ]
        
        for i, segment in enumerate(transcript):
            if isinstance(segment, dict):
                text = segment.get("text", "").lower()
                for marker in step_markers:
                    if re.search(marker, text):
                        steps.append({
                            "step": i,
                            "text": segment.get("text", ""),
                            "timestamp": segment.get("timestamp")
                        })
                        break
        
        return steps