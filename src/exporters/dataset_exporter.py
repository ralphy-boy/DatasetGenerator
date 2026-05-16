"""Export pipeline for dataset export."""

import gzip
import json
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from ..models import AgentTrajectory, ExportMetadata

logger = logging.getLogger(__name__)


class DatasetExporter:
    """
    Export trajectories to various formats.
    
    Formats:
    - JSONL
    - HuggingFace datasets
    - Agent-FLAN
    - ShareGPT
    - ReAct
    """
    
    def __init__(self, output_dir: str = "/workspace/project/data/trajectories"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def export(
        self,
        trajectories: list[AgentTrajectory],
        format: str = "jsonl",
        metadata: dict = None,
        config: dict = None
    ) -> str:
        """
        Export trajectories.
        
        Args:
            trajectories: List of trajectories
            format: Export format
            metadata: Export metadata
            config: Export config
            
        Returns:
            Output file path
        """
        config = config or {}
        
        if format == "jsonl":
            return self._export_jsonl(trajectories, config)
        elif format == "huggingface":
            return self._export_huggingface(trajectories, config)
        elif format == "agent_flan":
            return self._export_agent_flan(trajectories, config)
        elif format == "sharegpt":
            return self._export_sharegpt(trajectories, config)
        elif format == "react":
            return self._export_react(trajectories, config)
        
        return self._export_jsonl(trajectories, config)
    
    def _export_jsonl(
        self,
        trajectories: list[AgentTrajectory],
        config: dict
    ) -> str:
        """Export to JSONL format."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"trajectories_{timestamp}.jsonl"
        filepath = self.output_dir / filename
        
        with open(filepath, "w") as f:
            for traj in trajectories:
                record = {
                    "id": traj.id,
                    "conversations": [
                        {"from": c.from_role.value, "value": c.value}
                        for c in traj.conversations
                    ],
                    "metadata": {
                        "difficulty": traj.difficulty.value if traj.difficulty else None,
                        "category": traj.category.value if traj.category else None,
                        "tools": [t.value for t in traj.tools_used],
                        "success": traj.success,
                        "total_steps": traj.total_steps
                    }
                }
                f.write(json.dumps(record) + "\n")
        
        logger.info(f"Exported {len(trajectories)} trajectories to {filepath}")
        return str(filepath)
    
    def _export_huggingface(
        self,
        trajectories: list[AgentTrajectory],
        config: dict
    ) -> str:
        """Export to HuggingFace datasets format."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"trajectories_{timestamp}.hf"
        filepath = self.output_dir / filename
        
        records = []
        
        for traj in trajectories:
            record = {
                "id": traj.id,
                "conversations": traj.conversations,
                "messages": [
                    {
                        "role": c.from_role.value,
                        "content": c.value
                    }
                    for c in traj.conversations
                ]
            }
            records.append(record)
        
        # Save as JSON (can be loaded by HuggingFace datasets)
        with open(filepath, "w") as f:
            json.dump(records, f)
        
        logger.info(f"Exported {len(trajectories)} to HuggingFace format: {filepath}")
        return str(filepath)
    
    def _export_agent_flan(
        self,
        trajectories: list[AgentTrajectory],
        config: dict
    ) -> str:
        """Export to Agent-FLAN format."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"agent_flan_{timestamp}.jsonl"
        filepath = self.output_dir / filename
        
        with open(filepath, "w") as f:
            for traj in trajectories:
                record = {
                    "id": traj.id,
                    "conversations": [
                        {"from": c.from_role.value, "value": c.value}
                        for c in traj.conversations
                    ]
                }
                f.write(json.dumps(record) + "\n")
        
        return str(filepath)
    
    def _export_sharegpt(
        self,
        trajectories: list[AgentTrajectory],
        config: dict
    ) -> str:
        """Export to ShareGPT format."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"sharegpt_{timestamp}.jsonl"
        filepath = self.output_dir / filename
        
        with open(filepath, "w") as f:
            for traj in trajectories:
                messages = []
                
                for conv in traj.conversations:
                    if conv.from_role.value == "human":
                        role = "human"
                    elif conv.from_role.value == "assistant":
                        role = "gpt"
                    else:
                        role = "tool"
                    
                    messages.append({
                        "role": role,
                        "content": conv.value
                    })
                
                record = {
                    "id": traj.id,
                    "conversations": messages
                }
                f.write(json.dumps(record) + "\n")
        
        return str(filepath)
    
    def _export_react(
        self,
        trajectories: list[AgentTrajectory],
        config: dict
    ) -> str:
        """Export to ReAct format."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"react_{timestamp}.jsonl"
        filepath = self.output_dir / filename
        
        with open(filepath, "w") as f:
            for traj in trajectories:
                steps = []
                
                for conv in traj.conversations:
                    if conv.from_role.value == "assistant":
                        # Parse thought and action
                        thought = conv.value.split(".")[0] if "." in conv.value else conv.value[:50]
                        steps.append({
                            "thought": thought,
                            "action": "execute_command",
                            "action_input": conv.value
                        })
                    elif conv.from_role.value == "tool":
                        if steps:
                            steps[-1]["observation"] = conv.value
                
                record = {
                    "id": traj.id,
                    "steps": steps,
                    "finalAnswer": traj.success
                }
                f.write(json.dumps(record) + "\n")
        
        return str(filepath)


class DatasetVersioning:
    """Version dataset exports."""
    
    def __init__(self, output_dir: str = "/workspace/project/data/trajectories"):
        self.output_dir = Path(output_dir)
    
    def create_version(
        self,
        trajectories: list[AgentTrajectory],
        version: str,
        formats: list[str] = None
    ) -> dict:
        """Create versioned export."""
        formats = formats or ["jsonl", "huggingface"]
        
        exporter = DatasetExporter(str(self.output_dir))
        
        results = {}
        
        # Version directory
        version_dir = self.output_dir / f"v{version}"
        version_dir.mkdir(exist_ok=True)
        
        # Export in each format
        for fmt in formats:
            try:
                path = exporter.export(trajectories, fmt)
                results[fmt] = path
            except Exception as e:
                logger.error(f"Export failed for {fmt}: {e}")
        
        # Create metadata
        metadata = {
            "version": version,
            "created_at": datetime.utcnow().isoformat(),
            "total_samples": len(trajectories),
            "formats": formats,
            "files": results
        }
        
        metadata_path = version_dir / "metadata.json"
        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)
        
        results["metadata"] = str(metadata_path)
        
        return results