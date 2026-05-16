"""Main pipeline - orchestrates the full dataset generation workflow."""

import asyncio
import logging
import uuid
from datetime import datetime
from typing import Any, Optional

from ..collectors import DeepResearchEngine, HackTheBoxCollector
from ..normalizers import ContentNormalizer, AttackPhaseClassifier
from ..generators import TrajectoryGenerator
from ..augmentors import ReasoningAugmentor
from ..simulators import ToolOutputSimulator, FailureInjector
from ..validators import DatasetValidator
from ..exporters import DatasetExporter

logger = logging.getLogger(__name__)


class DatasetPipeline:
    """
    Main pipeline for cybersecurity dataset generation.
    
    Orchestrates:
    1. Data Collection (deep research + scraping)
    2. Content Normalization
    3. Agent Trajectory Generation
    4. Synthetic Reasoning Generation (optional)
    5. Tool Output Simulation (for augmentation)
    6. Failure Injection
    7. Dataset Validation
    8. Dataset Generation
    9. Export
    """
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        
        # Initialize components
        self.research_engine = DeepResearchEngine(config=None)
        self.normalizer = ContentNormalizer()
        self.phase_classifier = AttackPhaseClassifier()
        self.trajectory_generator = TrajectoryGenerator()
        self.reasoning_augmentor = ReasoningAugmentor()
        self.tool_simulator = ToolOutputSimulator()
        self.failure_injector = FailureInjector(
            self.config.get("failure_rate", 0.35)
        )
        self.validator = DatasetValidator()
        self.exporter = DatasetExporter(
            self.config.get("output_dir", "/workspace/project/data/trajectories")
        )
    
    async def run(
        self,
        topic: str,
        options: dict = None
    ) -> dict:
        """
        Run the full pipeline.
        
        Args:
            topic: Topic to research and generate
            options: Pipeline options
            
        Returns:
            Pipeline results
        """
        options = options or {}
        start_time = datetime.utcnow()
        
        results = {
            "pipeline_id": str(uuid.uuid4()),
            "topic": topic,
            "start_time": start_time.isoformat(),
            "phases": {}
        }
        
        try:
            # Phase 1: Data Collection
            logger.info(f"Phase 1: Collecting content on '{topic}'")
            
            collected = await self._collect_content(topic, options)
            results["phases"]["collection"] = {
                "status": "completed",
                "items": len(collected)
            }
            
            # Phase 2: Normalization
            logger.info("Phase 2: Normalizing content")
            
            events = await self._normalize_content(collected, options)
            results["phases"]["normalization"] = {
                "status": "completed",
                "events": len(events)
            }
            
            # Phase 3: Trajectory Generation
            logger.info("Phase 3: Generating trajectories")
            
            trajectories = self.trajectory_generator.generate(events, options)
            results["phases"]["generation"] = {
                "status": "completed",
                "trajectories": len(trajectories)
            }
            
            # Phase 4: Reasoning Augmentation (optional)
            if options.get("augment", False):
                logger.info("Phase 4: Augmenting with reasoning")
                
                trajectories = await self._augment_trajectories(trajectories, options)
                results["phases"]["augmentation"] = {
                    "status": "completed",
                    "trajectories": len(trajectories)
                }
            
            # Phase 5: Failure Injection
            logger.info("Phase 5: Injecting failures")
            
            trajectories = self.failure_injector.inject_batch(trajectories, options)
            results["phases"]["failure_injection"] = {
                "status": "completed",
                "with_failures": sum(1 for t in trajectories if not t.success)
            }
            
            # Phase 6: Validation
            logger.info("Phase 6: Validating trajectories")
            
            valid_count = 0
            validated = []
            
            for traj in trajectories:
                result = self.validator.validate(traj, options)
                if result.is_valid:
                    valid_count += 1
                    validated.append(traj)
            
            trajectories = validated
            results["phases"]["validation"] = {
                "status": "completed",
                "valid": valid_count,
                "invalid": len(trajectories) - valid_count
            }
            
            # Phase 7: Export
            logger.info("Phase 7: Exporting dataset")
            
            output_path = self.exporter.export(trajectories, options.get("format", "jsonl"))
            results["phases"]["export"] = {
                "status": "completed",
                "output_path": output_path
            }
            
            # Final results
            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()
            
            results["status"] = "completed"
            results["end_time"] = end_time.isoformat()
            results["duration_seconds"] = duration
            results["final_samples"] = len(trajectories)
            
            logger.info(f"Pipeline completed: {len(trajectories)} trajectories in {duration:.1f}s")
            
            return results
            
        except Exception as e:
            logger.error(f"Pipeline failed: {e}")
            results["status"] = "failed"
            results["error"] = str(e)
            return results
    
    async def _collect_content(self, topic: str, options: dict) -> list:
        """Collect content."""
        async with self.research_engine as engine:
            return await engine.research_topic(
                topic,
                options.get("max_sources", 100)
            )
    
    async def _normalize_content(self, collected: list, options: dict) -> list:
        """Normalize content."""
        events = []
        
        for item in collected:
            try:
                normalized = self.normalizer.normalize(item)
                events.extend(normalized)
            except Exception as e:
                logger.debug(f"Normalization failed: {e}")
        
        return events
    
    async def _augment_trajectories(self, trajectories: list, options: dict) -> list:
        """Augment trajectories."""
        augmented = []
        
        try:
            for traj in trajectories:
                try:
                    aug_traj = await self.reasoning_augmentor.tra augment(traj, options)
                    augmented.append(aug_traj)
                except Exception as e:
                    logger.debug(f"Augmentation failed: {e}")
                    augmented.append(traj)
        except Exception:
            # If augmentation fails, return original
            return trajectories
        
        return augmented


class ParallelPipeline:
    """Pipeline for parallel processing."""
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.pipeline = DatasetPipeline(config)
    
    async def run_batch(
        self,
        topics: list[str],
        options: dict = None
    ) -> list[dict]:
        """Run pipeline on multiple topics."""
        results = []
        
        tasks = [self.pipeline.run(topic, options) for topic in topics]
        
        for coro in asyncio.as_completed(tasks):
            result = await coro
            results.append(result)
        
        return results


def create_pipeline(config: dict = None) -> DatasetPipeline:
    """Create pipeline from config."""
    return DatasetPipeline(config)