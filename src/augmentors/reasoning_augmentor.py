"""LLM-powered reasoning augmentation for trajectories."""

import asyncio
import hashlib
import json
import logging
import os
from datetime import datetime
from typing import Any, Optional

import aiohttp

logger = logging.getLogger(__name__)

# Try to import transformers
try:
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    logger.warning("Transformers not available, LLM augmentation limited")


class ReasoningAugmentor:
    """
    LLM-powered reasoning augmentation.
    
    Uses a coding LLM to generate expert-level reasoning:
    - Why action was selected
    - Alternative paths
    - Why failure occurred
    - OPSEC considerations
    - Prioritization logic
    """
    
    def __init__(
        self,
        model_name: str = "deepseek-ai/deepseek-coder-33b-instruct",
        api_url: Optional[str] = None
    ):
        self.model_name = model_name
        self.api_url = api_url or os.environ.get("VLLM_API_URL", "http://localhost:8001")
        self.pipeline = None
        self._initialize()
    
    def _initialize(self):
        """Initialize model."""
        if TRANSFORMERS_AVAILABLE and self.api_url:
            try:
                # Try vLLM API first
                self.pipeline = pipeline(
                    "text-generation",
                    model=self.model_name,
                    backend="vllm",
                    vllm_server=self.api_url
                )
            except Exception as e:
                logger.warning(f"Failed to initialize vLLM: {e}")
    
    async def augment(
        self,
        trajectory: dict,
        config: dict = None
    ) -> dict:
        """
        Augment trajectory with LLM-generated reasoning.
        
        Args:
            trajectory: Trajectory to augment
            config: Augmentation config
            
        Returns:
            Augmented trajectory
        """
        config = config or {}
        
        if not self.pipeline:
            return trajectory
        
        # Extract current reasoning
        conversations = trajectory.get("conversations", [])
        
        # Find assistant turns
        for i, turn in enumerate(conversations):
            if turn.get("from") == "assistant":
                current_value = turn.get("value", "")
                
                # Generate enhanced reasoning
                enhanced = await self._generate_reasoning(
                    current_value,
                    trajectory,
                    config
                )
                
                if enhanced:
                    conversations[i]["value"] = enhanced
        
        trajectory["conversations"] = conversations
        trajectory["augmented_at"] = datetime.utcnow().isoformat()
        
        return trajectory
    
    async def _generate_reasoning(
        self,
        current_reasoning: str,
        trajectory: dict,
        config: dict
    ) -> str:
        """Generate enhanced reasoning."""
        # Build prompt
        prompt = f"""Given the current reasoning from an autonomous penetration testing agent:

Current reasoning: {current_reasoning}

Task: Generate an enhanced version with:
1. Why this action was selected
2. Alternative approaches that could be tried
3. OPSEC considerations
4. Expected outcome

Provide an enhanced reasoning in 2-3 sentences:"""
        
        try:
            if self.pipeline:
                # Use local model
                result = self.pipeline(
                    prompt,
                    max_new_tokens=150,
                    temperature=0.7,
                    top_p=0.9
                )
                
                if result and len(result) > 0:
                    return result[0]["generated_text"].split("enhanced reasoning in 2-3 sentences:")[-1].strip()
            
            # Fallback to API
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.api_url}/generate",
                    json={
                        "prompt": prompt,
                        "max_tokens": 150,
                        "temperature": 0.7
                    }
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get("text", current_reasoning)
        
        except Exception as e:
            logger.debug(f"Reasoning generation failed: {e}")
        
        return current_reasoning
    
    async def augment_batch(
        self,
        trajectories: list[dict],
        config: dict = None,
        batch_size: int = 8
    ) -> list[dict]:
        """
        Augment batch of trajectories.
        
        Args:
            trajectories: List of trajectories
            config: Augmentation config
            batch_size: Batch size for processing
            
        Returns:
            Augmented trajectories
        """
        augmented = []
        
        for i in range(0, len(trajectories), batch_size):
            batch = trajectories[i:i + batch_size]
            
            # Process in parallel
            tasks = [self.tra augment(t, config) for t in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, Exception):
                    logger.warning(f"Augmentation failed: {result}")
                    augmented.append(None)
                else:
                    augmented.append(result)
            
            # Rate limiting
            await asyncio.sleep(1)
        
        return [t for t in augmented if t is not None]


class ReasoningPromptBuilder:
    """Build prompts for reasoning generation."""
    
    @staticmethod
    def build_why_action_prompt(action: str, context: dict) -> str:
        """Build prompt for explaining why action was selected."""
        return f"""Why was the following action selected for penetration testing?

Action: {action}

Context:
- Target: {context.get('target', 'unknown')}
- Phase: {context.get('phase', 'unknown')}
- Previous findings: {context.get('findings', 'none')}

Explain in 1-2 sentences:"""
    
    @staticmethod
    def build_alternative_prompt(
        action: str,
        outcome: str,
        success: bool
    ) -> str:
        """Build prompt for alternative approaches."""
        prompt = f"""Given this penetration testing action and its outcome:

Action: {action}
Outcome: {outcome}
Success: {success}

Suggest 2-3 alternative approaches if this failed, or ways to improve if it succeeded:"""
        
        return prompt
    
    @staticmethod
    def build_opsec_prompt(action: str, target: str) -> str:
        """Build prompt for OPSEC considerations."""
        return f"""What OPSEC (Operational Security) considerations should be noted for:

Action: {action}
Target: {target}

List critical OPSEC points:"""
    
    @staticmethod
    def build_failure_analysis_prompt(
        action: str,
        error: str,
        phase: str
    ) -> str:
        """Build prompt for failure analysis."""
        return f"""Analyze why this penetration test step failed:

Action: {action}
Error/Output: {error}
Phase: {phase}

Explain why it failed and suggest next steps:"""


class BatchAugmentor:
    """Batch processing for trajectory augmentation."""
    
    def __init__(self, augmentor: ReasoningAugmentor):
        self.augmentor = augmentor
    
    async def process(
        self,
        trajectories: list[dict],
        config: dict = None
    ) -> list[dict]:
        """Process batch of trajectories."""
        config = config or {}
        
        results = []
        
        for trajectory in trajectories:
            try:
                augmented = await self.augmentor.tra augment(trajectory, config)
                results.append(augmented)
            except Exception as e:
                logger.warning(f"Trajectory augmentation failed: {e}")
                results.append(trajectory)
        
        return results
    
    async def process_streaming(
        self,
        trajectories: list[dict],
        config: dict = None
    ):
        """Process trajectories as async generator."""
        config = config or {}
        
        for trajectory in trajectories:
            try:
                augmented = await self.augmentor.tra augment(trajectory, config)
                yield augmented
            except Exception as e:
                logger.warning(f"Trajectory augmentation failed: {e}")
                yield trajectory