"""FastAPI server for the cybersecurity dataset generation system."""

import logging
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from ..collectors import DeepResearchEngine
from ..normalizers import ContentNormalizer
from ..generators import ReActTrajectoryGenerator
from ..augmentors import ReasoningAugmentor
from ..validators import DatasetValidator
from ..exporters import DatasetExporter

logger = logging.getLogger(__name__)


# Request models
class CollectRequest(BaseModel):
    """Request to collect content."""
    topic: str = Field(..., description="Topic to research")
    max_sources: int = Field(100, ge=1, le=1000)


class GenerateReactRequest(BaseModel):
    """Request to generate ReAct trajectories."""
    events: list = Field(..., description="List of attack events")
    min_steps: int = Field(5, ge=1, le=50)
    max_steps: int = Field(30, ge=1, le=100)
    failure_rate: float = Field(0.30, ge=0, le=1)


class GenerateRequest(BaseModel):
    """Request to generate trajectories."""
    use_react_format: bool = Field(False, description="Use ReAct format")
    min_steps: int = Field(5, ge=1, le=50)
    max_steps: int = Field(30, ge=1, le=100)
    failure_rate: float = Field(0.35, ge=0, le=1)
    validate: bool = True


class CollectRequestFull(BaseModel):
    """Full pipeline request."""
    topic: str
    max_sources: int = 50
    use_react_format: bool = True
    inject_failures: bool = True
    validate: bool = True
    augment: bool = False


# Application lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan."""
    logger.info("Starting Cybersecurity Dataset Generator (ReAct format)")
    yield
    logger.info("Shutting down")


# Create app
app = FastAPI(
    title="CyberAgent ReAct Dataset Generator",
    description="Generate ReAct-style penetration testing trajectories",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "CyberAgent ReAct Dataset Generator",
        "version": "2.0.0",
        "format": "ReAct (Thought/Action)",
        "status": "running"
    }


@app.get("/health")
async def health():
    """Health check."""
    return {"status": "healthy"}


@app.post("/collect")
async def collect_content(request: CollectRequest):
    """Collect content from web sources."""
    try:
        async with DeepResearchEngine(config=None) as engine:
            results = await engine.research_topic(request.topic, request.max_sources)
        
        return {
            "status": "completed",
            "collected": len(results),
            "sources": [{"url": r.url, "source": r.source} for r in results[:10]]
        }
    except Exception as e:
        logger.error(f"Collection failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/generate/react")
async def generate_react_trajectories(request: GenerateReactRequest):
    """
    Generate ReAct-style trajectories.
    
    Produces conversations in this exact format:
    
    User:
    Instruction: ...
    Observation: ...
    
    Agent:
    Thought: ...
    Action: tool[args]
    
    User:
    Observation: ...
    """
    try:
        from ..models import ConversationTurn, ConversationRole
        
        # Convert raw events to model events
        events = []
        for e in request.events:
            from ..models import AttackEvent, StepType, ToolName
            
            # Parse step type
            step_type = StepType(e.get("step_type", "enumeration"))
            
            # Parse tool
            tool = None
            if tool_name := e.get("tool"):
                try:
                    tool = ToolName(tool_name)
                except ValueError:
                    pass
            
            event = AttackEvent(
                step_type=step_type,
                observation=e.get("observation", ""),
                command=e.get("command", ""),
                output=e.get("output", ""),
                reasoning=e.get("reasoning", ""),
                tool_used=tool,
                target=e.get("target"),
                success=e.get("success", True),
                metadata=e.get("metadata", {})
            )
            events.append(event)
        
        # Generate trajectories
        generator = ReActTrajectoryGenerator()
        trajectories = generator.generate(events, {
            "min_steps": request.min_steps,
            "max_steps": request.max_steps,
        })
        
        # Inject failures if requested
        if request.failure_rate > 0:
            from .generators import ReactFailureInjector
            injector = ReactFailureInjector(request.failure_rate)
            trajectories = [injector.inject(t) for t in trajectories]
        
        # Export to JSON
        results = []
        for traj in trajectories:
            results.append({
                "id": traj.id,
                "conversations": [
                    {"from": c.from_role.value, "value": c.value}
                    for c in traj.conversations
                ],
                "metadata": {
                    "difficulty": traj.difficulty.value if traj.difficulty else None,
                    "category": traj.category.value if traj.category else None,
                    "success": traj.success,
                    "total_steps": traj.total_steps,
                    "tools": [t.value for t in traj.tools_used],
                }
            })
        
        return {
            "status": "completed",
            "generated": len(results),
            "trajectories": results
        }
        
    except Exception as e:
        logger.error(f"Generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/full_pipeline")
async def full_pipeline(request: CollectRequestFull):
    """
    Run full pipeline: collect -> normalize -> generate -> validate -> export.
    """
    try:
        # 1. Collect
        logger.info(f"Step 1: Collecting content on '{request.topic}'")
        
        normalizer = ContentNormalizer()
        generator = ReActTrajectoryGenerator()
        exporter = DatasetExporter()
        
        # Use failure injector
        from ..generators import ReactFailureInjector
        failure_injector = ReactFailureInjector(0.30) if request.inject_failures else None
        
        validator = DatasetValidator() if request.validate else None
        
        # Collect content
        async with DeepResearchEngine(config=None) as engine:
            collected = await engine.research_topic(request.topic, request.max_sources)
        
        logger.info(f"Collected {len(collected)} items")
        
        # 2. Normalize
        logger.info("Step 2: Normalizing content")
        all_events = []
        
        for item in collected:
            events = normalizer.normalize(item)
            all_events.extend(events)
        
        logger.info(f"Normalized {len(all_events)} events")
        
        if not all_events:
            raise HTTPException(status_code=400, detail="No events extracted from content")
        
        # 3. Generate trajectories
        logger.info("Step 3: Generating ReAct trajectories")
        
        trajectories = generator.generate(all_events, {
            "min_steps": request.max_sources,
            "max_steps": 30,
        })
        
        if not trajectories:
            raise HTTPException(status_code=400, detail="Failed to generate trajectories")
        
        logger.info(f"Generated {len(trajectories)} trajectories")
        
        # 4. Inject failures
        if failure_injector:
            logger.info("Step 4: Injecting failures")
            trajectories = [failure_injector.inject(t) for t in trajectories]
        
        # 5. Validate
        if validator:
            logger.info("Step 5: Validating trajectories")
            valid = []
            for traj in trajectories:
                result = validator.validate(traj)
                if result.is_valid:
                    valid.append(traj)
            trajectories = valid
            logger.info(f"Valid trajectories: {len(trajectories)}")
        
        # 6. Export
        logger.info("Step 6: Exporting dataset")
        output_path = exporter.export(trajectories, "jsonl")
        
        return {
            "status": "completed",
            "topic": request.topic,
            "collected": len(collected),
            "events": len(all_events),
            "generated": len(trajectories),
            "output_path": output_path,
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Pipeline failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/validate")
async def validate_trajectories(trajectories: list[dict]):
    """Validate trajectories."""
    try:
        validator = DatasetValidator()
        
        results = []
        
        for traj_dict in trajectories:
            from ..models import AgentTrajectory, ConversationTurn
            
            convs = []
            for c in traj_dict.get("conversations", []):
                convs.append(ConversationTurn(
                    from_role=c.get("from", "human"),
                    value=c.get("value", "")
                ))
            
            traj = AgentTrajectory(
                id=traj_dict.get("id", "unknown"),
                conversations=convs
            )
            
            result = validator.validate(traj)
            results.append({
                "id": traj.id,
                "is_valid": result.is_valid,
                "score": result.score,
                "errors": result.errors
            })
        
        return {
            "total": len(results),
            "valid": sum(1 for r in results if r["is_valid"]),
            "results": results
        }
        
    except Exception as e:
        logger.error(f"Validation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/export")
async def export_dataset(
    trajectories: list[dict],
    format: str = "jsonl",
    version: str = None
):
    """Export trajectories to various formats."""
    try:
        from ..models import AgentTrajectory, ConversationTurn
        
        trajs = []
        for traj_dict in trajectories:
            convs = []
            for c in traj_dict.get("conversations", []):
                convs.append(ConversationTurn(
                    from_role=c.get("from", "human"),
                    value=c.get("value", "")
                ))
            
            traj = AgentTrajectory(
                id=traj_dict.get("id", "unknown"),
                conversations=convs
            )
            trajs.append(traj)
        
        exporter = DatasetExporter()
        output_path = exporter.export(trajs, format)
        
        return {
            "status": "completed",
            "output_path": output_path,
            "format": format,
            "count": len(trajs)
        }
        
    except Exception as e:
        logger.error(f"Export failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.exception_handler(Exception)
async def exception_handler(request, exc):
    """Handle exceptions."""
    logger.error(f"Exception: {exc}")
    return {"detail": str(exc)}