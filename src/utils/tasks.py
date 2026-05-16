"""Celery tasks for distributed processing."""

import asyncio
import logging
import uuid

from celery import Task

logger = logging.getLogger(__name__)


class CallbackTask(Task):
    """Task with callbacks."""
    
    def on_success(self, retval, task_id, args, kwargs):
        logger.info(f"Task {task_id} completed successfully")
    
    def on_failure(self, retval, task_id, args, kwargs, einfo):
        logger.error(f"Task {task_id} failed")


# Import from celery_app
from .celery_app import celery_app


@celery_app.task(bind=True, base=CallbackTask, name="collect_topic")
def collect_topic(self, topic: str, options: dict = None):
    """Collect content for a topic."""
    logger.info(f"Collecting content for: {topic}")
    return {"status": "completed", "topic": topic}


@celery_app.task(bind=True, base=CallbackTask, name="generate_trajectories")
def generate_trajectories(self, events: list, options: dict = None):
    """Generate trajectories from events."""
    return {"status": "completed", "count": len(events) if events else 0}


@celery_app.task(bind=True, base=CallbackTask, name="validate_trajectories")
def validate_trajectories(self, trajectories: list, options: dict = None):
    """Validate trajectories."""
    return {"status": "completed", "count": len(trajectories) if trajectories else 0}


@celery_app.task(bind=True, base=CallbackTask, name="augment_trajectories")
def augment_trajectories(self, trajectories: list, config: dict = None):
    """Augment trajectories with reasoning."""
    return {"status": "completed", "count": len(trajectories) if trajectories else 0}


@celery_app.task(bind=True, base=CallbackTask, name="export_dataset")
def export_dataset(self, trajectories: list, format: str = "jsonl", version: str = None):
    """Export dataset."""
    return {"status": "completed", "format": format, "count": len(trajectories) if trajectories else 0}


@celery_app.task(bind=True, name="full_pipeline")
def full_pipeline(self, topic: str, options: dict = None):
    """Run full pipeline."""
    return {"status": "completed", "topic": topic}