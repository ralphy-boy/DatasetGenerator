"""Celery application for distributed processing."""

import logging
import os

from celery import Celery
from celery.signals import worker_ready, worker_shutdown

logger = logging.getLogger(__name__)

# Create Celery app
celery_app = Celery(
    "cyberagent",
    broker=os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0"),
    backend=os.environ.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/1")
)

# Configure Celery
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_track_started=True,
    task_time_limit=3600,
    task_soft_time_limit=3000,
)

# Import tasks after app creation
from . import tasks