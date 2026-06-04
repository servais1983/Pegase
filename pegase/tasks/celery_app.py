"""Celery application factory."""

from __future__ import annotations

from celery import Celery

from pegase.core.config import get_settings


def make_celery() -> Celery:
    settings = get_settings()
    app = Celery(
        "pegase",
        broker=settings.celery_broker_url,
        backend=settings.celery_result_backend,
        include=["pegase.tasks.scans"],
    )
    app.conf.update(
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        task_acks_late=True,
        worker_prefetch_multiplier=1,
        task_time_limit=60 * 60,  # 1h hard
        task_soft_time_limit=55 * 60,
        broker_connection_retry_on_startup=True,
    )
    return app


celery_app = make_celery()
