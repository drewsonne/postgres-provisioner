"""Postgres-provisioner operator entry point.

Importing the handler modules registers their kopf decorators.
"""

from __future__ import annotations

import logging
from typing import Any

import databases  # noqa: F401 — registers PostgresDatabase handlers
import kopf
import users  # noqa: F401 — registers PostgresUser handlers

# ---------------------------------------------------------------------------
# Operator settings
# ---------------------------------------------------------------------------


@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_: Any) -> None:
    settings.peering.standalone = True
    settings.persistence.finalizer = "pgprovisioner.drewsonne.github.io/finalizer"

    # Store handler progress and diff-base in annotations under our own prefix
    # so we never collide with another operator or the kopf default namespace.
    settings.persistence.progress_storage = kopf.AnnotationsProgressStorage(
        prefix="pgprovisioner.drewsonne.github.io"
    )
    settings.persistence.diffbase_storage = kopf.AnnotationsDiffBaseStorage(
        prefix="pgprovisioner.drewsonne.github.io",
        key="last-handled-configuration",
    )

    # After we patch a resource (e.g. setting ownerReferences) give the watch
    # stream up to 10 s to deliver the new resourceVersion before processing
    # continues. Prevents double-reconciliation on slow K3s clusters.
    settings.persistence.consistency_timeout = 10

    # Post WARNING+ logger messages from handlers as K8s events so that
    # "kubectl describe" surfaces drift detection and error details.
    settings.posting.level = logging.WARNING
    settings.posting.loggers = True

    # Explicit thread-pool size for sync handlers (psycopg2 calls).
    # Default is 5x CPU cores which can be very low in small containers.
    settings.execution.max_workers = 20

    # Retry K8s API 5xx / network errors with an explicit backoff sequence
    # (seconds). Each success resets the sequence.
    settings.networking.error_backoffs = [10, 20, 30, 60, 120]

    # Reconnect the watch stream if no events or bookmarks arrive for 90 s.
    # Catches silently stalled TCP connections behind load-balancers.
    settings.watching.inactivity_timeout = 90

    # Per-resource framework-error backoff sequence (not handler errors).
    settings.queueing.error_delays = [1, 2, 5, 10, 30, 60, 120]


@kopf.on.probe(id="alive")
def liveness_probe(**_: Any) -> bool:
    """Minimal liveness probe — confirms the operator event loop is running.

    Enable with: kopf run --liveness=http://0.0.0.0:8080/healthz
    """
    return True


@kopf.on.cleanup()
def on_shutdown(logger: kopf.Logger, **_: Any) -> None:
    logger.info("postgres-provisioner shutting down gracefully")
