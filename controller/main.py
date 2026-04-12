"""Postgres-provisioner operator entry point.

Importing the handler modules registers their kopf decorators.
"""

from __future__ import annotations

import logging
from typing import Any

import kopf

import databases  # noqa: F401 — registers PostgresDatabase handlers
import users  # noqa: F401 — registers PostgresUser handlers


# ---------------------------------------------------------------------------
# Operator settings
# ---------------------------------------------------------------------------


@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_: Any) -> None:
    settings.peering.standalone = True
    settings.posting.level = logging.WARNING
    settings.persistence.finalizer = "pgprovisioner.drewsonne.github.io/finalizer"
