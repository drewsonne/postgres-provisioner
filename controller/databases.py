"""Kopf handlers for the PostgresDatabase CRD."""

from __future__ import annotations

from typing import Any

import kopf
import psycopg2
import psycopg2.extensions
from common import (
    CRD_GROUP,
    CRD_VERSION,
    connect,
    database_exists,
    dbt_is_active,
    delete_secret,
    ensure_role,
    ensure_secret,
    get_existing_password,
    rand_pw,
    resolve_connection_params,
    role_exists,
    secret_data,
    validate_identifier,
)
from psycopg2 import sql


def _ensure_database(
    cur: psycopg2.extensions.cursor,
    db: str,
    owner: str,
) -> None:
    if not database_exists(cur, db):
        cur.execute(
            sql.SQL("CREATE DATABASE {} OWNER {}").format(
                sql.Identifier(db),
                sql.Identifier(owner),
            ),
        )


def _upsert_database(
    spec: kopf.Spec,
    namespace: str,
    body: kopf.Body,
    logger: kopf.Logger,
) -> dict[str, Any]:
    """Ensure the database and owner role exist and match spec.

    Called from create, resume, and update handlers so all three share
    identical reconciliation logic and the same error-handling paths.
    """
    db = spec["dbName"]
    user = spec["owner"]
    secret_name = spec["secretName"]
    secret_ns = spec.get("secretNamespace", namespace)

    validate_identifier(db)
    validate_identifier(user)

    pg_host, pg_user, pg_password = resolve_connection_params(spec)
    password = get_existing_password(secret_ns, secret_name) or rand_pw()

    conn = connect(pg_host, pg_user, pg_password)
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            ensure_role(cur, user, password)
            _ensure_database(cur, db, user)
    except psycopg2.Error as exc:
        raise kopf.TemporaryError(f"PostgreSQL error: {exc}", delay=30) from exc
    finally:
        conn.close()

    ensure_secret(
        secret_ns,
        secret_name,
        body,
        secret_data(user, password, db, host=pg_host),
        logger,
    )

    logger.info("Provisioned database=%s owner=%s", db, user)
    return {"database": db, "owner": user, "ready": True}


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


@kopf.on.create(
    CRD_GROUP,
    CRD_VERSION,
    "postgresdatabases",
    retries=5,
    backoff=30,
    timeout=300,
)
def create_fn(
    spec: kopf.Spec,
    name: str,
    namespace: str,
    body: kopf.Body,
    logger: kopf.Logger,
    **_: Any,
) -> dict[str, Any]:
    return _upsert_database(spec, namespace, body, logger)


@kopf.on.resume(CRD_GROUP, CRD_VERSION, "postgresdatabases")
def resume_fn(
    spec: kopf.Spec,
    name: str,
    namespace: str,
    body: kopf.Body,
    logger: kopf.Logger,
    **_: Any,
) -> dict[str, Any]:
    """Re-verify and recreate resources if missing on operator restart."""
    return _upsert_database(spec, namespace, body, logger)


@kopf.on.update(
    CRD_GROUP,
    CRD_VERSION,
    "postgresdatabases",
    field="spec",
    retries=3,
    backoff=15,
)
def update_fn(
    spec: kopf.Spec,
    name: str,
    namespace: str,
    body: kopf.Body,
    logger: kopf.Logger,
    **_: Any,
) -> dict[str, Any]:
    return _upsert_database(spec, namespace, body, logger)


@kopf.on.delete(
    CRD_GROUP,
    CRD_VERSION,
    "postgresdatabases",
    retries=3,
    backoff=15,
    timeout=120,
)
def delete_fn(
    spec: kopf.Spec,
    name: str,
    namespace: str,
    logger: kopf.Logger,
    **_: Any,
) -> None:
    # The database and owner role are intentionally NOT dropped here to prevent
    # accidental data loss. Only the K8s connection secret is removed.
    secret_name = spec["secretName"]
    secret_ns = spec.get("secretNamespace", namespace)
    delete_secret(secret_name, secret_ns, logger)


@kopf.timer(
    CRD_GROUP,
    CRD_VERSION,
    "postgresdatabases",
    interval=300,
    initial_delay=60,
    idle=30,
)
def check_drift(
    spec: kopf.Spec,
    name: str,
    namespace: str,
    body: kopf.Body,
    logger: kopf.Logger,
    **_: Any,
) -> dict[str, Any] | None:
    """Periodically reconcile database and owner role to repair drift."""
    db = spec["dbName"]
    user = spec["owner"]
    secret_name = spec["secretName"]
    secret_ns = spec.get("secretNamespace", namespace)

    pg_host, pg_user, pg_password = resolve_connection_params(spec)

    password = get_existing_password(secret_ns, secret_name)
    if password is None:
        raise kopf.TemporaryError(
            f"Secret {secret_name} not found during drift check; will retry",
            delay=30,
        )

    if dbt_is_active(pg_host, pg_user, pg_password, db):
        logger.info(
            "dbt build active in %s; skipping database drift check this cycle", db
        )
        return None

    conn = connect(pg_host, pg_user, pg_password)
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            role_ok = role_exists(cur, user)
            db_ok = database_exists(cur, db)
            if not role_ok or not db_ok:
                logger.warning(
                    "Drift detected: database=%s(%s) role=%s(%s); repairing",
                    db,
                    db_ok,
                    user,
                    role_ok,
                )
            ensure_role(cur, user, password)
            _ensure_database(cur, db, user)
    except psycopg2.Error as exc:
        raise kopf.TemporaryError(f"Drift check failed: {exc}", delay=60) from exc
    finally:
        conn.close()

    if not role_ok or not db_ok:
        reason = ", ".join(
            filter(
                None,
                [
                    "role missing" if not role_ok else "",
                    "database missing" if not db_ok else "",
                ],
            )
        )
        logger.warning("Drift repaired: database=%s role=%s (%s)", db, user, reason)
        return {"drift": True, "driftReason": reason, "ready": True}

    logger.debug("Drift check OK: database=%s owner=%s", db, user)
    return None
