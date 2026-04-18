"""Kopf handlers for the PostgresDatabase CRD."""

from __future__ import annotations

from typing import Any

import kopf
import psycopg2
from common import (
    CRD_GROUP,
    CRD_VERSION,
    connect,
    database_exists,
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
        raise kopf.TemporaryError(
            f"PostgreSQL error: {exc}",
            delay=30,
        ) from exc
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


@kopf.on.resume(CRD_GROUP, CRD_VERSION, "postgresdatabases")
def resume_fn(
    spec: kopf.Spec,
    name: str,
    namespace: str,
    logger: kopf.Logger,
    **_: Any,
) -> dict[str, Any]:
    """Re-verify resources exist on operator restart without changing passwords."""
    db = spec["dbName"]
    user = spec["owner"]
    secret_name = spec["secretName"]
    secret_ns = spec.get("secretNamespace", namespace)

    validate_identifier(db)
    validate_identifier(user)

    pg_host, pg_user, pg_password = resolve_connection_params(spec)

    password = get_existing_password(secret_ns, secret_name)
    if password is None:
        raise kopf.TemporaryError(
            f"Secret {secret_name} not found during resume; will retry",
            delay=30,
        )

    conn = connect(pg_host, pg_user, pg_password)
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            if not role_exists(cur, user):
                raise kopf.TemporaryError(
                    f"Role {user} missing during resume; will retry",
                    delay=30,
                )
            if not database_exists(cur, db):
                raise kopf.TemporaryError(
                    f"Database {db} missing during resume; will retry",
                    delay=30,
                )
    except psycopg2.Error as exc:
        raise kopf.TemporaryError(
            f"PostgreSQL error: {exc}",
            delay=30,
        ) from exc
    finally:
        conn.close()

    logger.info("Resumed database=%s owner=%s", db, user)
    return {"database": db, "owner": user, "ready": True}


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
    from common import delete_secret

    secret_name = spec["secretName"]
    secret_ns = spec.get("secretNamespace", namespace)
    delete_secret(secret_name, secret_ns, logger)


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
    old: Any,
    new: Any,
    **_: Any,
) -> dict[str, Any]:
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
        raise kopf.TemporaryError(
            f"PostgreSQL error: {exc}",
            delay=30,
        ) from exc
    finally:
        conn.close()

    ensure_secret(
        secret_ns,
        secret_name,
        body,
        secret_data(user, password, db, host=pg_host),
        logger,
    )

    logger.info("Reconciled database=%s owner=%s", db, user)
    return {"database": db, "owner": user, "ready": True}


@kopf.timer(
    CRD_GROUP,
    CRD_VERSION,
    "postgresdatabases",
    interval=300,
    initial_delay=60,
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

    conn = connect(pg_host, pg_user, pg_password)
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            role_ok = role_exists(cur, user)
            db_ok = database_exists(cur, db)
            ensure_role(cur, user, password)
            _ensure_database(cur, db, user)
    except psycopg2.Error as exc:
        raise kopf.TemporaryError(
            f"Drift check failed: {exc}",
            delay=60,
        ) from exc
    finally:
        conn.close()

    if not role_ok or not db_ok:
        logger.warning(
            "Drift repaired: database=%s(%s) role=%s(%s)",
            db,
            db_ok,
            user,
            role_ok,
        )
    else:
        logger.debug("Drift check OK: database=%s owner=%s", db, user)
    return None
