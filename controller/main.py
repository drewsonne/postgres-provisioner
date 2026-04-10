from __future__ import annotations

import base64
import logging
import os
import secrets
import string
from typing import Any

import kopf
import kubernetes
import psycopg2
from psycopg2 import sql

PG_HOST = os.environ["PG_HOST"]
PG_USER = os.environ["PG_USER"]
PG_PASSWORD = os.environ["PG_PASSWORD"]

VALID_IDENTIFIER_CHARS = set(string.ascii_letters + string.digits + "_")


def _rand_pw(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _validate_identifier(value: str) -> None:
    if not value or not all(c in VALID_IDENTIFIER_CHARS for c in value):
        msg = f"Invalid SQL identifier: {value!r}"
        raise kopf.PermanentError(msg)
    if value[0].isdigit():
        msg = f"SQL identifier must not start with a digit: {value!r}"
        raise kopf.PermanentError(msg)


def _connect() -> psycopg2.extensions.connection:
    try:
        return psycopg2.connect(
            host=PG_HOST,
            user=PG_USER,
            password=PG_PASSWORD,
            dbname="postgres",
        )
    except psycopg2.OperationalError as exc:
        raise kopf.TemporaryError(
            f"Cannot connect to PostgreSQL: {exc}",
            delay=30,
        ) from exc


def _database_exists(
    cur: psycopg2.extensions.cursor,
    name: str,
) -> bool:
    cur.execute("SELECT 1 FROM pg_database WHERE datname=%s", (name,))
    return cur.fetchone() is not None


def _role_exists(cur: psycopg2.extensions.cursor, name: str) -> bool:
    cur.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (name,))
    return cur.fetchone() is not None


def _ensure_role(
    cur: psycopg2.extensions.cursor,
    role: str,
    password: str,
) -> None:
    if not _role_exists(cur, role):
        cur.execute(
            sql.SQL("CREATE ROLE {} LOGIN PASSWORD %s").format(
                sql.Identifier(role),
            ),
            (password,),
        )


def _ensure_database(
    cur: psycopg2.extensions.cursor,
    db: str,
    owner: str,
) -> None:
    if not _database_exists(cur, db):
        cur.execute(
            sql.SQL("CREATE DATABASE {} OWNER {}").format(
                sql.Identifier(db),
                sql.Identifier(owner),
            ),
        )


def _get_existing_password(
    namespace: str,
    secret_name: str,
) -> str | None:
    """Read the password from an existing Kubernetes secret, or return None."""
    v1 = kubernetes.client.CoreV1Api()
    try:
        secret = v1.read_namespaced_secret(name=secret_name, namespace=namespace)
        raw = (secret.data or {}).get("password")
        if raw:
            return base64.b64decode(raw).decode()
    except kubernetes.client.exceptions.ApiException as exc:
        if exc.status != 404:
            raise kopf.TemporaryError(
                f"Failed reading secret {secret_name}: {exc}",
                delay=15,
            ) from exc
    return None


def _ensure_secret(
    namespace: str,
    secret_name: str,
    body: kopf.Body,
    data: dict[str, str],
    logger: kopf.Logger,
) -> None:
    v1 = kubernetes.client.CoreV1Api()
    secret_body = kubernetes.client.V1Secret(
        metadata=kubernetes.client.V1ObjectMeta(name=secret_name),
        string_data=data,
    )
    kopf.adopt(secret_body)

    try:
        v1.create_namespaced_secret(namespace=namespace, body=secret_body)
        logger.info("Created secret %s", secret_name)
    except kubernetes.client.exceptions.ApiException as exc:
        if exc.status == 409:
            v1.patch_namespaced_secret(
                name=secret_name,
                namespace=namespace,
                body={"stringData": data},
            )
            logger.info("Updated existing secret %s", secret_name)
        else:
            raise kopf.TemporaryError(
                f"Kubernetes API error creating secret: {exc}",
                delay=15,
            ) from exc


def _secret_data(user: str, password: str, db: str) -> dict[str, str]:
    return {
        "username": user,
        "password": password,
        "database": db,
        "host": PG_HOST,
        "port": "5432",
    }


# ---------------------------------------------------------------------------
# Operator settings
# ---------------------------------------------------------------------------


@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_: Any) -> None:
    settings.peering.standalone = True
    settings.posting.level = logging.WARNING
    settings.persistence.finalizer = "db.example.com/finalizer"


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


@kopf.on.create(
    "db.example.com", "v1", "postgresdatabases", retries=5, backoff=30, timeout=300
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

    _validate_identifier(db)
    _validate_identifier(user)

    password = _get_existing_password(namespace, secret_name) or _rand_pw()

    conn = _connect()
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            _ensure_role(cur, user, password)
            _ensure_database(cur, db, user)
    except psycopg2.Error as exc:
        raise kopf.TemporaryError(
            f"PostgreSQL error: {exc}",
            delay=30,
        ) from exc
    finally:
        conn.close()

    _ensure_secret(
        namespace, secret_name, body, _secret_data(user, password, db), logger
    )

    logger.info("Provisioned database=%s owner=%s", db, user)
    return {"database": db, "owner": user, "ready": True}


@kopf.on.resume("db.example.com", "v1", "postgresdatabases")
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

    _validate_identifier(db)
    _validate_identifier(user)

    password = _get_existing_password(namespace, secret_name)
    if password is None:
        raise kopf.TemporaryError(
            f"Secret {secret_name} not found during resume; will retry",
            delay=30,
        )

    conn = _connect()
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            if not _role_exists(cur, user):
                raise kopf.TemporaryError(
                    f"Role {user} missing during resume; will retry",
                    delay=30,
                )
            if not _database_exists(cur, db):
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
    "db.example.com", "v1", "postgresdatabases", retries=3, backoff=15, timeout=120
)
def delete_fn(
    spec: kopf.Spec,
    name: str,
    namespace: str,
    logger: kopf.Logger,
    **_: Any,
) -> None:
    secret_name = spec["secretName"]

    v1 = kubernetes.client.CoreV1Api()
    try:
        v1.delete_namespaced_secret(name=secret_name, namespace=namespace)
        logger.info("Deleted secret %s", secret_name)
    except kubernetes.client.exceptions.ApiException as exc:
        if exc.status != 404:
            raise kopf.TemporaryError(
                f"Failed to delete secret: {exc}",
                delay=15,
            ) from exc
        logger.info("Secret %s already absent", secret_name)


@kopf.on.update(
    "db.example.com", "v1", "postgresdatabases", field="spec", retries=3, backoff=15
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

    _validate_identifier(db)
    _validate_identifier(user)

    password = _get_existing_password(namespace, secret_name) or _rand_pw()

    conn = _connect()
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            _ensure_role(cur, user, password)
            _ensure_database(cur, db, user)
    except psycopg2.Error as exc:
        raise kopf.TemporaryError(
            f"PostgreSQL error: {exc}",
            delay=30,
        ) from exc
    finally:
        conn.close()

    _ensure_secret(
        namespace, secret_name, body, _secret_data(user, password, db), logger
    )

    logger.info("Reconciled database=%s owner=%s", db, user)
    return {"database": db, "owner": user, "ready": True}


@kopf.timer("db.example.com", "v1", "postgresdatabases", interval=300, initial_delay=60)
def check_drift(
    spec: kopf.Spec,
    logger: kopf.Logger,
    **_: Any,
) -> dict[str, Any] | None:
    db = spec["dbName"]
    user = spec["owner"]

    conn = _connect()
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            db_ok = _database_exists(cur, db)
            role_ok = _role_exists(cur, user)
    except psycopg2.Error as exc:
        raise kopf.TemporaryError(
            f"Drift check failed: {exc}",
            delay=60,
        ) from exc
    finally:
        conn.close()

    if not db_ok or not role_ok:
        logger.warning(
            "Drift detected: database=%s(%s) role=%s(%s)",
            db,
            db_ok,
            user,
            role_ok,
        )
        return {"database": db, "owner": user, "ready": False, "drift": True}

    return None
