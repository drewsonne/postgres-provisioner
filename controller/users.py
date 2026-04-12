"""Kopf handlers for the PostgresUser CRD."""

from __future__ import annotations

from typing import Any

import kopf
import psycopg2
from psycopg2 import sql

from common import (
    CRD_GROUP,
    CRD_VERSION,
    connect,
    database_exists,
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

_VALID_ACCESS = frozenset({"read", "readwrite"})


def _validate_access(access: str) -> None:
    if access not in _VALID_ACCESS:
        msg = f"Invalid access level {access!r}; must be one of {sorted(_VALID_ACCESS)}"
        raise kopf.PermanentError(msg)


def _grant_access(
    cur: psycopg2.extensions.cursor,
    username: str,
    access: str,
) -> None:
    """Grant schema-level privileges on the connected database.

    Must be called on a connection to the *target* database (not ``postgres``).
    """
    role = sql.Identifier(username)

    # Both levels get USAGE on public
    cur.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(role))

    if access == "read":
        cur.execute(
            sql.SQL(
                "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {}",
            ).format(role),
        )
        cur.execute(
            sql.SQL(
                "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
                "GRANT SELECT ON TABLES TO {}",
            ).format(role),
        )
    else:
        # readwrite
        cur.execute(
            sql.SQL(
                "GRANT CREATE ON SCHEMA public TO {}",
            ).format(role),
        )
        cur.execute(
            sql.SQL(
                "GRANT SELECT, INSERT, UPDATE, DELETE "
                "ON ALL TABLES IN SCHEMA public TO {}",
            ).format(role),
        )
        cur.execute(
            sql.SQL(
                "GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO {}",
            ).format(role),
        )
        cur.execute(
            sql.SQL(
                "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
                "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {}",
            ).format(role),
        )
        cur.execute(
            sql.SQL(
                "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
                "GRANT USAGE ON SEQUENCES TO {}",
            ).format(role),
        )


def _revoke_access(
    cur: psycopg2.extensions.cursor,
    username: str,
) -> None:
    """Revoke all schema-level privileges on the connected database."""
    role = sql.Identifier(username)

    cur.execute(
        sql.SQL(
            "ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM {}",
        ).format(role),
    )
    cur.execute(
        sql.SQL(
            "ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM {}",
        ).format(role),
    )
    cur.execute(
        sql.SQL("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {}").format(role),
    )
    cur.execute(
        sql.SQL("REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {}").format(role),
    )
    cur.execute(
        sql.SQL("REVOKE ALL ON SCHEMA public FROM {}").format(role),
    )


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


@kopf.on.create(
    CRD_GROUP,
    CRD_VERSION,
    "postgresusers",
    retries=5,
    backoff=30,
    timeout=300,
)
def user_create_fn(
    spec: kopf.Spec,
    name: str,
    namespace: str,
    body: kopf.Body,
    logger: kopf.Logger,
    **_: Any,
) -> dict[str, Any]:
    username = spec["username"]
    db = spec["dbName"]
    access = spec["access"]
    secret_name = spec["secretName"]
    secret_ns = spec.get("secretNamespace", namespace)

    validate_identifier(username)
    validate_identifier(db)
    _validate_access(access)

    pg_host, pg_user, pg_password = resolve_connection_params(spec)
    password = get_existing_password(secret_ns, secret_name) or rand_pw()

    # --- connect to 'postgres' to create role + verify DB exists ---
    conn = connect(pg_host, pg_user, pg_password)
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            if not database_exists(cur, db):
                raise kopf.TemporaryError(
                    f"Database {db} does not exist yet; will retry",
                    delay=30,
                )
            ensure_role(cur, username, password)
            cur.execute(
                sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                    sql.Identifier(db),
                    sql.Identifier(username),
                ),
            )
    except psycopg2.Error as exc:
        raise kopf.TemporaryError(
            f"PostgreSQL error: {exc}",
            delay=30,
        ) from exc
    finally:
        conn.close()

    # --- connect to target DB to set schema-level grants ---
    db_conn = connect(pg_host, pg_user, pg_password, dbname=db)
    try:
        db_conn.autocommit = True
        with db_conn.cursor() as cur:
            _grant_access(cur, username, access)
    except psycopg2.Error as exc:
        raise kopf.TemporaryError(
            f"PostgreSQL error granting on {db}: {exc}",
            delay=30,
        ) from exc
    finally:
        db_conn.close()

    ensure_secret(
        secret_ns,
        secret_name,
        body,
        secret_data(username, password, db, host=pg_host),
        logger,
    )

    logger.info("Provisioned user=%s db=%s access=%s", username, db, access)
    return {"username": username, "database": db, "access": access, "ready": True}


@kopf.on.resume(CRD_GROUP, CRD_VERSION, "postgresusers")
def user_resume_fn(
    spec: kopf.Spec,
    name: str,
    namespace: str,
    logger: kopf.Logger,
    **_: Any,
) -> dict[str, Any]:
    """Re-verify resources exist on operator restart."""
    username = spec["username"]
    db = spec["dbName"]
    access = spec["access"]
    secret_name = spec["secretName"]
    secret_ns = spec.get("secretNamespace", namespace)

    validate_identifier(username)
    validate_identifier(db)
    _validate_access(access)

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
            if not role_exists(cur, username):
                raise kopf.TemporaryError(
                    f"Role {username} missing during resume; will retry",
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

    logger.info("Resumed user=%s db=%s access=%s", username, db, access)
    return {"username": username, "database": db, "access": access, "ready": True}


@kopf.on.update(
    CRD_GROUP,
    CRD_VERSION,
    "postgresusers",
    field="spec",
    retries=3,
    backoff=15,
)
def user_update_fn(
    spec: kopf.Spec,
    name: str,
    namespace: str,
    body: kopf.Body,
    logger: kopf.Logger,
    old: Any,
    new: Any,
    **_: Any,
) -> dict[str, Any]:
    username = spec["username"]
    db = spec["dbName"]
    access = spec["access"]
    secret_name = spec["secretName"]
    secret_ns = spec.get("secretNamespace", namespace)

    validate_identifier(username)
    validate_identifier(db)
    _validate_access(access)

    pg_host, pg_user, pg_password = resolve_connection_params(spec)
    password = get_existing_password(secret_ns, secret_name) or rand_pw()

    # Ensure role + CONNECT
    conn = connect(pg_host, pg_user, pg_password)
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            if not database_exists(cur, db):
                raise kopf.TemporaryError(
                    f"Database {db} does not exist yet; will retry",
                    delay=30,
                )
            ensure_role(cur, username, password)
            cur.execute(
                sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                    sql.Identifier(db),
                    sql.Identifier(username),
                ),
            )
    except psycopg2.Error as exc:
        raise kopf.TemporaryError(
            f"PostgreSQL error: {exc}",
            delay=30,
        ) from exc
    finally:
        conn.close()

    # Revoke old grants, apply new ones
    db_conn = connect(pg_host, pg_user, pg_password, dbname=db)
    try:
        db_conn.autocommit = True
        with db_conn.cursor() as cur:
            _revoke_access(cur, username)
            _grant_access(cur, username, access)
    except psycopg2.Error as exc:
        raise kopf.TemporaryError(
            f"PostgreSQL error granting on {db}: {exc}",
            delay=30,
        ) from exc
    finally:
        db_conn.close()

    ensure_secret(
        secret_ns,
        secret_name,
        body,
        secret_data(username, password, db, host=pg_host),
        logger,
    )

    logger.info("Reconciled user=%s db=%s access=%s", username, db, access)
    return {"username": username, "database": db, "access": access, "ready": True}


@kopf.on.delete(
    CRD_GROUP,
    CRD_VERSION,
    "postgresusers",
    retries=3,
    backoff=15,
    timeout=120,
)
def user_delete_fn(
    spec: kopf.Spec,
    name: str,
    namespace: str,
    logger: kopf.Logger,
    **_: Any,
) -> None:
    username = spec["username"]
    db = spec["dbName"]
    secret_name = spec["secretName"]
    secret_ns = spec.get("secretNamespace", namespace)

    pg_host, pg_user, pg_password = resolve_connection_params(spec)

    # Revoke schema-level grants on target DB
    try:
        db_conn = connect(pg_host, pg_user, pg_password, dbname=db)
        try:
            db_conn.autocommit = True
            with db_conn.cursor() as cur:
                _revoke_access(cur, username)
        finally:
            db_conn.close()
    except kopf.TemporaryError:
        logger.warning(
            "Could not connect to database %s to revoke grants for %s",
            db,
            username,
        )

    # Revoke CONNECT + drop role
    try:
        conn = connect(pg_host, pg_user, pg_password)
        try:
            conn.autocommit = True
            with conn.cursor() as cur:
                if role_exists(cur, username):
                    cur.execute(
                        sql.SQL("REVOKE CONNECT ON DATABASE {} FROM {}").format(
                            sql.Identifier(db),
                            sql.Identifier(username),
                        ),
                    )
                    cur.execute(
                        sql.SQL("DROP ROLE {}").format(sql.Identifier(username)),
                    )
                    logger.info("Dropped role %s", username)
                else:
                    logger.info("Role %s already absent", username)
        finally:
            conn.close()
    except kopf.TemporaryError:
        logger.warning("Could not connect to drop role %s", username)

    delete_secret(secret_name, secret_ns, logger)


@kopf.timer(
    CRD_GROUP,
    CRD_VERSION,
    "postgresusers",
    interval=300,
    initial_delay=60,
)
def user_check_drift(
    spec: kopf.Spec,
    logger: kopf.Logger,
    **_: Any,
) -> dict[str, Any] | None:
    username = spec["username"]
    db = spec["dbName"]
    access = spec["access"]

    pg_host, pg_user, pg_password = resolve_connection_params(spec)

    conn = connect(pg_host, pg_user, pg_password)
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            role_ok = role_exists(cur, username)
            db_ok = database_exists(cur, db)
    except psycopg2.Error as exc:
        raise kopf.TemporaryError(
            f"Drift check failed: {exc}",
            delay=60,
        ) from exc
    finally:
        conn.close()

    if not role_ok or not db_ok:
        logger.warning(
            "Drift detected: user=%s(%s) database=%s(%s)",
            username,
            role_ok,
            db,
            db_ok,
        )
        return {
            "username": username,
            "database": db,
            "access": access,
            "ready": False,
            "drift": True,
        }

    return None
