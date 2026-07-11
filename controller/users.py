"""Kopf handlers for the PostgresUser CRD."""

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
    require_namespace,
    resolve_connection_params,
    role_exists,
    secret_data,
    set_database_owner_reference,
    validate_identifier,
)
from psycopg2 import sql

_VALID_ACCESS = frozenset({"read", "readwrite"})


def _validate_access(access: str) -> None:
    if access not in _VALID_ACCESS:
        msg = f"Invalid access level {access!r}; must be one of {sorted(_VALID_ACCESS)}"
        raise kopf.PermanentError(msg)


def _list_user_schemas(cur: psycopg2.extensions.cursor) -> list[str]:
    """Return all non-system schema names in the current database."""
    cur.execute(
        "SELECT nspname FROM pg_namespace "
        "WHERE nspname NOT LIKE 'pg_%' "
        "AND nspname != 'information_schema'",
    )
    return [row[0] for row in cur.fetchall()]


def _schema_owners(
    cur: psycopg2.extensions.cursor,
    schema_name: str,
) -> list[str]:
    """Return distinct owner role names that own objects in *schema_name*."""
    cur.execute(
        "SELECT DISTINCT pg_get_userbyid(relowner) "
        "FROM pg_class c JOIN pg_namespace n ON c.relnamespace = n.oid "
        "WHERE n.nspname = %s",
        (schema_name,),
    )
    return [row[0] for row in cur.fetchall()]


def _grant_access(
    cur: psycopg2.extensions.cursor,
    username: str,
    access: str,
    schemas: list[str] | None = None,
) -> None:
    """Grant schema-level privileges on the connected database.

    Must be called on a connection to the *target* database (not ``postgres``).
    If *schemas* is ``None``, grants on all user schemas.

    Sets ``ALTER DEFAULT PRIVILEGES`` both for the current user *and* for every
    role that already owns objects in each schema so that future objects created
    by any of those roles are automatically accessible.
    """
    role = sql.Identifier(username)
    if schemas is None:
        schemas = _list_user_schemas(cur)

    for schema_name in schemas:
        schema = sql.Identifier(schema_name)
        owners = _schema_owners(cur, schema_name)
        cur.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(schema, role))

        if access == "read":
            cur.execute(
                sql.SQL(
                    "GRANT SELECT ON ALL TABLES IN SCHEMA {} TO {}",
                ).format(schema, role),
            )
            cur.execute(
                sql.SQL(
                    "ALTER DEFAULT PRIVILEGES IN SCHEMA {} "
                    "GRANT SELECT ON TABLES TO {}",
                ).format(schema, role),
            )
            for owner in owners:
                cur.execute(
                    sql.SQL(
                        "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA {} "
                        "GRANT SELECT ON TABLES TO {}",
                    ).format(sql.Identifier(owner), schema, role),
                )
        else:
            # readwrite
            cur.execute(
                sql.SQL("GRANT CREATE ON SCHEMA {} TO {}").format(schema, role),
            )
            cur.execute(
                sql.SQL(
                    "GRANT SELECT, INSERT, UPDATE, DELETE "
                    "ON ALL TABLES IN SCHEMA {} TO {}",
                ).format(schema, role),
            )
            cur.execute(
                sql.SQL(
                    "GRANT USAGE ON ALL SEQUENCES IN SCHEMA {} TO {}",
                ).format(schema, role),
            )
            cur.execute(
                sql.SQL(
                    "ALTER DEFAULT PRIVILEGES IN SCHEMA {} "
                    "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {}",
                ).format(schema, role),
            )
            cur.execute(
                sql.SQL(
                    "ALTER DEFAULT PRIVILEGES IN SCHEMA {} "
                    "GRANT USAGE ON SEQUENCES TO {}",
                ).format(schema, role),
            )
            for owner in owners:
                cur.execute(
                    sql.SQL(
                        "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA {} "
                        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {}",
                    ).format(sql.Identifier(owner), schema, role),
                )
                cur.execute(
                    sql.SQL(
                        "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA {} "
                        "GRANT USAGE ON SEQUENCES TO {}",
                    ).format(sql.Identifier(owner), schema, role),
                )


def _revoke_access(
    cur: psycopg2.extensions.cursor,
    username: str,
    schemas: list[str] | None = None,
) -> None:
    """Revoke all schema-level privileges on the connected database.

    If *schemas* is ``None``, revokes on all user schemas.
    """
    role = sql.Identifier(username)
    if schemas is None:
        schemas = _list_user_schemas(cur)

    for schema_name in schemas:
        schema = sql.Identifier(schema_name)
        owners = _schema_owners(cur, schema_name)
        cur.execute(
            sql.SQL(
                "ALTER DEFAULT PRIVILEGES IN SCHEMA {} REVOKE ALL ON TABLES FROM {}",
            ).format(schema, role),
        )
        cur.execute(
            sql.SQL(
                "ALTER DEFAULT PRIVILEGES IN SCHEMA {} REVOKE ALL ON SEQUENCES FROM {}",
            ).format(schema, role),
        )
        for owner in owners:
            cur.execute(
                sql.SQL(
                    "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA {} "
                    "REVOKE ALL ON TABLES FROM {}",
                ).format(sql.Identifier(owner), schema, role),
            )
            cur.execute(
                sql.SQL(
                    "ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA {} "
                    "REVOKE ALL ON SEQUENCES FROM {}",
                ).format(sql.Identifier(owner), schema, role),
            )
        cur.execute(
            sql.SQL("REVOKE ALL ON ALL TABLES IN SCHEMA {} FROM {}").format(
                schema,
                role,
            ),
        )
        cur.execute(
            sql.SQL("REVOKE ALL ON ALL SEQUENCES IN SCHEMA {} FROM {}").format(
                schema,
                role,
            ),
        )
        cur.execute(
            sql.SQL("REVOKE ALL ON SCHEMA {} FROM {}").format(schema, role),
        )


def _ensure_member_of(
    cur: psycopg2.extensions.cursor,
    username: str,
    member_of: list[str],
    logger: kopf.Logger,
) -> None:
    """Ensure *username* is a member of each role in *member_of*.

    Idempotent — skips roles that don't exist yet (they may be created later)
    and roles the user is already a member of.
    """
    for parent_role in member_of:
        cur.execute(
            "SELECT 1 FROM pg_roles WHERE rolname = %s",
            (parent_role,),
        )
        if cur.fetchone() is None:
            logger.warning(
                "memberOf role %s does not exist yet; skipping grant",
                parent_role,
            )
            continue
        cur.execute(
            "SELECT 1 FROM pg_auth_members am "
            "JOIN pg_roles r ON am.roleid = r.oid "
            "JOIN pg_roles m ON am.member = m.oid "
            "WHERE r.rolname = %s AND m.rolname = %s",
            (parent_role, username),
        )
        if cur.fetchone() is None:
            cur.execute(
                sql.SQL("GRANT {} TO {}").format(
                    sql.Identifier(parent_role),
                    sql.Identifier(username),
                ),
            )
            logger.info("Granted role %s to %s", parent_role, username)


def _upsert_user(
    spec: kopf.Spec,
    namespace: str,
    body: kopf.Body,
    logger: kopf.Logger,
    *,
    revoke_first: bool = False,
) -> dict[str, Any]:
    """Ensure the user role, CONNECT grant, and schema grants match spec.

    Called from create, resume, and update handlers.
    Set revoke_first=True on updates to clear stale grants before re-applying.
    """
    username = spec["username"]
    db = spec["dbName"]
    access = spec["access"]
    schemas: list[str] | None = spec.get("schemas") or None
    member_of: list[str] = spec.get("memberOf") or []
    secret_name = spec["secretName"]
    secret_ns = spec.get("secretNamespace", namespace)

    validate_identifier(username)
    validate_identifier(db)
    _validate_access(access)
    if schemas is not None:
        for s in schemas:
            validate_identifier(s)
    for r in member_of:
        validate_identifier(r)

    pg_host, pg_user, pg_password = resolve_connection_params(spec)
    password = get_existing_password(secret_ns, secret_name) or rand_pw()

    # Connect to postgres to ensure role + CONNECT grant + role memberships
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
            if member_of:
                _ensure_member_of(cur, username, member_of, logger)
    except psycopg2.Error as exc:
        raise kopf.TemporaryError(f"PostgreSQL error: {exc}", delay=30) from exc
    finally:
        conn.close()

    # Connect to target DB for schema-level grants
    db_conn = connect(pg_host, pg_user, pg_password, dbname=db)
    try:
        db_conn.autocommit = True
        with db_conn.cursor() as cur:
            if revoke_first:
                _revoke_access(cur, username)
            _grant_access(cur, username, access, schemas)
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

    logger.info(
        "Provisioned user=%s db=%s access=%s schemas=%s memberOf=%s",
        username,
        db,
        access,
        schemas,
        member_of,
    )
    return {
        "username": username,
        "database": db,
        "access": access,
        "schemas": schemas,
        "memberOf": member_of,
        "ready": True,
    }


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
    name: str | None,
    namespace: str | None,
    body: kopf.Body,
    logger: kopf.Logger,
    **_: Any,
) -> dict[str, Any]:
    ns = require_namespace(namespace)
    result = _upsert_user(spec, ns, body, logger)
    set_database_owner_reference(body, ns, spec["dbName"], logger)
    return result


@kopf.on.resume(CRD_GROUP, CRD_VERSION, "postgresusers")
def user_resume_fn(
    spec: kopf.Spec,
    name: str | None,
    namespace: str | None,
    body: kopf.Body,
    logger: kopf.Logger,
    **_: Any,
) -> dict[str, Any]:
    """Re-verify and recreate resources if missing on operator restart."""
    ns = require_namespace(namespace)
    result = _upsert_user(spec, ns, body, logger)
    set_database_owner_reference(body, ns, spec["dbName"], logger)
    return result


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
    name: str | None,
    namespace: str | None,
    body: kopf.Body,
    logger: kopf.Logger,
    **_: Any,
) -> dict[str, Any]:
    # revoke_first=True clears stale grants before applying the new access level
    return _upsert_user(
        spec, require_namespace(namespace), body, logger, revoke_first=True
    )


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
    name: str | None,
    namespace: str | None,
    logger: kopf.Logger,
    **_: Any,
) -> None:
    username = spec["username"]
    db = spec["dbName"]
    secret_name = spec["secretName"]
    secret_ns = spec.get("secretNamespace", namespace)

    pg_host, pg_user, pg_password = resolve_connection_params(spec)

    # Reassign owned objects, drop owned, revoke CONNECT, then drop role
    try:
        db_conn = connect(pg_host, pg_user, pg_password, dbname=db)
        try:
            db_conn.autocommit = True
            with db_conn.cursor() as cur:
                if role_exists(cur, username):
                    cur.execute(
                        sql.SQL("REASSIGN OWNED BY {} TO {}").format(
                            sql.Identifier(username),
                            sql.Identifier(pg_user),
                        ),
                    )
                    cur.execute(
                        sql.SQL("DROP OWNED BY {}").format(sql.Identifier(username)),
                    )
        finally:
            db_conn.close()
    except kopf.TemporaryError:
        logger.warning(
            "Could not connect to database %s to reassign owned objects for %s",
            db,
            username,
        )

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


def _drift_check_role(
    pg_host: str,
    pg_user: str,
    pg_password: str,
    username: str,
    db: str,
    password: str,
    member_of: list[str],
    logger: kopf.Logger,
) -> bool | None:
    """Ensure role, CONNECT, and memberOf grants on the postgres DB.

    Returns True if the role was missing (drift detected), False if present,
    or None if the database doesn't exist yet (caller should skip schema grants).
    Raises TemporaryError on any psycopg2 failure.
    """
    conn = connect(pg_host, pg_user, pg_password)
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            if not database_exists(cur, db):
                return None
            missing = not role_exists(cur, username)
            if missing:
                logger.warning("Drift detected: role %s missing; repairing", username)
            ensure_role(cur, username, password)
            cur.execute(
                sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                    sql.Identifier(db),
                    sql.Identifier(username),
                ),
            )
            if member_of:
                _ensure_member_of(cur, username, member_of, logger)
    except psycopg2.Error as exc:
        raise kopf.TemporaryError(f"Drift check failed: {exc}", delay=60) from exc
    finally:
        conn.close()
    return missing


@kopf.timer(
    CRD_GROUP,
    CRD_VERSION,
    "postgresusers",
    interval=300,
    initial_delay=60,
    idle=30,
)
def user_check_drift(
    spec: kopf.Spec,
    name: str | None,
    namespace: str | None,
    body: kopf.Body,
    logger: kopf.Logger,
    **_: Any,
) -> dict[str, Any] | None:
    """Periodically reconcile user grants to repair drift.

    Re-applies role, CONNECT, and schema grants every interval. This catches
    schemas created after the initial CRD creation (e.g. dbt adding a schema)
    and roles that were dropped out-of-band.
    """
    username = spec["username"]
    db = spec["dbName"]
    access = spec["access"]
    schemas: list[str] | None = spec.get("schemas") or None
    member_of: list[str] = spec.get("memberOf") or []
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
        logger.info("dbt build active in %s; skipping user drift check this cycle", db)
        return None

    role_missing = _drift_check_role(
        pg_host,
        pg_user,
        pg_password,
        username,
        db,
        password,
        member_of,
        logger,
    )
    if role_missing is None:
        logger.warning("Database %s missing during drift check; skipping", db)
        return None

    # Re-apply schema grants on target DB
    db_conn = connect(pg_host, pg_user, pg_password, dbname=db)
    try:
        db_conn.autocommit = True
        with db_conn.cursor() as cur:
            if schemas is not None:
                cur.execute(
                    "SELECT nspname FROM pg_namespace WHERE nspname = ANY(%s)",
                    (schemas,),
                )
                existing = [row[0] for row in cur.fetchall()]
                missing_schemas = set(schemas) - set(existing)
                if missing_schemas:
                    logger.info(
                        "Schemas not yet created (will retry next cycle): %s",
                        sorted(missing_schemas),
                    )
            else:
                existing = None
            _grant_access(cur, username, access, existing)
    except psycopg2.Error as exc:
        raise kopf.TemporaryError(
            f"Drift check grant failed on {db}: {exc}",
            delay=60,
        ) from exc
    finally:
        db_conn.close()

    if role_missing:
        logger.warning("Drift repaired: re-created role %s with grants", username)
        return {"drift": True, "driftReason": "role_missing", "ready": True}

    logger.debug("Drift check OK: user=%s db=%s", username, db)
    return None
