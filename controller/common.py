"""Shared helpers for the postgres-provisioner operator."""

from __future__ import annotations

import base64
import os
import secrets
import string
from typing import Any

import kopf
import kubernetes
import psycopg2
import psycopg2.extensions

PG_HOST = os.environ["PG_HOST"]
PG_USER = os.environ["PG_USER"]
PG_PASSWORD = os.environ["PG_PASSWORD"]

VALID_IDENTIFIER_CHARS = set(string.ascii_letters + string.digits + "_")

CRD_GROUP = "pgprovisioner.drewsonne.github.io"
CRD_VERSION = "v1"

_KIND_PLURALS: dict[str, str] = {
    "PostgresDatabase": "postgresdatabases",
    "PostgresUser": "postgresusers",
}


def rand_pw(length: int = 24) -> str:
    """Generate a random password of the given length."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def validate_identifier(value: str) -> None:
    """Raise PermanentError if *value* is not a safe SQL identifier."""
    if not value or not all(c in VALID_IDENTIFIER_CHARS for c in value):
        msg = f"Invalid SQL identifier: {value!r}"
        raise kopf.PermanentError(msg)
    if value[0].isdigit():
        msg = f"SQL identifier must not start with a digit: {value!r}"
        raise kopf.PermanentError(msg)


def resolve_connection_params(
    spec: kopf.Spec,
) -> tuple[str, str, str]:
    """Return (host, user, password) for the target cluster.

    If the CR specifies ``host`` and ``superuserSecret``, read credentials
    from that secret.  Otherwise fall back to the global PG_HOST / PG_USER /
    PG_PASSWORD environment variables.
    """
    override_host = spec.get("host")
    override_secret = spec.get("superuserSecret")
    if override_host and override_secret:
        v1 = kubernetes.client.CoreV1Api()
        try:
            secret = v1.read_namespaced_secret(
                name=override_secret["name"],
                namespace=override_secret["namespace"],
            )
        except kubernetes.client.exceptions.ApiException as exc:
            raise kopf.TemporaryError(
                f"Cannot read superuser secret "
                f"{override_secret['namespace']}/{override_secret['name']}: {exc}",
                delay=30,
            ) from exc
        data = secret.data or {}
        user = base64.b64decode(data["username"]).decode()
        password = base64.b64decode(data["password"]).decode()
        return override_host, user, password
    return PG_HOST, PG_USER, PG_PASSWORD


def connect(
    host: str = PG_HOST,
    user: str = PG_USER,
    password: str = PG_PASSWORD,
    dbname: str = "postgres",
) -> psycopg2.extensions.connection:
    """Open an autocommit connection, retrying via TemporaryError on failure.

    connect_timeout=10 ensures a dead host fails fast rather than hanging
    the handler thread for the OS TCP timeout (often minutes).
    """
    try:
        return psycopg2.connect(
            host=host,
            user=user,
            password=password,
            dbname=dbname,
            connect_timeout=10,
        )
    except psycopg2.OperationalError as exc:
        raise kopf.TemporaryError(
            f"Cannot connect to PostgreSQL at {host}: {exc}",
            delay=30,
        ) from exc


def database_exists(
    cur: psycopg2.extensions.cursor,
    name: str,
) -> bool:
    """Check whether the named database exists."""
    cur.execute("SELECT 1 FROM pg_database WHERE datname=%s", (name,))
    return cur.fetchone() is not None


def role_exists(cur: psycopg2.extensions.cursor, name: str) -> bool:
    """Check whether the named role exists."""
    cur.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (name,))
    return cur.fetchone() is not None


def ensure_role(
    cur: psycopg2.extensions.cursor,
    role: str,
    password: str,
) -> None:
    """Create or update a LOGIN role with the given password."""
    from psycopg2 import sql as pgsql

    if not role_exists(cur, role):
        cur.execute(
            pgsql.SQL("CREATE ROLE {} LOGIN PASSWORD %s").format(
                pgsql.Identifier(role),
            ),
            (password,),
        )
    else:
        cur.execute(
            pgsql.SQL("ALTER ROLE {} PASSWORD %s").format(
                pgsql.Identifier(role),
            ),
            (password,),
        )


def get_existing_password(
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


def ensure_secret(
    namespace: str,
    secret_name: str,
    body: kopf.Body,
    data: dict[str, str],
    logger: kopf.Logger,
) -> None:
    """Create or update a Kubernetes Secret with the supplied data.

    Skips the patch if the secret already exists with identical values to
    avoid churning the secret's resourceVersion, which would require pod
    restarts to pick up the new env vars.
    """
    v1 = kubernetes.client.CoreV1Api()
    secret_body = kubernetes.client.V1Secret(
        metadata=kubernetes.client.V1ObjectMeta(name=secret_name),
        string_data=data,
    )
    # Owner references cannot cross namespaces
    cr_namespace = body["metadata"]["namespace"]
    if namespace == cr_namespace:
        kopf.adopt(secret_body)

    try:
        v1.create_namespaced_secret(namespace=namespace, body=secret_body)
        logger.info("Created secret %s", secret_name)
    except kubernetes.client.exceptions.ApiException as exc:
        if exc.status == 409:
            existing = v1.read_namespaced_secret(name=secret_name, namespace=namespace)
            existing_data = {
                k: base64.b64decode(v).decode()
                for k, v in (existing.data or {}).items()
            }
            if existing_data == data:
                logger.debug(
                    "Secret %s already up-to-date, skipping patch", secret_name
                )
                return
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


def secret_data(
    user: str,
    password: str,
    db: str,
    host: str = PG_HOST,
) -> dict[str, str]:
    """Build the dict used as Secret stringData."""
    return {
        "username": user,
        "password": password,
        "database": db,
        "host": host,
        "port": "5432",
    }


def delete_secret(
    secret_name: str,
    secret_ns: str,
    logger: kopf.Logger,
) -> None:
    """Delete a Kubernetes Secret, ignoring 404."""
    v1 = kubernetes.client.CoreV1Api()
    try:
        v1.delete_namespaced_secret(name=secret_name, namespace=secret_ns)
        logger.info("Deleted secret %s", secret_name)
    except kubernetes.client.exceptions.ApiException as exc:
        if exc.status != 404:
            raise kopf.TemporaryError(
                f"Failed to delete secret: {exc}",
                delay=15,
            ) from exc
        logger.info("Secret %s already absent", secret_name)


def set_database_owner_reference(
    body: kopf.Body,
    namespace: str,
    db_name: str,
    logger: kopf.Logger,
) -> None:
    """Patch this CR's ownerReferences to point to the matching PostgresDatabase.

    Enables K8s GC to cascade-delete PostgresUser CRs when the PostgresDatabase
    CR is removed. Silently skips if no matching PostgresDatabase is found.
    """
    custom = kubernetes.client.CustomObjectsApi()
    try:
        db_list = custom.list_namespaced_custom_object(
            group=CRD_GROUP,
            version=CRD_VERSION,
            namespace=namespace,
            plural="postgresdatabases",
        )
    except kubernetes.client.exceptions.ApiException as exc:
        logger.warning("Could not list PostgresDatabase objects: %s", exc)
        return

    db_obj = next(
        (
            d
            for d in db_list.get("items", [])
            if d.get("spec", {}).get("dbName") == db_name
        ),
        None,
    )
    if db_obj is None:
        logger.debug(
            "No PostgresDatabase found for dbName=%r in namespace %s"
            " — skipping owner ref",
            db_name,
            namespace,
        )
        return

    owner_uid = db_obj["metadata"]["uid"]
    existing_owners: list[dict[str, Any]] = body.get("metadata", {}).get(
        "ownerReferences", []
    )
    if any(o.get("uid") == owner_uid for o in existing_owners):
        return  # already set

    owner_ref = {
        "apiVersion": f"{CRD_GROUP}/{CRD_VERSION}",
        "kind": "PostgresDatabase",
        "name": db_obj["metadata"]["name"],
        "uid": owner_uid,
        "blockOwnerDeletion": True,
        "controller": True,
    }
    cr_name = body["metadata"]["name"]
    cr_plural = _KIND_PLURALS.get(str(body.get("kind", "")), "")

    try:
        custom.patch_namespaced_custom_object(
            group=CRD_GROUP,
            version=CRD_VERSION,
            namespace=namespace,
            plural=cr_plural,
            name=cr_name,
            body={"metadata": {"ownerReferences": [owner_ref]}},
        )
        logger.info(
            "Set ownerReference: %s/%s → PostgresDatabase/%s",
            cr_plural,
            cr_name,
            db_obj["metadata"]["name"],
        )
    except kubernetes.client.exceptions.ApiException as exc:
        logger.warning("Failed to set ownerReference: %s", exc)
