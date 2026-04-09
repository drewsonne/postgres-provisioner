import kopf
import psycopg2
import os
import kubernetes
import secrets
import string

PG_HOST = os.environ["PG_HOST"]
PG_USER = os.environ["PG_USER"]
PG_PASSWORD = os.environ["PG_PASSWORD"]

def rand_pw():
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(16))

def connect():
    return psycopg2.connect(
        host=PG_HOST,
        user=PG_USER,
        password=PG_PASSWORD,
        dbname="postgres"
    )

def database_exists(cur, name):
    cur.execute("SELECT 1 FROM pg_database WHERE datname=%s", (name,))
    return cur.fetchone() is not None

def role_exists(cur, name):
    cur.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (name,))
    return cur.fetchone() is not None

@kopf.on.create('db.example.com', 'v1', 'postgresdatabases')
def create_fn(spec, name, namespace, **kwargs):
    db = spec['dbName']
    user = spec['owner']
    secret_name = spec['secretName']

    password = rand_pw()

    conn = connect()
    conn.autocommit = True
    cur = conn.cursor()

    if not role_exists(cur, user):
        cur.execute(f"CREATE ROLE {user} LOGIN PASSWORD %s", (password,))

    if not database_exists(cur, db):
        cur.execute(f"CREATE DATABASE {db} OWNER {user}")

    cur.close()
    conn.close()

    v1 = kubernetes.client.CoreV1Api()

    try:
        v1.create_namespaced_secret(
            namespace=namespace,
            body=kubernetes.client.V1Secret(
                metadata={"name": secret_name},
                string_data={
                    "username": user,
                    "password": password,
                    "database": db,
                    "host": PG_HOST,
                    "port": "5432"
                }
            )
        )
    except Exception:
        # update if exists
        v1.patch_namespaced_secret(
            name=secret_name,
            namespace=namespace,
            body={"stringData": {
                "username": user,
                "password": password,
                "database": db,
                "host": PG_HOST,
                "port": "5432"
            }}
        )