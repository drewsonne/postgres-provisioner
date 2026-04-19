# postgres-provisioner

A lightweight Kubernetes operator that provisions PostgreSQL databases and users declaratively via CRDs.

Applications can request their own database, credentials, and schema-level access without manual SQL or shared admin access.

---

## What it does

The operator manages two CRD kinds:

| Kind | What it provisions |
| --- | --- |
| `PostgresDatabase` | A PostgreSQL database and owner role, with credentials stored in a K8s Secret |
| `PostgresUser` | A read-only or read-write user in an existing database, with schema-level grants stored in a K8s Secret |

All resources are reconciled continuously — the operator detects and repairs out-of-band drift every 5 minutes.

---

## Architecture

```
PostgresDatabase
  └── PostgresUser    (ownerRef → Database; cascade-deleted with database)
        └── K8s Secret (ownerRef → CR; GC'd with CR)
```

Deleting a `PostgresDatabase` CR triggers K8s garbage collection of all child `PostgresUser` CRs, which revoke grants and drop roles before the database CR itself is cleaned up.

---

## Installation

Add the Helm repository:

```bash
helm repo add postgres-provisioner https://drewsonne.github.io/postgres-provisioner
helm repo update
```

Install the chart:

```bash
helm install postgres-provisioner postgres-provisioner/postgres-provisioner \
  --namespace app-db \
  --set postgres.host=pg-rw.app-db.svc.cluster.local \
  --set postgres.secretName=pg-superuser
```

---

## Requirements

* A running PostgreSQL cluster accessible from within the cluster
* A Kubernetes Secret containing PostgreSQL superuser credentials:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: pg-superuser
  namespace: app-db
stringData:
  username: postgres
  password: <superuser-password>
```

---

## Configuration

Default values:

```yaml
image:
  repository: drewsonne/postgres-provisioner
  tag: latest

postgres:
  host: pg-rw.app-db.svc.cluster.local
  secretName: pg-superuser

namespace: app-db
```

---

## Usage

### PostgresDatabase

Creates a PostgreSQL database, an owner role, and a K8s Secret with connection credentials.

```yaml
apiVersion: pgprovisioner.drewsonne.github.io/v1
kind: PostgresDatabase
metadata:
  name: my-app-db
  namespace: app-db
spec:
  dbName: my_app
  owner: my_app_owner
  secretName: my-app-db-credentials
  secretNamespace: my-app        # optional; defaults to CR namespace
```

### PostgresUser

Creates a login role with `read` or `readwrite` access to an existing database. Grants are applied at the schema level (not just database level), including `ALTER DEFAULT PRIVILEGES` for future tables.

```yaml
apiVersion: pgprovisioner.drewsonne.github.io/v1
kind: PostgresUser
metadata:
  name: my-app-reader
  namespace: app-db
spec:
  username: my_app_reader
  dbName: my_app
  access: read                   # read | readwrite
  schemas:                       # optional; defaults to all user schemas
    - public
    - analytics
  secretName: my-app-reader-credentials
  secretNamespace: my-app        # optional; defaults to CR namespace
```

`access` values:

| Value | Grants |
| --- | --- |
| `read` | `USAGE` on schemas, `SELECT` on all tables, `ALTER DEFAULT PRIVILEGES` for SELECT |
| `readwrite` | `USAGE + CREATE` on schemas, `SELECT/INSERT/UPDATE/DELETE` on tables, `USAGE` on sequences, `ALTER DEFAULT PRIVILEGES` for DML + sequences |

---

## Per-CR credential override

Every CR accepts an optional `host` and `superuserSecret` to use a different PostgreSQL cluster (useful for multi-tenant setups):

```yaml
spec:
  host: other-pg-rw.other-ns.svc.cluster.local
  superuserSecret:
    name: other-pg-superuser
    namespace: other-ns
```

---

## Output

Both CRDs create a Secret containing:

* `username` — the PostgreSQL role name
* `password` — the role password
* `database` — the target database name
* `host` — the PostgreSQL host
* `port` — `5432`

```bash
kubectl get secret my-app-db-credentials -n my-app -o yaml
```

---

## Behaviour notes

* **Idempotent** — safe to reapply; existing PostgreSQL resources are updated, not recreated
* **Secret preservation** — if a Secret already exists, the `password` is preserved rather than regenerated
* **Database safety** — deleting a `PostgresDatabase` CR removes the K8s Secret but intentionally does NOT drop the PostgreSQL database or owner role, preventing accidental data loss
* **User deletion** — deleting a `PostgresUser` CR revokes all schema grants, revokes `CONNECT`, drops the role, and removes the Secret
* **Schema-level grants** — `PostgresUser` grants are applied per-schema with `ALTER DEFAULT PRIVILEGES`, so future tables created in the schema are automatically accessible
* **Drift detection** — a timer runs every 5 minutes to detect and repair out-of-band changes (e.g. manually dropped roles); drift is visible in `kubectl describe` as a K8s Warning event and in the `Drift` printer column
* **Cascade deletion** — deleting a `PostgresDatabase` CR triggers cleanup of all child `PostgresUser` CRs before the database CR is finalised
* **User/database ordering** — if a `PostgresUser` references a database that doesn't exist yet, the controller retries automatically until it is ready

---

## Observability

```bash
kubectl get postgresdatabases
kubectl get postgresusers
```

Printer columns include `Ready`, `Drift`, and `Age`. Drift events are also emitted as Kubernetes Warning events visible via `kubectl describe`.

---

## Development

Build locally:

```bash
docker build -t drewsonne/postgres-provisioner:dev .
```

Run locally (requires a reachable PostgreSQL instance):

```bash
docker run --rm \
  -e PG_HOST=pg-rw.app-db.svc.cluster.local \
  -e PG_USER=postgres \
  -e PG_PASSWORD=... \
  drewsonne/postgres-provisioner:dev
```

---

## License

MIT
