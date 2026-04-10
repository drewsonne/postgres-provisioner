# Postgres Provisioner

A lightweight Kubernetes controller that provisions PostgreSQL databases using a Custom Resource Definition (CRD).

It allows applications to declaratively request their own database, user, and credentials without manual SQL or shared admin access.

---

## What it does

When you create a `PostgresDatabase` resource, the controller will:

* Create a PostgreSQL database
* Create a dedicated user/role
* Grant ownership of the database to that user
* Store credentials in a Kubernetes Secret

---

## Architecture

* PostgreSQL cluster (e.g. CloudNativePG)
* This controller (runs in Kubernetes)
* CRD (`PostgresDatabase`)
* Kubernetes Secrets for credentials

---

## Installation

Add the Helm repository:

```bash
helm repo add drewsonne https://drewsonne.github.io/postgres-provisioner
helm repo update
```

Install the chart:

```bash
helm install db-provisioner drewsonne/postgres-provisioner -n app-db
```

---

## Requirements

You must already have:

* A running PostgreSQL cluster
* A superuser Secret accessible in the same namespace

Example (CloudNativePG default):

* Service: `pg-rw.app-db.svc.cluster.local`
* Secret: `pg-superuser`

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

Override with:

```bash
helm install db-provisioner \
  drewsonne/postgres-provisioner \
  -n app-db \
  --set postgres.host=pg-rw.app-db.svc.cluster.local
```

---

## Usage

Create a database:

```yaml
apiVersion: db.example.com/v1
kind: PostgresDatabase
metadata:
  name: example
  namespace: app-db
spec:
  dbName: example_db
  owner: example_user
  secretName: example-secret
```

Apply:

```bash
kubectl apply -f example.yaml
```

---

## Output

The controller will create a Secret:

```bash
kubectl get secret example-secret -n app-db
```

Contents:

* `username`
* `password`
* `database`
* `host`
* `port`

---

## Connecting to the database

Example:

```bash
psql -h pg-rw.app-db.svc.cluster.local \
     -U example_user \
     -d example_db
```

---

## Behaviour notes

* Idempotent: safe to reapply the same resource
* If the Secret exists, it is updated
* Password is regenerated on reconciliation (current behaviour)
* Uses PostgreSQL superuser credentials internally

---

## Limitations (current)

* No delete handling (database is not dropped)
* No password stability (rotates on update)
* No schema-level isolation (database-level only)
* No connection pooling

---

## Development

Build locally:

```bash
docker build -t drewsonne/postgres-provisioner:dev .
```

Run locally (requires cluster access):

```bash
docker run --rm \
  -e PG_HOST=pg-rw.app-db.svc.cluster.local \
  -e PG_USER=postgres \
  -e PG_PASSWORD=... \
  drewsonne/postgres-provisioner:dev
```

---

## Testing

1. Deploy PostgreSQL (e.g. CloudNativePG)
2. Install this chart
3. Apply a `PostgresDatabase` resource
4. Verify:

   * Secret created
   * Database exists
   * User can connect

---

## Roadmap / Improvements

* Connection pooling support
* Multi-cluster / multi-tenant support

---

## License

MIT
