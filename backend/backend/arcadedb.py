"""ArcadeDB HTTP client and hardcoded schema DDL for BeaconGraph's node/relationship model.

Unlike Neo4j, ArcadeDB vertices belong to exactly one type, arranged in a single-inheritance
hierarchy (CREATE VERTEX TYPE ... EXTENDS ...) - there is no equivalent of Neo4j's freeform
multi-label tagging. BeaconGraph's Neo4j writes give every node a specific type (e.g. WPA2)
plus a generic "Device" label; here "Device" is instead a real root vertex type that every
specific type extends, so a node is written under its single specific type and MATCH (n:Device)
still matches it polymorphically via inheritance.

BeaconGraph's schema is small and fixed (7 types + 1 root, 2 edge types), so unlike a larger
schema with many resource types, no YAML-driven schema registry is needed here - the DDL is
just a handful of hardcoded statement-generator functions. It is not flat, though: the five
encryption types extend `AP`, which extends the root, so the hierarchy here has to stay in
step with `pcap/data/schema.yaml` whenever it changes. Both CLIs write the same database and
whichever runs first on an empty one establishes the type hierarchy for both.
"""
import json

import requests
from loguru import logger

ROOT_LABEL = "Device"
VERTEX_LABELS = ("AP", "Client", "Open", "WEP", "WPA", "WPA2", "WPA3")
#: The encryption types extend `AP` rather than the root, so `MATCH (a:AP)` means "every
#: access point". `AP` stays concrete as well as a parent - it is what a BSSID is written as
#: when nothing could be determined about its encryption (`_classifyBssid`'s else branch
#: here, `crypto.py`'s node_type fallback on the pcap path). Kept in step with
#: `pcap/data/schema.yaml`, which `tests/test_schema.py` asserts statement for statement.
AP_SUBTYPES = ("Open", "WEP", "WPA", "WPA2", "WPA3")
EDGE_TYPES = ("Associated", "Probes")
ID_PROPERTY = "id"


def _root_children() -> list:
    return sorted(set(VERTEX_LABELS) - set(AP_SUBTYPES))


def type_statements() -> list:
    """CREATE VERTEX TYPE DDL, root first then children (a type cannot extend a parent that
    does not exist yet)."""
    statements = [f"CREATE VERTEX TYPE `{ROOT_LABEL}` IF NOT EXISTS;"]
    for label in _root_children():
        statements.append(f"CREATE VERTEX TYPE `{label}` IF NOT EXISTS EXTENDS `{ROOT_LABEL}`;")
    for label in sorted(AP_SUBTYPES):
        statements.append(f"CREATE VERTEX TYPE `{label}` IF NOT EXISTS EXTENDS `AP`;")
    return statements


def property_statements(id_property: str = ID_PROPERTY) -> list:
    """Declare the indexed id property once on the root type; every child type inherits it."""
    return [f"CREATE PROPERTY `{ROOT_LABEL}`.{id_property} IF NOT EXISTS STRING;"]


def index_statements(id_property: str = ID_PROPERTY) -> list:
    """CREATE INDEX DDL, children first then the root last. ArcadeDB rejects an index on a
    subtype once an ancestor already owns one on the same property, so every level can only be
    indexed when the DDL runs deepest-first."""
    ordered = sorted(AP_SUBTYPES) + _root_children() + [ROOT_LABEL]
    return [
        f"CREATE INDEX IF NOT EXISTS ON `{label}` ({id_property}) NOTUNIQUE;"
        for label in ordered
    ]


def edge_type_statements() -> list:
    return [f"CREATE EDGE TYPE `{edge_type}` IF NOT EXISTS;" for edge_type in EDGE_TYPES]


class ArcadeDBError(Exception):
    """Raised when the ArcadeDB HTTP API rejects a command. `payload` carries the parsed JSON
    error body when the server returned one."""

    def __init__(self, message, payload: dict = None):
        super().__init__(message)
        self.payload = payload or {}


class ArcadeDBClient:
    """Thin wrapper over the ArcadeDB HTTP command/batch endpoints."""

    def __init__(self, uri: str, database: str, user: str, password: str, insecure: bool = False):
        self.uri = uri.rstrip("/")
        self.database = database
        self.session = requests.Session()
        self.session.auth = (user, password)
        self.session.headers.update({"Content-Type": "application/json"})
        self.verify = not insecure

    def command(self, statement: str, language: str = "sql") -> dict:
        """Run one statement, raising ArcadeDBError on a non-2xx response."""
        response = self.session.post(
            f"{self.uri}/api/v1/command/{self.database}",
            json={"language": language, "command": statement.rstrip(";")},
            verify=self.verify,
            timeout=300,
        )
        if response.status_code >= 300:
            raise ArcadeDBError(f"{statement.rstrip(';')} -> {response.text[:400]}")
        return response.json()

    def verify_connectivity(self) -> None:
        self.command("SELECT 1")

    def apply(self, statements: list, label: str) -> int:
        """Run a list of DDL statements, returning the number that failed."""
        failed = 0
        for statement in statements:
            try:
                self.command(statement)
            except ArcadeDBError as err:
                failed += 1
                logger.error(f"{label} statement failed: {err}")

        if failed:
            logger.warning(f"{failed} of {len(statements)} {label} statement(s) failed")
        return failed

    def count_nodes(self, label: str) -> int:
        """How many vertices of the given type the database holds. A brand-new database has no
        types declared yet, so that case is reported as 0 rather than raised."""
        try:
            result = self.command(f"SELECT count(*) AS total FROM `{label}`")
        except ArcadeDBError as err:
            if "was not found" in str(err):
                return 0
            raise

        rows = result.get("result") or [{}]
        return int(rows[0].get("total", 0))

    def indexed_labels(self, id_property: str = ID_PROPERTY) -> set:
        """Every declared type that owns its *own* index on the given property.

        Needed because a blocked index cannot be detected from the DDL's result. ArcadeDB
        rejects an index on a type whose ancestor already indexes the property, but only for
        the bare form - with IF NOT EXISTS it treats the ancestor's index as satisfying the
        request and returns success without creating anything. A type added to the schema
        after the database was built therefore ends up silently unindexed, and every edge
        write that matches on it degrades to a scan. Callers must compare this against the
        schema rather than watching for an error.
        """
        result = self.command("SELECT name, indexes FROM schema:types")
        return {
            entry["name"]
            for entry in result.get("result", [])
            for index in (entry.get("indexes") or [])
            if index.get("name", "").endswith(f"[{id_property}]")
        }

    def vertex_parents(self) -> dict:
        """Every declared vertex type mapped to the parent types it actually extends.

        The hierarchy counterpart to ``indexed_labels()``, and needed for the same reason:
        ``CREATE VERTEX TYPE ... IF NOT EXISTS EXTENDS ...`` against a type that already
        exists returns ``created: false`` and leaves the existing parents untouched. A
        release that re-parents a type therefore has no effect on a database built before
        it, silently, and the only way to notice is to read back what the database holds.
        """
        result = self.command("SELECT name, type, parentTypes FROM schema:types")
        return {
            entry["name"]: list(entry.get("parentTypes") or [])
            for entry in result.get("result", [])
            if entry.get("type") == "vertex"
        }

    def declare_edge_types(self, edge_types) -> int:
        statements = [f"CREATE EDGE TYPE `{t}` IF NOT EXISTS;" for t in sorted(edge_types)]
        return len(statements) - self.apply(statements, "edge type")

    def batch_import(self, records, expected_edges: int = 0) -> dict:
        """Bulk-load vertices and edges through the batch endpoint. `records` is streamed as
        newline-delimited JSON. This endpoint inserts unconditionally (no match-or-create), so
        it is only safe against a database that holds no BeaconGraph data yet."""
        def stream():
            for record in records:
                yield json.dumps(record, default=str).encode() + b"\n"

        params = {"expectedEdgeCount": expected_edges} if expected_edges else None
        response = self.session.post(
            f"{self.uri}/api/v1/batch/{self.database}",
            data=stream(),
            params=params,
            headers={"Content-Type": "application/x-ndjson"},
            verify=self.verify,
            timeout=3600,
        )
        if response.status_code >= 300:
            try:
                payload = response.json()
            except ValueError:
                payload = {}
            raise ArcadeDBError(payload.get("error") or response.text[:400], payload)

        try:
            return response.json()
        except ValueError:
            return {}
