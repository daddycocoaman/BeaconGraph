"""Schema registry - the single source of truth for the pcap path's graph types.

Parsed from ``pcap/data/schema.yaml``, where nesting under ``children`` *is* the inheritance
lineage. Generates the per-backend DDL that BeaconGraph previously hardcoded in
``backend/backend/arcadedb.py``, plus the Neo4j index statements that
``backend.db.Neo4j.create_indexes()`` was supposed to produce but does not (it filters on the
substring ``"NODE_LABEL"`` while ``labels.py`` names most of its constants ``*_NODE_LEVEL``,
so only ``Client`` and ``WEP`` are ever indexed and ``Device`` - the label every relationship
endpoint matches - is not indexed at all).

Two ordering rules are load-bearing and run in opposite directions:

- ``type_order()`` is ancestors-first. A type cannot extend a parent that does not exist yet.
- ``index_order()`` is deepest-first. ArcadeDB rejects an index on a subtype once an ancestor
  owns one on the same property, so every level can only be indexed when the DDL runs
  descendants-before-ancestors. Neo4j wants the same order for a different reason: it uses
  index creation order for browser caption priority, and the root label should lose that
  contest to every more specific label.

The second rule has a trap that ``index_repair_plan()`` exists for: with ``IF NOT EXISTS``,
ArcadeDB treats an ancestor's index as satisfying a request for a subtype index and returns
success *without creating anything*. A label added to the schema after a database was built
therefore ends up silently unindexed, and no error is raised. Detecting it requires comparing
against what the database actually holds (``ArcadeDBClient.indexed_labels()``), not watching
for failures.

Modelled on Foxhound/Vortex's ``vortex/model/schema.py``, minus its ``state_derived`` concept
(BeaconGraph has no labels computed from mutable external state) and plus edge types, which
Vortex derives from code because its schema describes vertices only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

import yaml

SCHEMA_FILENAME = "schema.yaml"
ID_PROPERTY = "id"


class SchemaError(Exception):
    """Raised when schema.yaml is malformed or internally inconsistent."""


@dataclass(frozen=True)
class Vertex:
    """One declared node label."""

    label: str
    icon_type: str
    icon_name: str
    color: str
    parents: tuple = ()       # nesting parent first, then any `extends` targets
    abstract: bool = False    # declared and indexed, never a node's own type
    depth: int = 0            # longest path from a root, used for DDL ordering

    @property
    def icon(self) -> dict:
        return {"type": self.icon_type, "name": self.icon_name, "color": self.color}


@dataclass
class Schema:
    """Parsed schema.yaml with lineage and per-backend DDL generation."""

    version: int
    vertices: dict = field(default_factory=dict)
    edges: tuple = ()
    source: Path = None

    # -- lookups ----------------------------------------------------------

    def __contains__(self, label: str) -> bool:
        return label in self.vertices

    def __getitem__(self, label: str) -> Vertex:
        return self.vertices[label]

    def get(self, label: str):
        return self.vertices.get(label)

    def labels(self) -> tuple:
        """Every declared label, alphabetically."""
        return tuple(sorted(self.vertices))

    def concrete_labels(self) -> tuple:
        """Labels a node may be emitted as - everything not marked abstract."""
        return tuple(l for l in self.labels() if not self.vertices[l].abstract)

    def children(self, label: str) -> tuple:
        """Direct subtypes of the given label, alphabetically."""
        return tuple(sorted(l for l, v in self.vertices.items() if label in v.parents))

    @property
    def root(self) -> str:
        """The single parentless label. Both backends assume exactly one."""
        roots = [l for l, v in self.vertices.items() if not v.parents]
        if len(roots) != 1:
            raise SchemaError(f"Expected exactly one root label, found {sorted(roots)}")
        return roots[0]

    # -- lineage ----------------------------------------------------------

    def lineage(self, label: str) -> tuple:
        """The label plus every ancestor, most-specific first, root last.

        Linearized breadth-first over `parents` order, so a vertex's nesting parent always
        precedes anything it additionally extends.
        """
        if label not in self.vertices:
            raise SchemaError(f"Unknown label: {label}")

        ordered, seen, queue = [], set(), [label]
        while queue:
            current = queue.pop(0)
            if current in seen:
                continue
            seen.add(current)
            ordered.append(current)
            queue.extend(p for p in self.vertices[current].parents if p not in seen)

        return tuple(ordered)

    def ancestors(self, label: str) -> tuple:
        """Every strict ancestor of the label, most-specific first."""
        return self.lineage(label)[1:]

    def index_order(self) -> tuple:
        """Labels deepest-first - every descendant before any of its ancestors."""
        return tuple(sorted(self.vertices, key=lambda l: (-self.vertices[l].depth, l)))

    def type_order(self) -> tuple:
        """Labels ancestors-first, for CREATE VERTEX TYPE ... EXTENDS.

        The inverse of index_order(): a type cannot extend a parent that does not exist yet,
        while an index cannot be created once an ancestor already owns one on the property.
        """
        return tuple(sorted(self.vertices, key=lambda l: (self.vertices[l].depth, l)))

    # -- generated artifacts ----------------------------------------------

    def icons_payload(self) -> dict:
        """Per-label styling, keyed by label.

        Carried here so the frontend's hand-maintained NODE_LABELS map
        (frontend/src/cy-config.js) can eventually be generated from the same source.
        Not wired up yet - the frontend styles on the `Type` property while the pcap path
        writes `node_type`, so generating it today would style nothing.
        """
        return {label: self.vertices[label].icon for label in self.labels()}

    def neo4j_index_statements(self, id_property: str = ID_PROPERTY) -> list:
        """CREATE INDEX statements, deepest-first."""
        return [
            f"CREATE INDEX IF NOT EXISTS FOR (n:`{label}`) ON (n.{id_property});"
            for label in self.index_order()
        ]

    def arcadedb_type_statements(self) -> list:
        """CREATE VERTEX TYPE ... EXTENDS DDL, ancestors-first."""
        statements = []
        for label in self.type_order():
            parents = self.vertices[label].parents
            clause = f" EXTENDS {', '.join(f'`{p}`' for p in parents)}" if parents else ""
            statements.append(f"CREATE VERTEX TYPE `{label}` IF NOT EXISTS{clause};")
        return statements

    def arcadedb_property_statements(self, id_property: str = ID_PROPERTY) -> list:
        """Declare the indexed property on the root type.

        ArcadeDB requires a property to exist before it can be indexed, unlike Cypher's
        implicit schema-on-write. Declaring it once on the root is enough - every other type
        descends from it and inherits the declaration.
        """
        return [f"CREATE PROPERTY `{self.root}`.{id_property} IF NOT EXISTS STRING;"]

    def arcadedb_index_statements(self, id_property: str = ID_PROPERTY) -> list:
        """Native SQL index DDL, deepest-first."""
        return [
            f"CREATE INDEX IF NOT EXISTS ON `{label}` ({id_property}) NOTUNIQUE;"
            for label in self.index_order()
        ]

    def arcadedb_edge_statements(self) -> list:
        """CREATE EDGE TYPE DDL, alphabetically."""
        return [f"CREATE EDGE TYPE `{edge}` IF NOT EXISTS;" for edge in sorted(self.edges)]

    def index_repair_plan(self, indexed: set, id_property: str = ID_PROPERTY) -> tuple:
        """Work out how to add indexes an existing database is missing.

        ArcadeDB refuses an index on a type whose ancestor already owns one, so a label
        introduced by a later release cannot simply be added - the blocking ancestors have to
        be dropped and rebuilt around it. Returns ``(blocked, statements)``; an empty first
        element means the missing indexes can be created directly with no rebuild.

        ``indexed`` is the set of labels that currently own an id index in the target
        database, as reported by ``ArcadeDBClient.indexed_labels()``.
        """
        missing = [l for l in self.index_order() if l not in indexed]

        blocking, blocked = set(), []
        for label in missing:
            ancestors = {a for a in self.ancestors(label) if a in indexed}
            if ancestors:
                blocked.append(label)
                blocking |= ancestors

        # Drop the blockers shallowest-first, then rebuild everything deepest-first so no
        # ancestor is ever back in place before one of its descendants.
        drops = [
            f"DROP INDEX `{label}[{id_property}]`;"
            for label in sorted(blocking, key=lambda l: (self.vertices[l].depth, l))
        ]
        rebuild = sorted(set(missing) | blocking, key=lambda l: (-self.vertices[l].depth, l))
        creates = [
            f"CREATE INDEX IF NOT EXISTS ON `{label}` ({id_property}) NOTUNIQUE;"
            for label in rebuild
        ]

        return blocked, drops + creates

    def hierarchy_repair_plan(self, actual: dict) -> tuple:
        """Work out how to re-parent types an existing database declared differently.

        The hierarchy twin of ``index_repair_plan``, and it exists for an identical reason:
        ``CREATE VERTEX TYPE ... IF NOT EXISTS EXTENDS ...`` against a type that already
        exists returns ``created: false`` and leaves its parents exactly as they were. When
        a release moves a type - as `WPA2` moved from extending `Device` to extending `AP` -
        every database built before it keeps the old shape, no error is raised, and
        ``MATCH (a:AP)`` silently returns nothing for the types that moved.

        ``actual`` is ``{label: [parent, ...]}`` as reported by
        ``ArcadeDBClient.vertex_parents()``. Returns ``(mismatched, statements)``.

        Both directions are emitted. Adding `AP` without removing the now-redundant direct
        `Device` parent would leave a migrated database at ``[Device, AP]`` where a fresh one
        is at ``[AP]`` - harmless to query, but a schema that differs by how it was built is
        one nobody can reason about. Verified against ArcadeDB 26.10: the ALTER is additive,
        keeps every vertex in place, and leaves each type's own id index intact, so unlike an
        index repair it needs no rebuild and nothing is dropped.
        """
        mismatched, statements = [], []
        # Shallowest-first: a parent has to exist at its own correct depth before anything
        # is re-pointed at it.
        for label in self.type_order():
            if label not in actual:
                continue  # not yet created; the CREATE DDL will get it right first time
            want = list(self.vertices[label].parents)
            have = list(actual[label])
            if want == have:
                continue
            mismatched.append(label)
            for parent in want:
                if parent not in have:
                    statements.append(f"ALTER TYPE `{label}` SUPERTYPE +`{parent}`;")
            for parent in have:
                if parent not in want:
                    statements.append(f"ALTER TYPE `{label}` SUPERTYPE -`{parent}`;")

        return mismatched, statements


# -- parsing --------------------------------------------------------------


def _walk(nodes, parent, out: dict, order: list) -> None:
    """Recursively flatten the nested `vertices` tree into label -> raw-entry pairs."""
    if not isinstance(nodes, list):
        raise SchemaError(f"Expected a list of vertices under {parent or 'vertices'}")

    for entry in nodes:
        if not isinstance(entry, dict) or "label" not in entry:
            raise SchemaError(f"Vertex entry missing a label under {parent or 'vertices'}")

        label = entry["label"]
        if label in out:
            raise SchemaError(f"Duplicate label in schema: {label}")

        for required in ("icon_type", "icon_name", "color"):
            if not entry.get(required):
                raise SchemaError(f"{label} is missing required field '{required}'")

        parents = list(entry.get("extends") or [])
        if parent is not None:
            parents.insert(0, parent)

        out[label] = {"entry": entry, "parents": tuple(parents)}
        order.append(label)

        if entry.get("children"):
            _walk(entry["children"], label, out, order)

    return None


def _depths(raw: dict) -> dict:
    """Longest path from a root for each label, so parents always sort before children."""
    depths, resolving = {}, set()

    def resolve(label: str) -> int:
        if label in depths:
            return depths[label]
        if label in resolving:
            raise SchemaError(f"Inheritance cycle detected involving {label}")

        resolving.add(label)
        parents = raw[label]["parents"]
        depths[label] = 1 + max((resolve(p) for p in parents), default=-1)
        resolving.discard(label)
        return depths[label]

    for label in raw:
        resolve(label)

    return depths


def parse(document: dict, source: Path = None) -> Schema:
    """Build a Schema from an already-loaded YAML document."""
    if not isinstance(document, dict):
        raise SchemaError("schema.yaml must be a mapping at the top level")

    version = document.get("version")
    if version is None:
        raise SchemaError("schema.yaml is missing a top-level 'version'")

    raw, order = {}, []
    _walk(document.get("vertices") or [], None, raw, order)

    if not raw:
        raise SchemaError("schema.yaml declares no vertices")

    for label, info in raw.items():
        for parent in info["parents"]:
            if parent not in raw:
                raise SchemaError(f"{label} extends unknown label '{parent}'")

    depths = _depths(raw)

    vertices = {}
    for label, info in raw.items():
        entry = info["entry"]
        vertices[label] = Vertex(
            label=label,
            icon_type=entry["icon_type"],
            icon_name=entry["icon_name"],
            color=entry["color"],
            parents=info["parents"],
            abstract=bool(entry.get("abstract", False)),
            depth=depths[label],
        )

    edges = []
    for entry in document.get("edges") or []:
        if not isinstance(entry, dict) or not entry.get("type"):
            raise SchemaError("Every edge entry needs a 'type'")
        if entry["type"] in edges:
            raise SchemaError(f"Duplicate edge type in schema: {entry['type']}")
        edges.append(entry["type"])

    schema = Schema(version=int(version), vertices=vertices, edges=tuple(edges), source=source)
    schema.root  # raises if the document does not describe a single-rooted hierarchy
    return schema


_CACHE = {}


def load(path=None, refresh: bool = False) -> Schema:
    """Load the schema, caching by resolved path.

    Reads the packaged copy by default, so it resolves under a pipx install and not only from
    a checkout. `path` overrides it, which is what the tests use.
    """
    key = str(path) if path is not None else "<packaged>"

    if not refresh and key in _CACHE:
        return _CACHE[key]

    if path is not None:
        target = Path(path)
        with open(target, "r", encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
        schema = parse(document, source=target)
    else:
        with resources.files("pcap.data").joinpath(SCHEMA_FILENAME).open(
            "r", encoding="utf-8"
        ) as handle:
            document = yaml.safe_load(handle)
        schema = parse(document, source=None)

    _CACHE[key] = schema
    return schema


def check_parity(schema: Schema) -> tuple:
    """Warn when the schema and the backend's own type constants have drifted apart.

    This is the guard the registry exists to provide, and BeaconGraph already has the bug it
    catches: ``backend.db.create_indexes()`` silently indexes only two of seven labels because
    of a ``NODE_LABEL``/``NODE_LEVEL`` naming typo in ``labels.py``. Returns
    ``(missing, extra)`` and only warns - drift is a maintenance problem, not a reason to fail
    an ingest.
    """
    try:
        from backend import arcadedb as backend_arcadedb
    except Exception:
        return set(), set()

    declared = set(schema.labels())
    known = set(backend_arcadedb.VERTEX_LABELS) | {backend_arcadedb.ROOT_LABEL}

    missing = known - declared
    extra = declared - known

    return missing, extra
