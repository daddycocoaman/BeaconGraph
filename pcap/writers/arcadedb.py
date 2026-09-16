"""ArcadeDB writer: schema DDL from the registry, then bulk NDJSON or Cypher MERGE.

ArcadeDB vertices belong to exactly one type in a single-inheritance hierarchy, so there is
no equivalent of Neo4j's multi-labelling. A node is written under its single specific type
and ``MATCH (n:Device)`` still finds it polymorphically; the dual-role fact that Neo4j
carries as an extra ``Client`` label is carried here - and there - by the ``roles`` property,
so the same query works against both backends.
"""
import itertools

from loguru import logger
from neo4j.exceptions import TransientError

from backend import arcadedb as client_module

from . import chunks
from .. import graph
from ..schema import load as load_schema

DEFAULT_BATCH_SIZE = 1000


class BlockedIndexes(Exception):
    """Raised when declared labels cannot be indexed without a rebuild."""

    def __init__(self, blocked, statements):
        super().__init__(", ".join(sorted(blocked)))
        self.blocked = blocked
        self.statements = statements


def apply_schema(client, rebuild: bool = False, schema=None) -> None:
    """Declare types, properties and indexes, repairing index chains when asked.

    Two silent-drift repairs run here, both against what the database actually holds rather
    than against what the DDL reported. ``_repair_hierarchy`` fixes types an earlier release
    created under a different parent; the index repair below fixes types an ancestor's index
    silently swallowed. Neither failure raises an error of its own.

    The index repair path exists because ArcadeDB's ``CREATE INDEX ... IF NOT EXISTS`` on a subtype
    whose ancestor already indexes the property **returns success without creating
    anything**. A type added to the schema after the database was built therefore ends up
    silently unindexed, and every edge write matching on it degrades to a scan. The only way
    to detect it is to compare the schema against what the database actually holds, which is
    what ``indexed_labels()`` is for.

    Raises BlockedIndexes rather than continuing: an ingest that looks hung is worse than one
    that refuses and says why.
    """
    schema = schema or load_schema()

    client.apply(schema.arcadedb_type_statements(), "type")
    _repair_hierarchy(client, schema)
    client.apply(schema.arcadedb_property_statements(), "property")
    client.apply(schema.arcadedb_edge_statements(), "edge type")

    try:
        indexed = client.indexed_labels()
    except Exception as err:
        logger.debug(f"could not introspect indexes ({err}); applying the full index DDL")
        client.apply(schema.arcadedb_index_statements(), "index")
        return

    blocked, statements = schema.index_repair_plan(indexed)
    if blocked and not rebuild:
        raise BlockedIndexes(blocked, statements)

    if blocked:
        logger.warning(f"Rebuilding index chains for {len(blocked)} label(s): "
                       f"{', '.join(sorted(blocked))}")
    if statements:
        client.apply(statements, "index")


def _repair_hierarchy(client, schema) -> None:
    """Re-parent types an older release created under a different parent.

    Applied automatically rather than gated behind a flag, unlike the index repair. An index
    repair drops and rebuilds, which is expensive and worth refusing over; ``ALTER TYPE ...
    SUPERTYPE`` is additive, leaves every vertex and every index in place, and without it the
    types simply carry the wrong lineage - ``MATCH (a:AP)`` would keep returning nothing on
    the database while working perfectly on a fresh one.
    """
    try:
        actual = client.vertex_parents()
    except Exception as err:
        logger.debug(f"could not introspect the type hierarchy ({err}); leaving it as declared")
        return

    mismatched, statements = schema.hierarchy_repair_plan(actual)
    if not statements:
        return

    logger.warning(f"Re-parenting {len(mismatched)} type(s) declared under a different "
                   f"parent by an earlier release: {', '.join(mismatched)}")
    client.apply(statements, "hierarchy")


def bulk_import(client, nodes, edges) -> bool:
    """Load everything through the batch endpoint in one request.

    ``@id`` is a handle scoped to this single request, so an edge can only reference a vertex
    travelling with it - which is why nothing can be streamed per-chunk the way the merge
    path can. Handles are tracked per real id so an edge whose endpoint id is shared by more
    than one vertex expands to one record per match, mirroring what the Cypher path's
    polymorphic endpoint match does with the same collision.
    """
    vertices = []
    handles_by_id = {}
    handles_by_key = {}

    for node in nodes:
        handle = len(vertices)
        record = {"@type": "v", "@class": node.label, "@id": handle}
        record.update(node.props)
        record["id"] = node.id
        vertices.append(record)
        handles_by_id.setdefault(node.id, []).append(handle)
        handles_by_key.setdefault((node.label, node.id), []).append(handle)

    def endpoints(label, node_id):
        if label == graph.ROOT_LABEL:
            return handles_by_id.get(node_id, [])
        return handles_by_key.get((label, node_id), []) or handles_by_id.get(node_id, [])

    edge_records = []
    for edge in edges:
        for source in endpoints(edge.from_label, edge.from_id):
            for target in endpoints(edge.to_label, edge.to_id):
                record = {"@type": "e", "@class": edge.type, "@from": source, "@to": target}
                record.update(edge.props)
                edge_records.append(record)

    if not vertices and not edge_records:
        logger.warning("Nothing to import")
        return True

    logger.info(f"Importing {len(vertices):,} vertices and {len(edge_records):,} edges")
    try:
        result = client.batch_import(
            itertools.chain(vertices, edge_records), expected_edges=len(edge_records))
    except client_module.ArcadeDBError as err:
        logger.error(f"ArcadeDB bulk import failed: {err}")
        payload = err.payload or {}
        created_v, created_e = payload.get("verticesCreated"), payload.get("edgesCreated")
        if created_v is not None or created_e is not None:
            logger.error(f"{created_v or 0:,} vertices and {created_e or 0:,} edges were "
                         "written before the failure.")
        if payload.get("partialCommit"):
            logger.error("The import committed partially - the target database now holds an "
                         "incomplete graph.")
        logger.error("Re-run with --merge to ingest over Bolt, which matches endpoints as it "
                     "goes and can safely run against the partially loaded graph.")
        return False

    skipped = result.get("linesSkipped") or 0
    if skipped:
        logger.warning(f"ArcadeDB skipped {skipped:,} record(s) during the import")
    return True


def _node_rows(nodes):
    """Group nodes by vertex type - Cypher cannot parameterize a label.

    Keyed on the label alone, unlike the Neo4j writer's ``(label, extra_labels)``: an
    ArcadeDB vertex has exactly one type, and the dual-role fact rides in ``roles`` instead.
    """
    grouped = {}
    for node in nodes:
        grouped.setdefault(node.label, []).append({"id": node.id, "props": node.props})
    return grouped


def _edge_rows(edges):
    """Group edges by statement shape, including whether they carry properties.

    A propertyless edge - every ``Probes``, and ``Broadcasts`` for an AP whose beacon count
    is zero - is written with no ``SET`` clause at all rather than with an empty map, which
    ArcadeDB's partial openCypher need not accept. Keeping that in the key is what lets one
    statement serve a whole group.
    """
    grouped = {}
    for edge in edges:
        has_props = bool(edge.props)
        row = {"from_id": edge.from_id, "to_id": edge.to_id}
        if has_props:
            row["props"] = edge.props
        key = (edge.type, edge.from_label, edge.to_label, has_props)
        grouped.setdefault(key, []).append(row)
    return grouped


def merge_import(driver, database, nodes, edges, batch_size=DEFAULT_BATCH_SIZE) -> dict:
    """Ingest over Bolt with Cypher MERGE, so an existing graph is updated in place.

    ArcadeDB's openCypher support is partial, so batching is established in two steps rather
    than one. ``_supports_unwind`` probes the shape this path sends before anything is
    written, and because a read-only probe cannot prove that ``MERGE ... SET +=`` over an
    unwound row is accepted, the first batched statement the engine rejects latches the rest
    of the import back to one row at a time. Rows travel as a single query parameter either
    way, so nothing captured is ever interpolated into the statement text.

    Either way ``_run_with_retry`` handles the transient deadlocks ArcadeDB reports even for
    a single sequential writer; a deadlock is re-raised rather than mistaken for a rejected
    statement shape, since retrying it per row would not help.
    """
    from cli_csv import _run_with_retry

    stats = {"nodes": 0, "edges": 0}
    with driver.session(database=database) as session:
        batched = _supports_unwind(session)
        if not batched:
            logger.info("ArcadeDB did not accept a batched UNWIND; writing one row at a time")

        def write_group(rows, batched_statement, single_statement) -> int:
            nonlocal batched
            written = 0
            for chunk in chunks(rows, batch_size):
                if batched:
                    try:
                        _run_with_retry(session, batched_statement, rows=chunk)
                        written += len(chunk)
                        continue
                    except TransientError:
                        raise
                    except Exception as err:
                        logger.warning(
                            f"ArcadeDB rejected a batched statement ({err}); writing one row "
                            "at a time for the rest of this import")
                        batched = False
                for row in chunk:
                    _run_with_retry(session, single_statement, **row)
                written += len(chunk)
            return written

        for label, rows in _node_rows(nodes).items():
            stats["nodes"] += write_group(
                rows,
                "UNWIND $rows AS row "
                f"MERGE (obj:`{label}` {{id: row.id}}) "
                "SET obj += row.props",
                f"MERGE (obj:`{label}` {{id: $id}}) SET obj += $props",
            )

        for (edge_type, from_label, to_label, has_props), rows in _edge_rows(edges).items():
            batched_statement = (
                "UNWIND $rows AS row "
                f"MATCH (a:`{from_label}` {{id: row.from_id}}) "
                f"MATCH (b:`{to_label}` {{id: row.to_id}}) "
                f"MERGE (a)-[r:`{edge_type}`]->(b)"
            )
            single_statement = (
                f"MATCH (a:`{from_label}` {{id: $from_id}}) "
                f"MATCH (b:`{to_label}` {{id: $to_id}}) "
                f"MERGE (a)-[r:`{edge_type}`]->(b)"
            )
            if has_props:
                batched_statement += " SET r += row.props"
                single_statement += " SET r += $props"
            stats["edges"] += write_group(rows, batched_statement, single_statement)

    return stats


def _supports_unwind(session) -> bool:
    """Probe the shape this path sends: a parameterized list of maps, read back by key.

    Read-only, so it cannot prove a MERGE over an unwound row is accepted - that is what the
    fallback in ``merge_import`` is for. It does rule out the engine rejecting UNWIND or map
    parameters outright, which is the cheap half of the answer and the common failure.
    """
    try:
        session.run(
            "UNWIND $rows AS row RETURN count(row.id) AS n", rows=[{"id": "probe"}]
        ).consume()
        return True
    except Exception:
        return False


def count_nodes(client) -> int:
    total = 0
    for label in (graph.ROOT_LABEL,):
        total += client.count_nodes(label)
    return total
