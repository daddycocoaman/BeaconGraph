"""Neo4j writer: parameterized, UNWIND-batched Cypher.

Deliberately not built on ``backend.db.Neo4j``, for reasons that matter more here than on
the CSV path. That class interpolates every value directly into the query text
(``db.py:73-86``) behind a sanitizer that strips ``'`` but not ``"`` (``db.py:67-71``), and
``base_import_cypher`` (``db.py:21``) interpolates the node id without sanitizing at all.
SSIDs out of a packet capture are 0-32 arbitrary attacker-chosen octets - the repo's own
``docs/samples/walk.csv`` already carries a probed ESSID of ``;DROP TABLE USERS;--``. It also
coerces ``0``, ``False`` and ``None`` into the strings ``'0'``, ``'False'`` and ``'None'``,
which is exactly what the omit rule forbids, and runs two full-graph scans in its
constructor before writing anything.

Everything here travels as a query parameter. Only label and relationship-type names are
interpolated, and those come from the schema registry, never from captured data.
"""
from loguru import logger

from . import chunks
from .. import graph
from ..schema import SchemaError
from ..schema import load as load_schema

DEFAULT_BATCH_SIZE = 1000


def create_indexes(session, schema=None) -> int:
    """Index every declared label on ``id``, deepest-first.

    Not delegated to ``backend.db.Neo4j.create_indexes()``, which filters its label list on
    the substring ``"NODE_LABEL"`` while ``labels.py`` names five of its seven constants
    ``*_NODE_LEVEL`` - so it only ever indexes ``Client`` and ``WEP``, and never ``Device``,
    the label every relationship endpoint matches on.

    Deepest-first because Neo4j uses index creation order when choosing which label captions
    a node in the browser, and the root should lose that contest to every specific label.
    """
    schema = schema or load_schema()
    created = 0
    for statement in schema.neo4j_index_statements():
        try:
            session.run(statement)
            created += 1
        except Exception as err:
            logger.debug(f"index statement skipped: {statement} -> {err}")
    return created


def _node_batches(nodes):
    """Group nodes by their full label set - Cypher cannot parameterize a label."""
    grouped = {}
    for node in nodes:
        key = (node.label, node.extra_labels)
        grouped.setdefault(key, []).append({"id": node.id, "props": node.props})
    return grouped


def label_set(label, extra=(), schema=None):
    """Every label a node carries: its own, its ancestors, and the same for each extra.

    Neo4j has no label inheritance. ArcadeDB gets the hierarchy for free from
    ``EXTENDS``, so a WPA2 vertex answers ``MATCH (a:AP)`` there without anything being
    written out; here the lineage has to be physically applied or the same query finds
    nothing. ``Device`` needs no special case - it is the schema root, so it is the last
    element of every lineage.

    An undeclared label falls back to itself plus the root rather than failing the ingest:
    ``graph.validate()`` has already warned about it by this point, and refusing to write
    the node would turn a styling problem into data loss.
    """
    schema = schema or load_schema()
    names = []
    for name in (label,) + tuple(extra):
        try:
            lineage = schema.lineage(name)
        except SchemaError:
            lineage = (name, graph.ROOT_LABEL)
        for entry in lineage:
            if entry not in names:
                names.append(entry)
    return tuple(names)


def _edge_batches(edges):
    grouped = {}
    for edge in edges:
        key = (edge.type, edge.from_label, edge.to_label)
        grouped.setdefault(key, []).append(
            {"from_id": edge.from_id, "to_id": edge.to_id, "props": edge.props}
        )
    return grouped


def write(driver, nodes, edges, database=None, batch_size=DEFAULT_BATCH_SIZE,
          create_index=True) -> dict:
    """Write nodes then edges. Returns a small stats dict."""
    stats = {"nodes": 0, "edges": 0, "unmatched": 0, "indexes": 0}
    session_args = {"database": database} if database else {}

    with driver.session(**session_args) as session:
        if create_index:
            stats["indexes"] = create_indexes(session)

        # Nodes first, unconditionally: the edge statements MATCH their endpoints rather
        # than MERGE them, because endpoint MERGE is precisely the mechanism that created
        # the disconnected phantom nodes this model exists to remove.
        schema = load_schema()
        for (label, extra), rows in _node_batches(nodes).items():
            carried = label_set(label, extra, schema)
            labels = "".join(f":`{name}`" for name in carried)
            stale = "".join(f":`{name}`" for name in schema.labels() if name not in carried)
            remove = f"REMOVE n{stale} " if stale else ""
            # MERGE on the root, not the specific label: MERGE is label-scoped, so keying on
            # the specific one duplicates any node whose type changed since the last ingest.
            # `id` is globally unique across the graph, so the root is the correct key.
            statement = (
                "UNWIND $rows AS row "
                f"MERGE (n:`{graph.ROOT_LABEL}` {{id: row.id}}) "
                f"{remove}"
                f"SET n{labels} "
                "SET n += row.props"
            )
            for chunk in chunks(rows, batch_size):
                session.execute_write(lambda tx, c=chunk: tx.run(statement, rows=c).consume())
                stats["nodes"] += len(chunk)

        for (edge_type, from_label, to_label), rows in _edge_batches(edges).items():
            statement = (
                "UNWIND $rows AS row "
                f"MATCH (a:`{from_label}` {{id: row.from_id}}) "
                f"MATCH (b:`{to_label}` {{id: row.to_id}}) "
                f"MERGE (a)-[r:`{edge_type}`]->(b) "
                "SET r += row.props "
                "RETURN count(*) AS matched"
            )
            for chunk in chunks(rows, batch_size):
                matched = session.execute_write(
                    lambda tx, c=chunk: tx.run(statement, rows=c).single()["matched"]
                )
                stats["edges"] += len(chunk)
                if matched < len(chunk):
                    # A row that matched nothing means an endpoint was never written, which
                    # is a bug rather than a data condition. More matches than rows is legal:
                    # it is the documented id-collision case.
                    stats["unmatched"] += len(chunk) - matched

    if stats["unmatched"]:
        logger.warning(
            f"{stats['unmatched']} edge row(s) matched no endpoint and were not written")
    return stats


def count_nodes(driver, database=None) -> int:
    session_args = {"database": database} if database else {}
    with driver.session(**session_args) as session:
        return session.run(
            f"MATCH (n:`{graph.ROOT_LABEL}`) RETURN count(n) AS total").single()["total"]
