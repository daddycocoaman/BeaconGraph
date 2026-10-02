#!/usr/bin/env python3
"""Parse an airodump-ng CSV and load it directly into a Neo4j or ArcadeDB database."""
import argparse
import asyncio
import itertools
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

# This script lives at the repo root, but the "backend" package lives at backend/backend/ -
# add backend/ to sys.path so `import backend` resolves regardless of the current working
# directory this script is invoked from.
sys.path.insert(0, str(Path(__file__).resolve().parent / "backend"))

from loguru import logger
from neo4j import GraphDatabase
from neo4j.exceptions import TransientError

from backend import arcadedb
from backend.db import Neo4j
from backend.parser import AIRODUMP_SNIFF_TOKEN, AirodumpProcessor
from pcap.reader import looks_like_capture

# Scoped rather than matching the whole graph. Two guards, both load-bearing once a
# database can hold data from cli.py as well: `:Device` keeps it off any future node
# type that is not a device, and the `n.name IS NULL` clause keeps it off pcap-written
# nodes, which carry snake_case `name`/`node_type` and would otherwise all be relabelled
# Type='AP' - SSID nodes included. Behaviour is unchanged for a CSV-only database, where no
# node has a lowercase `name`.
NAME_BACKFILL_QUERY = (
    "MATCH (n:Device) WHERE n.Name IS NULL AND n.name IS NULL "
    "SET n.Name = n.id SET n.Type = 'AP'"
)

DEFAULT_ARCADEDB_HTTP_URI = "http://localhost:2480"
DEFAULT_ARCADEDB_BOLT_URI = "bolt://localhost:7687"
BOLT_URI_SCHEMES = ("bolt://", "bolt+s://", "bolt+ssc://", "neo4j://", "neo4j+s://", "neo4j+ssc://")
HTTP_URI_SCHEMES = ("http://", "https://")

LOG_LEVELS = ["TRACE", "DEBUG", "INFO", "WARNING", "ERROR"]


def format_duration(delta: timedelta) -> str:
    total = int(delta.total_seconds())
    hours, remainder = divmod(total, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m {seconds}s"
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Parse an airodump-ng CSV and load it directly into a graph database.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    neo4j_parser = subparsers.add_parser("neo4j", help="Load into Neo4j over Bolt")
    neo4j_parser.add_argument("filepath", type=Path, help="Path to an airodump-ng CSV file")
    neo4j_parser.add_argument(
        "--uri", default="bolt://localhost:7687",
        help="Neo4j Bolt connection URI (default: bolt://localhost:7687)",
    )
    neo4j_parser.add_argument(
        "-u", "--username", default="neo4j", help="Neo4j username (default: neo4j)"
    )
    neo4j_parser.add_argument(
        "-p", "--password", default="password", help="Neo4j password (default: password)"
    )
    neo4j_parser.add_argument(
        "--log-level", default="INFO", choices=LOG_LEVELS,
        help="Console log level (default: INFO)",
    )
    neo4j_parser.set_defaults(run=run_neo4j)

    arcadedb_parser = subparsers.add_parser(
        "arcadedb", help="Load into ArcadeDB (HTTP bulk import or Bolt merge)"
    )
    arcadedb_parser.add_argument("filepath", type=Path, help="Path to an airodump-ng CSV file")
    arcadedb_parser.add_argument(
        "--merge", action="store_true", default=False,
        help="Ingest with Cypher MERGE over Bolt, updating a database that already holds "
             "BeaconGraph data. Slower, but the default bulk import cannot update existing "
             f"nodes (default URI: {DEFAULT_ARCADEDB_BOLT_URI})",
    )
    arcadedb_parser.add_argument(
        "--uri", type=str, default=None, metavar="URI",
        help=f"ArcadeDB ingestion URI (default: {DEFAULT_ARCADEDB_HTTP_URI}, or "
             f"{DEFAULT_ARCADEDB_BOLT_URI} with --merge)",
    )
    arcadedb_parser.add_argument(
        "--http-uri", type=str, default=DEFAULT_ARCADEDB_HTTP_URI, metavar="URI",
        help="ArcadeDB HTTP URI, used for schema DDL which Cypher/Bolt cannot express. Only "
             f"consulted with --merge (default: {DEFAULT_ARCADEDB_HTTP_URI})",
    )
    arcadedb_parser.add_argument(
        "-u", "--username", default="root", help="ArcadeDB username (default: root)"
    )
    arcadedb_parser.add_argument(
        "-p", "--password", default="password", help="ArcadeDB password (default: password)"
    )
    arcadedb_parser.add_argument(
        "--database", default="beacongraph", help="ArcadeDB database name (default: beacongraph)"
    )
    arcadedb_parser.add_argument(
        "-k", "--insecure", action="store_true", default=False,
        help="Skip TLS certificate verification against the ArcadeDB HTTP endpoint",
    )
    arcadedb_parser.add_argument(
        "--no-pre-processing", action="store_true", default=False,
        help="Skip schema declaration and index creation before ingestion",
    )
    arcadedb_parser.add_argument(
        "--log-level", default="INFO", choices=LOG_LEVELS,
        help="Console log level (default: INFO)",
    )
    arcadedb_parser.set_defaults(run=run_arcadedb)

    return parser


def _reject_non_csv(path: Path, content: bytes) -> bool:
    """Log and return True if `content` is not an airodump-ng CSV."""
    if AIRODUMP_SNIFF_TOKEN in content:
        return False
    if looks_like_capture(path):
        logger.error(f"{path} is a packet capture, not an airodump-ng CSV. "
                     "Load it with `beacongraph-cli`.")
    else:
        logger.error("Not an Airodump file")
    return True


async def run_neo4j(args: argparse.Namespace) -> int:
    if not args.filepath.is_file():
        logger.error(f"File not found: {args.filepath}")
        return 1

    content = args.filepath.read_bytes()
    if _reject_non_csv(args.filepath, content):
        return 1

    try:
        neo = Neo4j(server=args.uri, user=args.username, password=args.password)
    except Exception as err:
        logger.error(f"Failed to connect to Neo4j at {args.uri}: {err}")
        return 2

    processor = AirodumpProcessor()
    processor.neo = neo
    try:
        await processor.parseUpload(content)
        neo.query(NAME_BACKFILL_QUERY)
    except ValueError as err:
        logger.error(str(err))
        return 1
    except Exception:
        logger.exception(f"Ingestion into {args.uri} failed")
        return 2
    finally:
        neo.shutdown()

    logger.success(f"Loaded {args.filepath} into {args.uri}")
    return 0


def _resolve_arcadedb_uri(args: argparse.Namespace) -> str:
    if args.uri:
        return args.uri
    return DEFAULT_ARCADEDB_BOLT_URI if args.merge else DEFAULT_ARCADEDB_HTTP_URI


def _classify(processor: AirodumpProcessor, bDict: list, sDict: list):
    """Reuse AirodumpProcessor's classification helpers (shared with the Neo4j path) without
    writing through its Neo4j-shaped self.neo.insert_asset()/create_relationship() calls.

    Neo4j's create_relationship() auto-vivifies a missing relationship endpoint via MERGE (this
    is how a probed ESSID that was never captured as its own AP row still ends up as a node -
    see NAME_BACKFILL_QUERY). ArcadeDB's MATCH-based edge writes have no such auto-create, so
    any edge endpoint id not already covered by a classified node gets a synthetic phantom AP
    node here, matching what the Neo4j path's backfill query does for the same case
    (Type='AP', Name=id).
    """
    bNodes = [processor._classifyBssid(entry) for entry in bDict]
    sNodes = [processor._classifyStation(entry) for entry in sDict]

    known_ids = {node["BSSID"] for node in bNodes} | {node["Name"] for node in sNodes}

    edges = []  # (from_id, to_id, edge_type) - from_id is always a Client's own id
    for entry, sNode in zip(sDict, sNodes):
        bssid = entry["BSSID"] if entry["BSSID"] != "(not associated)" else None
        if bssid:
            edges.append((sNode["Name"], bssid, "Associated"))
        for essid in entry["Probed ESSIDs"].split(","):
            if essid:
                edges.append((sNode["Name"], essid, "Probes"))

    for _, to_id, _ in edges:
        if to_id not in known_ids:
            bNodes.append({"Type": "AP", "Name": to_id, "BSSID": to_id})
            known_ids.add(to_id)

    return bNodes, sNodes, edges


def _run_with_retry(session, query: str, retries: int = 5, **params) -> None:
    """Run one Cypher statement, retrying on ArcadeDB's transient deadlock errors.

    Observed empirically: ArcadeDB's Bolt implementation can report a transient deadlock even
    for a single connection issuing purely sequential statements (no concurrent writers). The
    neo4j driver classifies this as TransientError specifically because it is safe/expected to
    retry, unlike a genuine constraint violation.
    """
    delay = 0.1
    for attempt in range(retries):
        try:
            session.run(query, **params)
            return
        except TransientError:
            if attempt == retries - 1:
                raise
            time.sleep(delay)
            delay *= 2


def _merge_import(driver, database: str, bNodes: list, sNodes: list, edges: list) -> None:
    """Ingest with Cypher MERGE, one row at a time. Nodes are written as their single specific
    vertex type only (no extra label) - ArcadeDB has no equivalent of Neo4j's multi-label
    tagging. Every edge in BeaconGraph originates from a Client node, so the "from" endpoint is
    matched on the specific `Client` type (never ambiguous); the "to" endpoint is matched via
    the polymorphic root type so it resolves regardless of which specific type that node was
    written under. This exactly mirrors backend.db.Neo4j.create_relationship()'s existing
    asymmetric from_label="Client"/to_label="Device" pattern, including its behavior when a
    node's id collides across two different types (e.g. a mesh node whose BSSID also appears
    as a station's own MAC): the polymorphic "to" match can resolve to more than one node,
    producing one relationship per match - consistent with what the same collision already
    does against Neo4j today."""
    with driver.session(database=database) as session:
        for node in bNodes:
            _run_with_retry(
                session,
                f"MERGE (obj:`{node['Type']}` {{id: $id}}) SET obj += $props",
                id=node["BSSID"], props=node,
            )
        for node in sNodes:
            _run_with_retry(
                session,
                "MERGE (obj:`Client` {id: $id}) SET obj += $props",
                id=node["Name"], props=node,
            )
        for from_id, to_id, edge_type in edges:
            _run_with_retry(
                session,
                "MATCH (a:`Client` {id: $from_id}) "
                f"MATCH (b:`{arcadedb.ROOT_LABEL}` {{id: $to_id}}) "
                f"MERGE (a)-[r:`{edge_type}`]->(b)",
                from_id=from_id, to_id=to_id,
            )
    return None


def _bulk_import(client: "arcadedb.ArcadeDBClient", bNodes: list, sNodes: list, edges: list) -> bool:
    """Bulk-load through ArcadeDB's batch endpoint. Returns False on failure.

    @id is only a temporary handle scoped to this one batch request, so it must be unique per
    vertex record even when two vertices share the same real "id" property (e.g. a mesh node
    whose BSSID also appears as a station's own MAC - the same collision _merge_import() handles
    via a polymorphic Cypher match). Handles are tracked by real id so an edge can be expanded
    into one record per matching vertex, mirroring _merge_import()'s asymmetric matching: the
    "from" side (always a Client, by construction of `edges`) resolves to exactly one handle,
    while the "to" side resolves to every vertex - of any type - sharing that id.
    """
    vertices = []
    ids_by_value: dict = {}
    client_ids_by_value: dict = {}

    def add_vertex(vtype: str, real_id, props: dict) -> None:
        handle = len(vertices)
        record = {"@type": "v", "@class": vtype, "@id": handle, "id": real_id}
        record.update(props)
        vertices.append(record)
        ids_by_value.setdefault(real_id, []).append(handle)
        if vtype == "Client":
            client_ids_by_value.setdefault(real_id, []).append(handle)

    for node in bNodes:
        add_vertex(node["Type"], node["BSSID"], node)
    for node in sNodes:
        add_vertex("Client", node["Name"], node)

    edge_records = [
        {"@type": "e", "@class": edge_type, "@from": from_handle, "@to": to_handle}
        for from_id, to_id, edge_type in edges
        for from_handle in client_ids_by_value.get(from_id, [])
        for to_handle in ids_by_value.get(to_id, [])
    ]

    if not vertices and not edge_records:
        logger.warning("Nothing to import")
        return True

    logger.info(f"Importing {len(vertices):,} vertices and {len(edge_records):,} edges")
    try:
        result = client.batch_import(
            itertools.chain(vertices, edge_records), expected_edges=len(edge_records)
        )
    except arcadedb.ArcadeDBError as err:
        logger.error(f"ArcadeDB bulk import failed: {err}")
        payload = err.payload or {}
        created_v = payload.get("verticesCreated")
        created_e = payload.get("edgesCreated")
        if created_v is not None or created_e is not None:
            logger.error(
                f"{created_v or 0:,} vertices and {created_e or 0:,} edges were written "
                "before the failure."
            )
        if payload.get("partialCommit"):
            logger.error(
                "The import committed partially - the target database now holds an "
                "incomplete graph."
            )
        return False

    skipped = result.get("linesSkipped") or 0
    if skipped:
        logger.warning(f"ArcadeDB skipped {skipped:,} record(s) during the import")
    return True


async def run_arcadedb(args: argparse.Namespace) -> int:
    uri = _resolve_arcadedb_uri(args)
    credentials = (args.username, args.password) if args.password else None

    if args.merge and not uri.startswith(BOLT_URI_SCHEMES):
        logger.error(f"--merge ingests over Bolt, but --uri is {uri}")
        return 2
    if not args.merge and not uri.startswith(HTTP_URI_SCHEMES):
        logger.error(
            f"The bulk import runs over HTTP, but --uri is {uri}. Pass --merge to ingest "
            "over Bolt."
        )
        return 2

    if not args.filepath.is_file():
        logger.error(f"File not found: {args.filepath}")
        return 1

    content = args.filepath.read_bytes()
    if _reject_non_csv(args.filepath, content):
        return 1

    # Schema DDL always goes over HTTP - Cypher has no CREATE VERTEX TYPE ... EXTENDS and no
    # native index syntax. When ingestion is already over HTTP that same endpoint serves both.
    http_uri = args.http_uri if args.merge else uri

    driver = None
    try:
        client = arcadedb.ArcadeDBClient(
            http_uri, args.database, args.username, args.password, args.insecure
        )
        client.verify_connectivity()

        if args.merge:
            driver = GraphDatabase.driver(uri, auth=credentials)
            driver.verify_connectivity()

        logger.info(f"Connected to ArcadeDB at {uri} (database: {args.database})")
    except Exception as err:
        logger.error(f"Failed to connect to ArcadeDB: {err}")
        if driver is not None:
            driver.close()
        return 2

    if not args.merge:
        try:
            existing = client.count_nodes(arcadedb.ROOT_LABEL)
        except Exception as err:
            logger.error(
                f"Could not determine whether {args.database} already holds BeaconGraph "
                f"data: {err}"
            )
            return 2

        if existing:
            logger.error(f"Database {args.database} already holds {existing:,} node(s).")
            logger.error(
                "The bulk import cannot update existing nodes and would duplicate the "
                "entire graph. Re-run with --merge to update in place, or target an empty "
                "database."
            )
            return 3

    processor = AirodumpProcessor()
    started = datetime.now()
    try:
        if not args.no_pre_processing:
            client.apply(arcadedb.type_statements(), "type")
            client.apply(arcadedb.property_statements(), "property")
            client.apply(arcadedb.index_statements(), "index")
            client.declare_edge_types(arcadedb.EDGE_TYPES)
        else:
            logger.info("Skipping schema declaration (--no-pre-processing)")

        bDict, sDict = await processor._parseAirodump(content)
        bNodes, sNodes, edges = _classify(processor, bDict, sDict)

        if args.merge:
            _merge_import(driver, args.database, bNodes, sNodes, edges)
        elif not _bulk_import(client, bNodes, sNodes, edges):
            return 2

        elapsed = format_duration(datetime.now() - started)
        logger.success(
            f"Loaded {args.filepath} into {uri} (database: {args.database}) in {elapsed}"
        )
    except ValueError as err:
        logger.error(str(err))
        return 1
    except Exception:
        logger.exception(f"Ingestion into {uri} failed")
        return 2
    finally:
        if driver is not None:
            driver.close()

    return 0


def main() -> int:
    args = build_parser().parse_args()
    logger.remove()
    logger.add(sys.stderr, level=args.log_level)
    return asyncio.run(args.run(args))


if __name__ == "__main__":
    sys.exit(main())
