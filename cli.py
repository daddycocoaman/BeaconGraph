#!/usr/bin/env python3
"""Parse an 802.11 packet capture directly into a Neo4j or ArcadeDB database.

The companion to cli_csv.py, which reads airodump-ng's CSV summary. Reading the capture instead
recovers what that summary cannot express: real RSN/WPA information elements (so WPA3 is
actually reachable, and 802.11r and management frame protection are visible at all), EAPOL
handshakes and PMKIDs, deauthentication activity, and SSID nodes that connect a client's
probe to the APs actually broadcasting that network.
"""
import argparse
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

# This script lives at the repo root while the `backend` package lives at backend/backend/,
# so backend/ has to be on the path for `import backend` to resolve regardless of the
# working directory. Same shim as cli_csv.py.
sys.path.insert(0, str(Path(__file__).resolve().parent / "backend"))

from loguru import logger
from neo4j import GraphDatabase

from backend import arcadedb
from backend.parser import AIRODUMP_SNIFF_TOKEN
from pcap import csvout, ft, graph, hc22000
from pcap.aggregate import aggregate
from pcap.reader import FrameSource, UnsupportedDltError
from pcap.schema import load as load_schema
from pcap.writers import arcadedb as arcadedb_writer
from pcap.writers import neo4j as neo4j_writer

DEFAULT_NEO4J_URI = "bolt://localhost:7687"
DEFAULT_ARCADEDB_HTTP_URI = "http://localhost:2480"
DEFAULT_ARCADEDB_BOLT_URI = "bolt://localhost:7687"

BOLT_URI_SCHEMES = ("bolt://", "bolt+s://", "bolt+ssc://", "neo4j://", "neo4j+s://",
                    "neo4j+ssc://")
HTTP_URI_SCHEMES = ("http://", "https://")

LOG_LEVELS = ["TRACE", "DEBUG", "INFO", "WARNING", "ERROR"]

EXIT_OK = 0
EXIT_INPUT = 1
EXIT_FAILURE = 2
EXIT_REFUSED = 3


def format_duration(delta: timedelta) -> str:
    total = int(delta.total_seconds())
    hours, remainder = divmod(total, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m {seconds}s"
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


def add_shared_arguments(parser) -> None:
    parser.add_argument("filepath", type=Path, help="Path to a pcap/pcapng capture file")
    parser.add_argument(
        "--export-csv", type=str, default=None, metavar="PATH",
        help="Also write an airodump-ng-compatible CSV ('-' for stdout)")
    parser.add_argument(
        "--export-hc22000", type=str, default=None, metavar="PATH",
        help="Also write hashcat mode 22000 hashes for every crackable handshake "
             "('-' for stdout). Only PSK networks are written: an 802.1X or SAE network "
             "derives its PMK from something other than a passphrase, so a hash for it "
             "could never be recovered from a wordlist")
    parser.add_argument(
        "--export-hc37100", type=str, default=None, metavar="PATH",
        help="Also write hashcat mode 37100 hashes for every 802.11r FT-PSK roam "
             "('-' for stdout). One FT Authentication frame is a complete offline verifier, "
             "so this needs no 4-way handshake. FT-SAE roams are excluded for the same reason "
             "SAE is excluded from --export-hc22000. NOTE: mode 37100 is not in mainline "
             "hashcat and needs a build from pull request #4645")
    parser.add_argument(
        "--all-stations", action="store_true", default=False,
        help="Also promote MACs seen only in control frames. Diverges from airodump-ng, "
             "which lists only transmitters of management or data frames")
    parser.add_argument(
        "--rate-mode", choices=("airodump", "physical"), default="airodump",
        help="'airodump' reproduces airodump-ng's Speed column exactly, quirks included; "
             "'physical' computes the true PHY maximum (default: airodump)")
    parser.add_argument(
        "--capture-tz", type=str, default=None, metavar="TZ",
        help="Timezone the capture was taken in, as an IANA name. airodump-ng writes local "
             "time with no marker, so a capture from another zone needs this to line up "
             "(default: this machine's local time)")
    parser.add_argument(
        "--fcs", dest="fcs", action="store_true", default=None,
        help="Frames carry a trailing FCS (default: auto-detect)")
    parser.add_argument(
        "--no-fcs", dest="fcs", action="store_false",
        help="Frames carry no trailing FCS (default: auto-detect)")
    parser.add_argument(
        "--max-frames", type=int, default=None, metavar="N",
        help="Stop after N frames, for quick iteration on a large capture")
    parser.add_argument(
        "--dry-run", action="store_true", default=False,
        help="Parse and summarize without writing to a database")
    parser.add_argument(
        "--log-level", default="INFO", choices=LOG_LEVELS,
        help="Console log level (default: INFO)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Parse an 802.11 packet capture directly into a graph database.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    neo4j_parser = subparsers.add_parser("neo4j", help="Load into Neo4j over Bolt")
    add_shared_arguments(neo4j_parser)
    neo4j_parser.add_argument(
        "--uri", default=DEFAULT_NEO4J_URI,
        help=f"Neo4j Bolt connection URI (default: {DEFAULT_NEO4J_URI})")
    neo4j_parser.add_argument("-u", "--username", default="neo4j",
                              help="Neo4j username (default: neo4j)")
    neo4j_parser.add_argument("-p", "--password", default="password",
                              help="Neo4j password (default: password)")
    neo4j_parser.add_argument("--database", default=None,
                              help="Neo4j database name (default: the server's default)")
    neo4j_parser.add_argument("--batch-size", type=int, default=1000, metavar="N",
                              help="Rows per UNWIND batch (default: 1000)")
    neo4j_parser.add_argument("--no-pre-processing", action="store_true", default=False,
                              help="Skip index creation before ingestion")
    neo4j_parser.set_defaults(run=run_neo4j)

    arcadedb_parser = subparsers.add_parser(
        "arcadedb", help="Load into ArcadeDB (HTTP bulk import or Bolt merge)")
    add_shared_arguments(arcadedb_parser)
    arcadedb_parser.add_argument(
        "--merge", action="store_true", default=False,
        help="Ingest with Cypher MERGE over Bolt, updating a database that already holds "
             "BeaconGraph data. Slower, but the default bulk import cannot update existing "
             f"nodes (default URI: {DEFAULT_ARCADEDB_BOLT_URI})")
    arcadedb_parser.add_argument(
        "--uri", type=str, default=None, metavar="URI",
        help=f"ArcadeDB ingestion URI (default: {DEFAULT_ARCADEDB_HTTP_URI}, or "
             f"{DEFAULT_ARCADEDB_BOLT_URI} with --merge)")
    arcadedb_parser.add_argument(
        "--http-uri", type=str, default=DEFAULT_ARCADEDB_HTTP_URI, metavar="URI",
        help="ArcadeDB HTTP URI, used for schema DDL and index introspection which "
             f"Cypher cannot express. Only consulted with --merge "
             f"(default: {DEFAULT_ARCADEDB_HTTP_URI})")
    arcadedb_parser.add_argument("-u", "--username", default="root",
                                 help="ArcadeDB username (default: root)")
    arcadedb_parser.add_argument("-p", "--password", default="password",
                                 help="ArcadeDB password (default: password)")
    arcadedb_parser.add_argument("--database", default="beacongraph",
                                 help="ArcadeDB database name (default: beacongraph)")
    arcadedb_parser.add_argument(
        "-k", "--insecure", action="store_true", default=False,
        help="Skip TLS certificate verification against the ArcadeDB HTTP endpoint")
    arcadedb_parser.add_argument(
        "--no-pre-processing", action="store_true", default=False,
        help="Skip schema declaration and index creation before ingestion")
    arcadedb_parser.add_argument(
        "--rebuild-indexes", action="store_true", default=False,
        help="Drop and rebuild the index chains blocking labels added since the target "
             "database was created")
    arcadedb_parser.add_argument("--batch-size", type=int, default=1000, metavar="N",
                                 help="Rows per batch on the --merge path (default: 1000)")
    arcadedb_parser.set_defaults(run=run_arcadedb)

    export_parser = subparsers.add_parser(
        "export", help="Write an airodump-ng-compatible CSV without touching a database")
    add_shared_arguments(export_parser)
    export_parser.add_argument("-o", "--output", type=str, default="-", metavar="PATH",
                               help="Output path ('-' for stdout, the default)")
    export_parser.set_defaults(run=run_export)

    return parser


def resolve_timezone(name):
    if not name:
        return None
    from zoneinfo import ZoneInfo

    return ZoneInfo(name)


def parse_capture(args):
    """Read and aggregate one capture, reporting what the file can and cannot supply.

    Returns ``(result, nodes, edges)`` or None if the file is unusable.
    """
    if not args.filepath.is_file():
        logger.error(f"File not found: {args.filepath}")
        return None

    # The token is the CSV's first-line header, so a head read settles it.
    with args.filepath.open("rb") as handle:
        head = handle.read(4096)
    if AIRODUMP_SNIFF_TOKEN in head:
        logger.error(f"{args.filepath} is an airodump-ng CSV, not a packet capture. "
                     "Load it with `beacongraph-csv`.")
        return None

    try:
        tz = resolve_timezone(args.capture_tz)
    except Exception as err:
        logger.error(f"Unknown timezone {args.capture_tz!r}: {err}")
        return None

    try:
        source = FrameSource(args.filepath, assume_fcs=args.fcs, max_frames=args.max_frames)
    except UnsupportedDltError as err:
        logger.error(str(err))
        return None
    except Exception as err:
        logger.error(f"Could not read {args.filepath}: {err}")
        return None

    started = datetime.now()
    result = aggregate(
        source, tz=tz,
        promote_control_only=args.all_stations,
        rate_mode=args.rate_mode,
    )
    meta = result.meta

    if not meta.packet_count:
        logger.error(f"{args.filepath} holds no 802.11 frames")
        return None

    logger.info(
        f"Read {meta.packet_count:,} frames from {args.filepath.name} "
        f"(DLT {meta.linktype} {meta.linktype_name}, FCS "
        f"{'present' if meta.fcs_present else 'absent'}) in "
        f"{format_duration(datetime.now() - started)}")

    # Naming the gap out loud is the visible half of the omit rule. Silently dropping a
    # column would be worse than writing the placeholder the design rejected.
    missing = meta.missing_properties()
    if missing:
        logger.warning(
            f"Capture link type is {meta.linktype_name} (DLT {meta.linktype}) with no radio "
            f"header: {', '.join(missing)} cannot be derived and will be omitted from all "
            f"nodes. Ingesting the matching airodump CSV afterwards will fill them in.")

    for warning in result.warnings:
        logger.warning(warning)

    if result.control_only_macs and not args.all_stations:
        logger.info(f"Skipped {len(result.control_only_macs)} MAC(s) seen only in control "
                    f"frames (--all-stations to include them)")

    nodes, edges = graph.build(result, tz=tz)

    unknown_nodes, unknown_edges = graph.validate(nodes, edges)
    if unknown_nodes or unknown_edges:
        logger.warning(f"Types absent from schema.yaml and therefore unindexed: "
                       f"{sorted(unknown_nodes | unknown_edges)}")

    logger.info(graph.summarize(nodes, edges))
    return result, nodes, edges


def maybe_export(args, result) -> None:
    target = getattr(args, "export_csv", None)
    if target:
        csvout.write(result, target, tz=resolve_timezone(args.capture_tz))
        if target != "-":
            logger.success(f"Wrote {target}")

    target = getattr(args, "export_hc22000", None)
    if target:
        count = hc22000.write(result, target)
        if target != "-":
            # The count matters more than the filename here: an empty hash file is a real
            # answer about the capture, not a failure, and saying so beats a bare success.
            logger.success(f"Wrote {count} hash line(s) to {target}")
        if not count:
            logger.warning("No crackable handshakes: every capture handshake was either "
                           "non-PSK, incomplete, or missing a usable client frame")

    target = getattr(args, "export_hc37100", None)
    if target:
        count = ft.write(result, target)
        if target != "-":
            logger.success(f"Wrote {count} 802.11r hash line(s) to {target}")
        if count:
            # Worth saying once rather than letting an operator discover it from a hashcat
            # that does not recognise the mode: 37100 is still an open pull request.
            logger.info("Mode 37100 is not in mainline hashcat - build from PR #4645 to run "
                        "these")
        else:
            logger.warning("No crackable 802.11r roams: the capture held no FT-PSK "
                           "reassociation with a PMKID (an initial association carries none)")


def run_export(args) -> int:
    parsed = parse_capture(args)
    if parsed is None:
        return EXIT_INPUT
    result, _, _ = parsed
    csvout.write(result, args.output, tz=resolve_timezone(args.capture_tz))
    if args.output != "-":
        logger.success(f"Wrote {args.output}")
    # `export` writes its CSV through `args.output` rather than `--export-csv`, but the other
    # shared export flags still apply here - `--export-hc22000` is useful precisely when no
    # database is involved.
    maybe_export(args, result)
    return EXIT_OK


def run_neo4j(args) -> int:
    parsed = parse_capture(args)
    if parsed is None:
        return EXIT_INPUT
    result, nodes, edges = parsed
    maybe_export(args, result)

    if args.dry_run:
        logger.info("Dry run: nothing written")
        return EXIT_OK

    try:
        driver = GraphDatabase.driver(args.uri, auth=(args.username, args.password))
        driver.verify_connectivity()
    except Exception as err:
        logger.error(f"Failed to connect to Neo4j at {args.uri}: {err}")
        return EXIT_FAILURE

    started = datetime.now()
    try:
        stats = neo4j_writer.write(
            driver, nodes, edges, database=args.database, batch_size=args.batch_size,
            create_index=not args.no_pre_processing)
    except Exception:
        logger.exception(f"Ingestion into {args.uri} failed")
        return EXIT_FAILURE
    finally:
        driver.close()

    logger.success(
        f"Loaded {args.filepath} into {args.uri}: {stats['nodes']:,} nodes, "
        f"{stats['edges']:,} edges in {format_duration(datetime.now() - started)}")
    return EXIT_OK


def _resolve_arcadedb_uri(args) -> str:
    if args.uri:
        return args.uri
    return DEFAULT_ARCADEDB_BOLT_URI if args.merge else DEFAULT_ARCADEDB_HTTP_URI


def run_arcadedb(args) -> int:
    uri = _resolve_arcadedb_uri(args)

    if args.merge and not uri.startswith(BOLT_URI_SCHEMES):
        logger.error(f"--merge ingests over Bolt, but --uri is {uri}")
        return EXIT_FAILURE
    if not args.merge and not uri.startswith(HTTP_URI_SCHEMES):
        logger.error(f"The bulk import runs over HTTP, but --uri is {uri}. Pass --merge to "
                     "ingest over Bolt.")
        return EXIT_FAILURE

    parsed = parse_capture(args)
    if parsed is None:
        return EXIT_INPUT
    result, nodes, edges = parsed
    maybe_export(args, result)

    if args.dry_run:
        logger.info("Dry run: nothing written")
        return EXIT_OK

    # Schema DDL always goes over HTTP: Cypher has no CREATE VERTEX TYPE ... EXTENDS, no
    # native index syntax, and cannot read schema:types. When ingestion is already over HTTP
    # the same endpoint serves both.
    http_uri = args.http_uri if args.merge else uri

    driver = None
    try:
        client = arcadedb.ArcadeDBClient(
            http_uri, args.database, args.username, args.password, args.insecure)
        client.verify_connectivity()
        if args.merge:
            driver = GraphDatabase.driver(uri, auth=(args.username, args.password))
            driver.verify_connectivity()
        logger.info(f"Connected to ArcadeDB at {uri} (database: {args.database})")
    except Exception as err:
        logger.error(f"Failed to connect to ArcadeDB: {err}")
        if driver is not None:
            driver.close()
        return EXIT_FAILURE

    if not args.merge:
        try:
            existing = arcadedb_writer.count_nodes(client)
        except Exception as err:
            logger.error(f"Could not determine whether {args.database} already holds "
                         f"BeaconGraph data: {err}")
            logger.error("Refusing to continue - an unreachable database must not be "
                         "mistaken for an empty one.")
            return EXIT_FAILURE
        if existing:
            logger.error(f"Database {args.database} already holds {existing:,} node(s).")
            logger.error("The bulk import cannot update existing nodes and would duplicate "
                         "the entire graph. Re-run with --merge to update in place, or "
                         "target an empty database.")
            return EXIT_REFUSED

    started = datetime.now()
    try:
        if not args.no_pre_processing:
            try:
                arcadedb_writer.apply_schema(client, rebuild=args.rebuild_indexes)
            except arcadedb_writer.BlockedIndexes as err:
                logger.error(f"{len(err.blocked)} label(s) have no index of their own and "
                             f"are blocked by an indexed ancestor: {', '.join(err.blocked)}")
                logger.error("ArcadeDB reports success for such an index without creating "
                             "it, so this cannot be detected from the DDL alone. Ingesting "
                             "anyway would run at a fraction of normal throughput.")
                logger.error("Re-run with --rebuild-indexes to drop and rebuild the "
                             "affected chains.")
                return EXIT_REFUSED
        else:
            logger.info("Skipping schema declaration (--no-pre-processing)")

        if args.merge:
            stats = arcadedb_writer.merge_import(
                driver, args.database, nodes, edges, batch_size=args.batch_size)
            written = f"{stats['nodes']:,} nodes, {stats['edges']:,} edges"
        else:
            if not arcadedb_writer.bulk_import(client, nodes, edges):
                return EXIT_FAILURE
            written = f"{len(nodes):,} nodes, {len(edges):,} edges"
    except Exception:
        logger.exception(f"Ingestion into {uri} failed")
        return EXIT_FAILURE
    finally:
        if driver is not None:
            driver.close()

    logger.success(f"Loaded {args.filepath} into {uri} (database: {args.database}): "
                   f"{written} in {format_duration(datetime.now() - started)}")
    return EXIT_OK


def main() -> int:
    args = build_parser().parse_args()
    logger.remove()
    logger.add(sys.stderr, level=args.log_level)
    return args.run(args)


if __name__ == "__main__":
    sys.exit(main())
