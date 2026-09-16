"""Turn a CaptureResult into the nodes and edges a writer can ingest.

Both backends consume the same two lists; everything backend-specific (multi-labelling,
batching, DDL) lives in the writers. The representation is deliberately close to what the
existing CSV CLI already builds, so the two paths stay comparable.
"""
from .oui import lookup as oui_lookup
from .records import WPAHandshakeRecord
from .schema import load as load_schema

#: Applied to every node in Neo4j, and the root vertex type every other type extends in
#: ArcadeDB. Relationship endpoints match on it, so it has to be indexed.
ROOT_LABEL = "Device"

PROBES = "Probes"
ASSOCIATED = "Associated"
BROADCASTS = "Broadcasts"
DEAUTHENTICATED = "Deauthenticated"
NEGOTIATED = "Negotiated"
PRESENTED = "Presented"
ISSUED_BY = "IssuedBy"
EXPOSES = "Exposes"

#: Parent of the four handshake subtypes. Edge endpoints match on it, since a handshake's own
#: label is always a subtype and one MATCH has to reach all of them.
HANDSHAKE_LABEL = "Handshake"


class Node:
    __slots__ = ("label", "id", "props", "extra_labels")

    def __init__(self, label, node_id, props, extra_labels=()):
        self.label = label
        self.id = node_id
        self.props = props
        self.extra_labels = tuple(extra_labels)

    def __repr__(self):
        return f"<Node {self.label}:{self.id}>"


class Edge:
    __slots__ = ("type", "from_label", "from_id", "to_label", "to_id", "props")

    def __init__(self, edge_type, from_id, to_id, from_label="Client", to_label=ROOT_LABEL,
                 props=None):
        self.type = edge_type
        self.from_label = from_label
        self.from_id = from_id
        self.to_label = to_label
        self.to_id = to_id
        self.props = props or {}

    def __repr__(self):
        return f"<Edge ({self.from_id})-[{self.type}]->({self.to_id})>"


def _prefixed(props, prefix, keys):
    return {f"{prefix}{k}": props[k] for k in keys if k in props}


def _issuer_fingerprint(info, certificates):
    """Find the certificate that signed this one, by matching its issuer to a subject.

    Matching on the distinguished name rather than verifying the signature: the point is to
    render the chain the server actually sent, not to validate it, and the server sends the
    chain in order. A DN match is what makes the link visible when the same CA arrives from
    two different handshakes.
    """
    if not info.issuer:
        return None
    for fingerprint, record in certificates.items():
        if record.info.subject == info.issuer:
            return fingerprint
    return None


def handshake_records(result) -> dict:
    """``{(bssid, station): WPAHandshakeRecord}`` for one capture.

    Shared by `build` and the hash exporters so they cannot disagree about what is crackable.
    """
    records = {}
    for (bssid, mac), handshake in result.handshakes.items():
        ap = result.aps.get(bssid)
        security = ap.security if ap else None
        records[(bssid, mac)] = WPAHandshakeRecord(
            handshake,
            essid=ap.essid if ap else None,
            essid_raw=ap.essid_raw if ap else None,
            akms=security.akms if security else (),
            # Per-association evidence; without it the AP's advertised set stands in.
            auth_alg=result.auth_alg.get((bssid, mac)),
            security=security,
            ft=result.ft.get((bssid, mac)),
        )
    return records


def build(result, tz=None):
    """``(nodes, edges)`` for one capture.

    A MAC that is both a BSSID and a station becomes **one** node, not two. That keeps `id`
    globally unique, which it has to be, and it is also the truthful model - a mesh repeater
    or phone hotspot is one radio doing two jobs. The AP type stays primary; the `Client`
    label is added alongside it in Neo4j, and the `roles` property carries the same fact for
    ArcadeDB, whose vertices belong to exactly one type.
    """
    nodes, edges = [], []
    dual = set(result.aps) & set(result.stations)

    for bssid, record in result.aps.items():
        props = record.to_node_dict(oui=oui_lookup(bssid), tz=tz)
        extra = []
        if bssid in dual:
            station = result.stations[bssid]
            station_props = station.to_node_dict(tz=tz)
            # The two records measure different things - the AP's frame count is every frame
            # on that BSSID, the station's is every frame attributed to it as a client - so
            # the station's are carried under their own names rather than overwriting.
            props.update(_prefixed(station_props, "client_",
                                   ("packets", "first_time_seen", "last_time_seen", "power")))
            extra.append("Client")
        nodes.append(Node(props.get("node_type", "AP"), bssid, props, extra))

    for mac, record in result.stations.items():
        if mac in dual:
            continue  # already emitted as the AP-typed node above
        nodes.append(Node("Client", mac, record.to_node_dict(oui=oui_lookup(mac), tz=tz)))

    for name, record in result.ssids.items():
        nodes.append(Node("SSID", name, record.to_node_dict(tz=tz)))

    for fingerprint, record in result.certificates.items():
        nodes.append(Node("TLSCertificate", fingerprint, record.to_node_dict(tz=tz)))

    for bssid, record in result.wps.items():
        nodes.append(Node("WPS", record.id, record.to_node_dict(tz=tz)))

    # Built before the edge loops below, not after: the `Associated` edge reports the same
    # `crackable` verdict as the node, and that verdict now depends on the AP's AKM and raw
    # ESSID, which only the record knows how to combine.
    handshake_nodes = handshake_records(result)
    for record in handshake_nodes.values():
        # The node's own type: the subtype says which credential the exchange used.
        nodes.append(Node(record.node_type, record.id, record.to_node_dict(tz=tz)))

    known = {node.id for node in nodes}

    def handshake_props(handshake):
        props = {"handshake": handshake.count}
        if handshake.complete:
            props["handshake_complete"] = True
        record = handshake_nodes.get((handshake.bssid, handshake.station))
        if record is not None and record.crackable:
            props["crackable"] = True
        if handshake.pmkid:
            props["pmkid"] = handshake.pmkid
        if handshake.identity:
            props["identity"] = handshake.identity
        return props

    associated = set()
    for mac, record in result.stations.items():
        if record.base_bssid and record.base_bssid in known:
            props = {"evidence": "data", "current": True}
            handshake = result.handshakes.get((record.base_bssid, mac))
            if handshake is not None:
                props.update(handshake_props(handshake))
                props["evidence"] = "eapol"
            associated.add((mac, record.base_bssid))
            edges.append(Edge(ASSOCIATED, mac, record.base_bssid, props=props))

        for name in record.probed:
            if name in known:
                edges.append(Edge(PROBES, mac, name, to_label="SSID"))

    # A station that roams leaves handshake evidence with an AP that is no longer its
    # current one - in the sample capture the only *complete* 4-way handshake is exactly
    # that case, and keying associations solely on the last-seen BSSID would discard it.
    # A completed handshake is proof of association, so it earns its own edge; `current`
    # distinguishes the live association the CSV reports.
    for (bssid, mac), handshake in result.handshakes.items():
        if (mac, bssid) in associated or bssid not in known or mac not in known:
            continue
        if not handshake.messages:
            continue
        props = handshake_props(handshake)
        props["evidence"] = "eapol"
        props["current"] = False
        edges.append(Edge(ASSOCIATED, mac, bssid, props=props))

    for bssid, record in result.aps.items():
        if record.essid and record.essid in known:
            props = {"beacons": record.beacons} if record.beacons else {}
            edges.append(Edge(BROADCASTS, bssid, record.essid,
                              from_label=ROOT_LABEL, to_label="SSID", props=props))

    # The handshake node hangs off both endpoints with one edge type: `from_label` is the
    # root, so the same loop serves a Client and an AP without caring which is which.
    for (bssid, mac), record in handshake_nodes.items():
        for endpoint in (mac, bssid):
            if endpoint in known:
                edges.append(Edge(NEGOTIATED, endpoint, record.id,
                                  from_label=ROOT_LABEL, to_label=HANDSHAKE_LABEL))

        chain = record.handshake.certificates
        if chain and chain[0].fingerprint in known:
            # Only the leaf is Presented; the CAs above it are reached through IssuedBy, so
            # "which authority signs for this network" is one traversal rather than a scan.
            edges.append(Edge(PRESENTED, record.id, chain[0].fingerprint,
                              from_label=HANDSHAKE_LABEL, to_label="TLSCertificate",
                              props={"chain_depth": 0}))

    for fingerprint, record in result.certificates.items():
        issuer = _issuer_fingerprint(record.info, result.certificates)
        # A chain whose root was never sent has no issuer node, and self-signed roots would
        # otherwise loop on themselves - in both cases the edge is simply absent.
        if issuer and issuer != fingerprint and issuer in known:
            edges.append(Edge(ISSUED_BY, fingerprint, issuer,
                              from_label="TLSCertificate", to_label="TLSCertificate"))

    # `from_label` is the root because an AP node's own label is its security type
    # (`WPA2`/`WPA3`/`Open`/...), never `AP` - matching on `AP` would find nothing.
    for bssid, record in result.wps.items():
        if bssid in known:
            edges.append(Edge(EXPOSES, bssid, record.id,
                              from_label=ROOT_LABEL, to_label="WPS"))

    for (source, target), record in result.deauths.items():
        if source in known and target in known:
            props = {"count": record.count}
            if record.reasons:
                props["reasons"] = ",".join(str(r) for r in sorted(record.reasons))
            edges.append(Edge(DEAUTHENTICATED, source, target,
                              from_label=ROOT_LABEL, props=props))

    return nodes, edges


def summarize(nodes, edges) -> str:
    """One-line inventory for the CLI's progress output."""
    from collections import Counter

    node_counts = Counter(node.label for node in nodes)
    edge_counts = Counter(edge.type for edge in edges)
    return (
        "Nodes: " + ", ".join(f"{n} {l}" for l, n in sorted(node_counts.items()))
        + " | Edges: " + ", ".join(f"{n} {t}" for t, n in sorted(edge_counts.items()))
    )


def validate(nodes, edges):
    """Check every node label and edge type is declared in the schema.

    Cheap guard against the drift the registry exists to prevent: an undeclared label gets
    no index and, in ArcadeDB, no vertex type at all, and nothing else would say so.
    """
    schema = load_schema()
    declared_nodes = set(schema.labels())
    declared_edges = set(schema.edges)

    unknown_nodes = {n.label for n in nodes} - declared_nodes
    unknown_edges = {e.type for e in edges} - declared_edges
    return unknown_nodes, unknown_edges
