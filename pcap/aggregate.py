"""Stateful accumulation of a capture into AP, station and SSID records.

Memory is O(distinct MACs) rather than O(frames): nothing per-frame is retained, so a
capture ten times the size of the sample costs the same as long as it covers the same
environment. The three structures that could grow without bound - WEP IV sets, per-station
probed-SSID sets, and the EAPOL pair table - are each capped explicitly.

Two behaviours here were established by measuring against the ground-truth CSV rather than
reasoned from the standard, and both are load-bearing:

- **Association is the last non-broadcast BSSID seen with a station.** That reproduces all
  164 rows exactly. "Most recent including broadcast" gives 159 and "most common" gives 153 -
  airodump never clears a station's base BSSID once it is set.
- **Probed SSIDs come from probe requests only.** A probe *response* directed at a station
  says the AP answered, not that the station named that SSID - it may have sent a wildcard
  probe. Counting responses adds SSIDs to stations the CSV leaves empty.
"""
from . import crypto, eapol, ft as ft_parser, ie, netlayer, rates, sae, wps as wps_parser
from .constants import (
    AUTH_ALG_FT,
    AUTH_ALG_SAE,
    EAPOL_TYPE_EAP_PACKET,
    EAPOL_TYPE_KEY,
    Ctrl,
    EID,
    FrameType,
    Mgmt,
)
from .frame import decode
from .oui import lookup as oui_lookup
from .records import APRecord, CertificateRecord, SSIDRecord, StationRecord, WPSRecord

#: Management subtypes carrying the 12-byte fixed prefix (timestamp, interval, capability)
#: before their element chain.
_BEACON_LIKE = frozenset({Mgmt.BEACON, Mgmt.PROBE_RESP})

#: Fixed-field widths before the element chain, by management subtype.
_FIXED_FIELDS = {
    Mgmt.ASSOC_REQ: 4,        # capability, listen interval
    Mgmt.ASSOC_RESP: 6,       # capability, status, AID
    Mgmt.REASSOC_REQ: 10,     # capability, listen interval, current AP
    Mgmt.REASSOC_RESP: 6,
    Mgmt.PROBE_REQ: 0,
    Mgmt.BEACON: 12,
    Mgmt.PROBE_RESP: 12,
    # Algorithm, sequence, status. Only an 802.11r FT auth carries elements after them.
    Mgmt.AUTH: sae.FIXED_LEN,
}


class DeauthRecord:
    __slots__ = ("source", "target", "count", "reasons", "first_ts", "last_ts")

    def __init__(self, source, target):
        self.source = source
        self.target = target
        self.count = 0
        self.reasons = set()
        self.first_ts = self.last_ts = None


class CaptureResult:
    """Everything one capture yielded."""

    __slots__ = ("aps", "stations", "ssids", "handshakes", "deauths", "certificates",
                 "wps", "meta", "warnings", "control_only_macs", "auth_alg", "ft")

    def __init__(self, aps, stations, ssids, handshakes, deauths, certificates, meta,
                 warnings, control_only_macs, wps=None, auth_alg=None, ft=None):
        self.aps = aps
        self.stations = stations
        self.ssids = ssids
        self.handshakes = handshakes
        self.deauths = deauths
        #: Fingerprint -> CertificateRecord, deduped across every handshake in the capture:
        #: one RADIUS deployment behind many BSSIDs converges on one node per certificate.
        self.certificates = certificates
        #: BSSID -> WPSRecord, only for APs that actually advertised a parseable WPS IE.
        self.wps = wps if wps is not None else {}
        self.meta = meta
        self.warnings = warnings
        self.control_only_macs = control_only_macs
        #: (bssid, station) -> authentication algorithm. The per-association evidence of which
        #: AKM family a client took, which on a transition-mode or Compatibility Mode BSS is a
        #: different question from what the BSS offers.
        self.auth_alg = auth_alg if auth_alg is not None else {}
        #: (bssid, station) -> FTRecord for every 802.11r exchange seen.
        self.ft = ft if ft is not None else {}


class Aggregator:
    """Consumes decoded frames and produces the records a writer or exporter needs."""

    def __init__(self, meta=None, tz=None, promote_control_only: bool = False,
                 rate_mode: str = "airodump", max_ivs: int = 100_000,
                 max_probed: int = 64, reparse_every: int = 64):
        self.meta = meta
        self.tz = tz
        self.promote_control_only = promote_control_only
        self.rate_mode = rate_mode
        self.max_ivs = max_ivs
        self.max_probed = max_probed
        self.reparse_every = reparse_every

        self.aps = {}
        self.stations = {}
        self.ssids = {}
        self.deauths = {}
        self.handshake_tracker = eapol.HandshakeTracker()
        self.control_only = set()
        self.warnings = []

        self._sae_auth = set()
        #: Per-BSSID SAE detail: groups, rejections, and the PWE method the Commit used.
        self._sae_state = {}
        #: Auth algorithm by (bssid, station) - which AKM family each client took.
        self._auth_alg = {}
        #: 802.11r material by (bssid, station).
        self._ft = {}
        self._unencrypted_data = set()
        self._encrypted_data = set()
        self._beacon_parses = {}
        self._wps = {}
        self._ssid_aps = {}

    # -- record access ----------------------------------------------------

    def _ap(self, bssid) -> APRecord:
        record = self.aps.get(bssid)
        if record is None:
            record = self.aps[bssid] = APRecord(bssid)
        return record

    def _station(self, mac) -> StationRecord:
        record = self.stations.get(mac)
        if record is None:
            record = self.stations[mac] = StationRecord(mac)
        return record

    def _ssid(self, name, raw=None) -> SSIDRecord:
        record = self.ssids.get(name)
        if record is None:
            record = self.ssids[name] = SSIDRecord(name, raw)
        return record

    @staticmethod
    def _touch(record, ts):
        if record.first_ts is None or ts < record.first_ts:
            record.first_ts = ts
        if record.last_ts is None or ts > record.last_ts:
            record.last_ts = ts

    # -- ingestion --------------------------------------------------------

    def consume(self, frame) -> None:
        if frame.type == FrameType.CTRL:
            # Not promoted to nodes, but worth counting: the diagnostic tells the operator
            # how many devices --all-stations would add.
            if frame.subtype in (Ctrl.RTS, Ctrl.BLOCK_ACK, Ctrl.BLOCK_ACK_REQ, Ctrl.PS_POLL):
                if frame.addr2:
                    self.control_only.add(frame.addr2)
            return

        bssid = frame.bssid
        station = frame.station(bssid)

        if bssid:
            ap = self._ap(bssid)
            self._touch(ap, frame.ts)
            ap.frames += 1

        if station:
            record = self._station(station)
            self._touch(record, frame.ts)
            record.packets += 1
            if frame.radio is not None and frame.radio.signal_dbm is not None:
                record.power = int(frame.radio.signal_dbm)
            if bssid:
                # Last non-broadcast BSSID wins, and is never cleared.
                record.base_bssid = bssid

        if frame.type == FrameType.MGMT:
            self._consume_management(frame, bssid, station)
        elif frame.type == FrameType.DATA:
            self._consume_data(frame, bssid, station)

    def _element_offset(self, frame):
        fixed = _FIXED_FIELDS.get(frame.subtype)
        return None if fixed is None else frame.body_offset + fixed

    def _consume_management(self, frame, bssid, station):
        subtype = frame.subtype

        if subtype == Mgmt.AUTH:
            self._consume_auth(frame, bssid, station)
            return

        if subtype in (Mgmt.DEAUTH, Mgmt.DISASSOC):
            self._record_deauth(frame)
            return

        offset = self._element_offset(frame)
        if offset is None or offset > len(frame.raw):
            return

        if subtype == Mgmt.PROBE_REQ:
            self._consume_probe_request(frame, station, offset)
            return

        elements = ie.parse(frame.raw, offset)

        if subtype in _BEACON_LIKE and bssid:
            if subtype == Mgmt.BEACON:
                self._ap(bssid).beacons += 1
            self._consume_beacon(frame, bssid, elements, offset)
        elif subtype in (Mgmt.ASSOC_REQ, Mgmt.REASSOC_REQ) and bssid:
            # An association request names the AP it is joining - sometimes the only place a
            # BSSID's ESSID appears at all.
            named = elements.ssid
            if named and not named[2]:
                self._set_essid(self._ap(bssid), named)

    def _consume_auth(self, frame, bssid, station):
        """Authentication frames: which AKM this pair negotiated, and any FT material.

        Per-pair, not per-BSSID: "this BSSID saw SAE" says the network offers WPA3, not that
        this client took it. Association Requests would say it directly but real captures
        often have none, while an Auth frame precedes every association.
        """
        info = sae.parse(frame.raw[frame.body_offset:])
        if info is None or not bssid:
            return

        if station is None and frame.addr2 == bssid:
            # `frame.station` drops frames transmitted by the BSSID, so beacons do not create a
            # Client per AP. Auth frames go both ways and the AP's half carries the R1KH-ID, so
            # take the peer from the receiver here.
            station = frame.addr1 if frame.addr1 != bssid else None

        if info.algorithm == AUTH_ALG_SAE:
            # SAE proves WPA3 even with no beacon captured - the cheapest signal there is.
            self._sae_auth.add(bssid)
            record = self._sae_state.setdefault(bssid, {"groups": set(), "rejected": False})
            if info.group is not None:
                record["groups"].add(info.group)
            if info.group_rejected:
                record["rejected"] = True
            pwe = info.pwe
            if pwe is not None:
                record.setdefault("pwe", pwe)  # first answer wins

        if station:
            self._auth_alg.setdefault((bssid, station), info.algorithm)

        if info.algorithm == AUTH_ALG_FT and station:
            self._consume_ft(frame, bssid, station)

    def _consume_ft(self, frame, bssid, station):
        """FT Authentication elements: PMKR0Name, MDID and the key-holder ids."""
        offset = self._element_offset(frame)
        if offset is None or offset > len(frame.raw):
            return
        elements = ie.parse(frame.raw, offset)

        rsn = crypto.parse_suite_element(elements.rsn) if elements.rsn else None
        mobility = elements.first(EID.MOBILITY_DOMAIN)
        fte = elements.first(EID.FAST_BSS_TRANSITION)

        key = (bssid, station)
        record = self._ft.get(key)
        if record is None:
            record = self._ft[key] = ft_parser.FTRecord(bssid, station)
        record.absorb(
            mdid=bytes(mobility[:2]) if mobility is not None and len(mobility) >= 2 else None,
            # PMKR0Name rides in the RSNE's PMKID field.
            pmkr0name=rsn.pmkid if rsn is not None else None,
            akms=rsn.akms if rsn is not None else (),
            fte=ft_parser.parse_fte(fte),
        )
        # An FT roam completes without a 4-way, so nothing else would ever create this pair.
        self.handshake_tracker.ensure(frame.ts, bssid, station)

    def _consume_probe_request(self, frame, station, offset):
        if station is None:
            return
        named = ie.parse(frame.raw, offset).ssid
        if named is None or named[2] or not named[0]:
            return  # a zero-length SSID is a wildcard probe, not a network
        record = self._station(station)
        if named[0] not in record.probed and len(record.probed) < self.max_probed:
            record.probed[named[0]] = None
        ssid = self._ssid(named[0], named[1])
        ssid.probe_count += 1

    def _consume_beacon(self, frame, bssid, elements, offset):
        ap = self._ap(bssid)

        # Above the sampling gate, and on its own completeness test rather than the shared
        # counter. WPS attributes are split across frame types by the spec - a beacon carries
        # the state and lockout, a probe response adds config methods - and `_BEACON_LIKE`
        # routes both through this counter, so a probe response landing on a sampled-out tick
        # would silently lose the richest WPS data in the capture. Parsing until the BSSID is
        # complete costs a handful of extra walks per AP, not one per beacon.
        self._consume_wps(bssid, elements, frame.ts)

        # Re-parsing every beacon for an AP that already yielded one is pure waste; sampling
        # still catches an element set that changes mid-capture.
        seen = self._beacon_parses.get(bssid, 0)
        self._beacon_parses[bssid] = seen + 1
        if seen and seen % self.reparse_every:
            return

        named = elements.ssid
        if named is not None:
            self._set_essid(ap, named)

        if elements.channel is not None:
            ap.channel = elements.channel

        capability = None
        raw = frame.raw
        if offset >= 2 and offset <= len(raw):
            capability = raw[offset - 2] | (raw[offset - 1] << 8)

        ap.security = crypto.classify(
            elements.rsn, elements.wpa1, capability,
            saw_unencrypted_data=bssid in self._unencrypted_data,
            saw_encrypted_data=bssid in self._encrypted_data,
            saw_sae_auth=bssid in self._sae_auth,
            rsne_override_element=elements.rsne_override,
            rsne_override_2_element=elements.rsne_override_2,
            rsnx_element=elements.rsnx,
            rsnxe_override_element=elements.rsnxe_override,
            extcap_element=elements.extended_capabilities,
        )
        ap.max_rate = rates.max_rate(elements, mode=self.rate_mode)
        ap.wps = elements.wps is not None
        ap.band = crypto.band_for_channel(ap.channel, elements.he_capabilities is not None)
        ap.standard = crypto.standard_for(elements, ap.band)

    def _consume_wps(self, bssid, elements, ts):
        record = self._wps.get(bssid)
        if record is not None:
            record.last_ts = ts
            if record.info.complete:
                return  # nothing left to learn from this BSSID

        body = elements.wps
        if body is None:
            return
        info = wps_parser.parse(body)
        if info is None:
            return

        if record is None:
            self._wps[bssid] = WPSRecord(bssid, info, first_ts=ts, last_ts=ts)
        else:
            record.info = wps_parser.merge(record.info, info)

    def _set_essid(self, ap, named):
        name, raw, hidden = named
        if hidden:
            ap.hidden = True
            if raw:
                ap.ssid_len = len(raw)
            return

        ap.essid, ap.essid_raw, ap.hidden = name, raw, False
        ap.ssid_len = len(raw)

        ssid = self._ssid(name, raw)
        # Counted per distinct BSSID, not per beacon, so a chatty AP does not inflate it.
        broadcasters = self._ssid_aps.setdefault(name, set())
        if ap.bssid not in broadcasters:
            broadcasters.add(ap.bssid)
            ssid.ap_count += 1

    def _record_deauth(self, frame):
        source, target = frame.addr2, frame.addr1
        if not source or not target:
            return
        key = (source, target)
        record = self.deauths.get(key)
        if record is None:
            record = self.deauths[key] = DeauthRecord(source, target)
        record.count += 1
        if record.first_ts is None:
            record.first_ts = frame.ts
        record.last_ts = frame.ts
        body = frame.raw[frame.body_offset:]
        if len(body) >= 2 and not frame.protected:
            record.reasons.add(body[0] | (body[1] << 8))

    def _consume_data(self, frame, bssid, station):
        ethertype, payload = netlayer.snap_payload(frame)
        is_eapol = netlayer.is_eapol(ethertype)

        if bssid and not frame.is_null_data:
            ap = self._ap(bssid)
            if ap.ivs < self.max_ivs:
                ap.ivs += 1
            if frame.protected:
                self._encrypted_data.add(bssid)
            elif not is_eapol:
                # EAPOL is sent in the clear on every WPA2 network, so it says nothing about
                # whether the network is open. Counting it would misclassify any AP whose
                # only captured payload was a handshake - which is exactly what the CSV does
                # not do for 30:86:2D:1F:40:80.
                self._unencrypted_data.add(bssid)

        if ethertype is None:
            return

        if is_eapol:
            packet_type, body = netlayer.eapol_body(payload)
            if packet_type == EAPOL_TYPE_KEY:
                key_frame = eapol.parse_key_frame(body)
                if key_frame is not None:
                    # hc22000's EAPOL field is the whole 802.1X frame, header included, so
                    # what `eapol_body` sliced off has to be put back. Copied out of the
                    # memoryview deliberately: a slice would pin the entire 802.11 frame.
                    raw = bytes(payload[:4 + len(body)])
                    self.handshake_tracker.observe_key(
                        frame.ts, bssid, station, key_frame, raw)
            elif packet_type == EAPOL_TYPE_EAP_PACKET:
                self.handshake_tracker.observe_eap(
                    frame.ts, bssid, station, eapol.parse_eap(body))
            return

        address = netlayer.source_ip(ethertype, payload)
        if address and bssid:
            self._ap(bssid).lan_ip = address

    # -- finalization -----------------------------------------------------

    def finalize(self) -> CaptureResult:
        leftover = self.control_only - set(self.aps) - set(self.stations)

        if self.promote_control_only:
            # Opt-in only, and it does diverge from airodump: promoting control-frame
            # transmitters takes the sample capture from 164 stations to 173. They arrive
            # with almost no properties, because a control frame carries no ToDS/FromDS
            # semantics and so cannot be attributed to a BSSID.
            for mac in sorted(leftover):
                self._station(mac)
            leftover = set()

        self._leftover_control_only = leftover

        # A MAC that is both a BSSID and a station is one radio doing two jobs - a mesh
        # repeater or a phone hotspot. It stays a single node keyed by that MAC, with the AP
        # type primary, and `roles` records the duality so both backends can express it.
        for mac in set(self.aps) & set(self.stations):
            self.aps[mac].also_client = True
            self.stations[mac].also_ap = True

        for ap in self.aps.values():
            if ap.security is None:
                ap.security = crypto.classify(
                    saw_unencrypted_data=ap.bssid in self._unencrypted_data,
                    saw_encrypted_data=ap.bssid in self._encrypted_data,
                    saw_sae_auth=ap.bssid in self._sae_auth,
                )
            # Here, not in `_consume_beacon`: SAE can happen after the last re-parsed beacon.
            state = self._sae_state.get(ap.bssid)
            if state is not None:
                ap.sae_pwe = state.get("pwe")
                ap.sae_groups = tuple(sorted(state["groups"]))
                ap.sae_group_rejected = state["rejected"]

        if self.aps and self.meta is not None:
            ratio = sum(a.beacons for a in self.aps.values()) / len(self.aps)
            if ratio < 2:
                self.warnings.append(
                    f"Capture holds {sum(a.beacons for a in self.aps.values())} beacon(s) for "
                    f"{len(self.aps)} AP(s). airodump-ng stores one beacon per AP unless "
                    f"--beacons was passed, so beacon counts and AP last-seen times are a "
                    f"lower bound and are not comparable with an airodump CSV."
                )

        if self.handshake_tracker.dropped:
            self.warnings.append(
                f"{self.handshake_tracker.dropped} EAPOL pair(s) dropped at the tracking limit")

        if self.handshake_tracker.reassembler.dropped:
            self.warnings.append(
                f"{self.handshake_tracker.reassembler.dropped} EAP-TLS stream(s) dropped at "
                f"the reassembly limit; a certificate chain may be incomplete")

        certificates = {}
        for handshake in self.handshake_tracker.handshakes.values():
            for depth, info in enumerate(handshake.certificates):
                existing = certificates.get(info.fingerprint)
                if existing is None:
                    certificates[info.fingerprint] = CertificateRecord(info, depth)
                elif depth < existing.chain_depth:
                    # The same CA can appear as an intermediate in one chain and the leaf of
                    # another; the shallowest position it was ever seen at is the truthful one.
                    existing.chain_depth = depth

        # Backfilled here rather than at construction: the WPS IE is parsed from the first
        # beacon that carries one, which may be a hidden-SSID beacon or precede the probe
        # response that names the network.
        for bssid, record in self._wps.items():
            ap = self.aps.get(bssid)
            if ap is not None:
                record.essid = ap.essid

        return CaptureResult(
            aps=self.aps,
            stations=self.stations,
            ssids=self.ssids,
            handshakes=self.handshake_tracker.handshakes,
            deauths=self.deauths,
            certificates=certificates,
            wps=self._wps,
            meta=self.meta,
            warnings=self.warnings,
            control_only_macs=self._leftover_control_only,
            auth_alg=self._auth_alg,
            ft=self._ft,
        )


def aggregate(source, tz=None, **kwargs) -> CaptureResult:
    """Run a FrameSource through an Aggregator."""
    aggregator = Aggregator(meta=getattr(source, "meta", None), tz=tz, **kwargs)
    for ts, raw, radio in source:
        frame = decode(ts, raw, radio)
        if frame is not None:
            aggregator.consume(frame)
    aggregator.meta = getattr(source, "meta", None)
    return aggregator.finalize()


def oui_for(mac):
    return oui_lookup(mac)
