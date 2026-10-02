"""Aggregated records and their conversion to graph node dictionaries.

The one rule that runs through all of this: a property whose value could not be derived is
**absent**, never an empty string and never null. That is what lets a later CSV ingest MERGE
a real value in - `SET n += $props` leaves untouched anything the map does not mention - and
it is why `compact()` is applied at every construction site rather than trusted to happen.

Note `0` and `False` survive `compact()`. Booleans are therefore written only when true, and
zero counts are dropped at the call site, so absence unambiguously means "not observed".
"""
from datetime import datetime

from .constants import AKM_SUITES, AKM_WPA3_PERSONAL, AUTH_ALG_NAMES, AUTH_ALG_OPEN, AUTH_ALG_SAE
from .frame import is_locally_administered


def compact(values: dict) -> dict:
    """Drop keys whose value is None or an empty string."""
    return {k: v for k, v in values.items() if v is not None and v != ""}


def _decode_kh(value):
    """A key-holder id as text where it is printable, else hex (R1KH-ID is a MAC)."""
    if not value:
        return None
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError:
        return value.hex()
    return text if text.isprintable() else value.hex()


def format_timestamp(ts, tz=None):
    """airodump's timestamp format: local time, second resolution, truncated not rounded."""
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz).strftime("%Y-%m-%d %H:%M:%S")


class APRecord:
    """One BSSID's accumulated state."""

    __slots__ = ("bssid", "first_ts", "last_ts", "essid", "essid_raw", "hidden", "ssid_len",
                 "channel", "security", "max_rate", "beacons", "ivs", "frames", "lan_ip",
                 "wps", "band", "standard", "also_client",
                 "sae_pwe", "sae_groups", "sae_group_rejected")

    def __init__(self, bssid):
        self.bssid = bssid
        self.first_ts = self.last_ts = None
        self.essid = self.essid_raw = None
        self.hidden = False
        self.ssid_len = None
        self.channel = None
        self.security = None
        self.max_rate = None
        self.beacons = 0
        self.ivs = 0
        self.frames = 0
        self.lan_ip = None
        self.wps = False
        self.band = None
        self.standard = None
        self.also_client = False
        #: What the SAE Commit used, as opposed to what the RSNXE says the AP can do.
        self.sae_pwe = None
        self.sae_groups = ()
        self.sae_group_rejected = False

    @property
    def name(self):
        """The ESSID, falling back to the BSSID when hidden or never observed.

        The frontend renders `name` directly, so leaving it unset produces an unlabelled
        node. `hidden` is what distinguishes a masked SSID from one simply not yet seen.
        """
        return self.essid or self.bssid

    @property
    def roles(self):
        """"AP" or "AP,Client" - a mesh repeater or phone hotspot is genuinely both.

        Carried as a property rather than relying on labels because ArcadeDB vertices have
        exactly one type, so multi-labelling cannot be expressed there. This keeps the dual
        role queryable identically on both backends.
        """
        return "AP,Client" if self.also_client else "AP"

    def to_node_dict(self, oui=None, tz=None) -> dict:
        security = self.security
        return compact({
            "id": self.bssid,
            "node_type": security.node_type if security else "AP",
            "name": self.name,
            "bssid": self.bssid,
            "roles": self.roles,
            "oui": oui,
            "encryption": security.node_type if security else None,
            "privacy": security.privacy if security else None,
            "cipher": security.cipher if security else None,
            "auth": security.auth if security else None,
            "akm": security.akm if security else None,
            "pmf": security.pmf if security else None,
            "pmf_required": security.mfp_required if security and security.has_rsn else None,
            "pmf_capable": security.mfp_capable if security and security.has_rsn else None,
            "channel": self.channel,
            "band": self.band,
            "standard": self.standard,
            "speed": self.max_rate,
            "first_time_seen": format_timestamp(self.first_ts, tz),
            "last_time_seen": format_timestamp(self.last_ts, tz),
            "beacons_observed": self.beacons or None,
            "ivs": self.ivs or None,
            "packets": self.frames or None,
            "lan_ip": self.lan_ip,
            "hidden": True if self.hidden else None,
            "ssid_len": self.ssid_len,
            "wps": True if self.wps else None,
            "randomized": True if is_locally_administered(self.bssid) else None,
            # -- WPA3 posture ---------------------------------------------------------
            # `ocv` and `sae_pwe` are written whatever the answer, like `pin_attack_status`:
            # "off" and "Hunting-and-Pecking" are the findings. Still absent when unknown.
            "rsn_overriding": True if security and security.rsn_overriding else None,
            "compatibility_mode": True if security and security.compatibility_mode else None,
            "override_akm": (security.override_akm or None) if security else None,
            "ocv": security.ocv if security else None,
            "beacon_protection": security.beacon_protection if security else None,
            "sae_h2e": security.sae_h2e if security else None,
            "sae_pk": security.sae_pk if security else None,
            "sae_pwe": self.sae_pwe,
            "sae_groups": ",".join(str(g) for g in sorted(self.sae_groups)) or None,
            "sae_group_rejected": True if self.sae_group_rejected else None,
        })


class StationRecord:
    """One station's accumulated state."""

    __slots__ = ("mac", "first_ts", "last_ts", "packets", "probed", "base_bssid",
                 "power", "also_ap")

    def __init__(self, mac):
        self.mac = mac
        self.first_ts = self.last_ts = None
        self.packets = 0
        self.probed = {}          # insertion-ordered set; airodump preserves first-seen order
        self.base_bssid = None
        self.power = None
        self.also_ap = False

    @property
    def roles(self):
        return "AP,Client" if self.also_ap else "Client"

    def to_node_dict(self, oui=None, tz=None) -> dict:
        return compact({
            "id": self.mac,
            "node_type": "Client",
            "name": self.mac,
            "roles": self.roles,
            "oui": oui,
            "first_time_seen": format_timestamp(self.first_ts, tz),
            "last_time_seen": format_timestamp(self.last_ts, tz),
            "packets": self.packets or None,
            # Absent unless the capture carried radiotap. A later CSV ingest of the same run
            # will MERGE the real value in precisely because nothing was written here.
            "power": self.power,
            "randomized": True if is_locally_administered(self.mac) else None,
        })


class SSIDRecord:
    """One network name.

    Its own node because today a Probes edge targets the SSID *string* while an AP node is
    keyed by its BSSID, so the two can never meet - every probed SSID becomes a disconnected
    phantom and the graph cannot answer "which clients are hunting for a network that is
    actually here".
    """

    __slots__ = ("name", "raw", "hidden", "ap_count", "probe_count")

    def __init__(self, name, raw=None):
        self.name = name
        self.raw = raw
        self.hidden = False
        self.ap_count = 0
        self.probe_count = 0

    def to_node_dict(self, tz=None) -> dict:
        return compact({
            "id": self.name,
            "node_type": "SSID",
            "name": self.name,
            # The exact octets: `name` is a lossy utf-8/replace decode and an SSID is an
            # arbitrary byte string, so this is the only faithful form.
            "ssid_hex": self.raw.hex() if self.raw else None,
            "ap_count": self.ap_count or None,
            "probe_count": self.probe_count or None,
            "hidden": True if self.hidden else None,
        })


class WPAHandshakeRecord:
    """One client-AP authentication exchange, as a node rather than edge properties.

    The `Associated` edge still carries the same handshake summary, and deliberately so -
    nothing that already queries it changes. What the node adds is somewhere for the things
    an edge cannot hold: an 802.1X exchange has its own identity, its own outcome, and a
    certificate chain that belongs to the authentication server rather than to either
    endpoint of the association.
    """

    __slots__ = ("bssid", "station", "handshake", "essid", "essid_raw", "akms", "_hashes",
                 "auth_alg", "security", "ft")

    def __init__(self, handshake, essid=None, essid_raw=None, akms=(), auth_alg=None,
                 security=None, ft=None):
        self.handshake = handshake
        self.bssid = handshake.bssid if handshake is not None else None
        self.station = handshake.station if handshake is not None else None
        self.essid = essid
        #: The SSID's real octets. `essid` is a lossy utf-8/replace decode and the ESSID is
        #: the PBKDF2 salt, so the hash has to be built from these.
        self.essid_raw = essid_raw
        #: The AP's advertised set; `negotiated_akms` narrows it to this association.
        self.akms = tuple(akms or ())
        #: Auth algorithm for this pair: 0 Open System, 2 FT, 3 SAE.
        self.auth_alg = auth_alg
        #: The AP's SecurityInfo - needed for "was SAE reachable here at all".
        self.security = security
        #: 802.11r material for this pair, when the capture caught a roam.
        self.ft = ft
        self._hashes = None

    @property
    def negotiated_akms(self) -> tuple:
        """The AKMs this association used, narrowed by the auth algorithm.

        A BSS offering both PSK and SAE reports every association as PSK if you take its
        advertised set verbatim, including the SAE ones that are not crackable at all.
        """
        if self.ft is not None and self.ft.akms:
            # An FT Auth RSNE carries the single selected AKM - the most direct evidence there is.
            return self.ft.akms
        if self.auth_alg == AUTH_ALG_SAE:
            sae_akms = tuple(a for a in self._reachable if a in AKM_WPA3_PERSONAL)
            return sae_akms or (8,)
        if self.auth_alg == AUTH_ALG_OPEN:
            non_sae = tuple(a for a in self._reachable if a not in AKM_WPA3_PERSONAL)
            if non_sae:
                return non_sae
        return self.akms

    @property
    def _reachable(self) -> tuple:
        if self.security is not None:
            return self.security.all_akms
        return self.akms

    @property
    def node_type(self) -> str:
        from . import crypto

        has_rsn = self.security.has_rsn if self.security is not None else True
        mfp_required = self.security.mfp_required if self.security is not None else False
        return crypto.handshake_type(
            self.negotiated_akms, has_rsn=has_rsn, mfp_required=mfp_required)

    @property
    def downgraded(self) -> bool:
        """A PSK-family association on a BSS where SAE was reachable.

        I.e. a crackable handshake over the passphrase that also protects the network's SAE.
        """
        if self.security is None or not self.security.offers_sae:
            return False
        return not set(self.negotiated_akms) & AKM_WPA3_PERSONAL

    @property
    def downgrade_status(self) -> str:
        """Always written, because "no" and "cannot tell" differ.

        `compatibility_mode`: SAE reachable only through a vendor element (§2.4).
        `transition_mode`: SAE beside PSK in the real RSNE, so a conforming client picks SAE
        and reaching PSK needs an attacker or a PSK-only profile.
        """
        if self.security is None:
            return "unknown"
        if not self.security.offers_sae:
            return "not_applicable"
        if not self.downgraded:
            return "none"
        return "compatibility_mode" if self.security.compatibility_mode else "transition_mode"

    @property
    def hashes(self):
        """`(pmkid_line, eapol_line, status)`, computed once."""
        if self._hashes is None:
            from . import hc22000

            # `negotiated_akms`, not `akms`: the AP's set makes an SAE association look PSK,
            # which emitted a PMKID line that could never crack.
            self._hashes = hc22000.build(
                self.handshake, self.bssid, self.station,
                akms=self.negotiated_akms, essid_raw=self.essid_raw, essid=self.essid)
        return self._hashes

    @property
    def exchange(self) -> str:
        """Which exchange authenticated this pair: ``4way``, ``ft_auth``, or both.

        A property, not a node type: 802.11r changes key delivery, not the credential.
        """
        parts = []
        if self.handshake is not None and self.handshake.messages:
            parts.append("4way")
        if self.ft is not None:
            parts.append("ft_auth")
        return ",".join(parts)

    @property
    def ft_hashes(self):
        """``(hc37100_line, status)`` for the 802.11r material, if any."""
        if self.ft is None:
            return None, None
        from . import ft as ft_module

        status = self.ft.status(essid_raw=self.essid_raw)
        if status != ft_module.STATUS_OK:
            return None, status
        return ft_module.render(self.ft, self.essid_raw), status

    @property
    def akm(self) -> str:
        """Suite names for what this association negotiated."""
        names = []
        for akm in self.negotiated_akms:
            name = AKM_SUITES.get(akm, f"AKM-{akm}")
            if name not in names:
                names.append(name)
        return ",".join(names)

    @property
    def crackable(self) -> bool:
        """Whether a hash an operator can actually run was produced.

        Narrower than `Handshake.has_key_material`, and deliberately so: that one
        answered "was enough material captured", which said yes to an 802.1X handshake whose
        PMK never came from a passphrase, and to a 4-way whose only client frame exceeded the
        255-byte cap hashcat's loader enforces. Both looked crackable and neither was.
        """
        pmkid, eapol, _ = self.hashes
        return bool(pmkid or eapol)

    @property
    def id(self) -> str:
        """The pair key the tracker already uses. Stable across re-runs of one capture."""
        return f"{self.bssid}|{self.station}"

    @property
    def name(self) -> str:
        return f"{self.station} - {self.essid or self.bssid}"

    @property
    def eap_method_names(self) -> str:
        """Method names in numeric order, unknown ones kept as their number rather than
        dropped - an unrecognised method is still evidence about the network."""
        from .constants import EAP_METHODS

        return ",".join(EAP_METHODS.get(m, str(m)) for m in sorted(self.handshake.eap_methods))

    def to_node_dict(self, tz=None) -> dict:
        handshake = self.handshake
        pmkid_hash, eapol_hash, status = self.hashes
        ft_hash, ft_status = self.ft_hashes
        return compact({
            "id": self.id,
            "node_type": self.node_type,
            "name": self.name,
            "bssid": self.bssid,
            "station": self.station,
            "akm": self.akm or None,
            "auth_alg": AUTH_ALG_NAMES.get(self.auth_alg),
            "exchange": self.exchange,
            "downgraded": True if self.downgraded else None,
            # Always written: "no SAE to downgrade from" and "could not tell" differ.
            "downgrade_status": self.downgrade_status,
            "messages": handshake.message_list or None,
            "handshake": handshake.count or None,
            "handshake_complete": True if handshake.complete else None,
            "crackable": True if self.crackable else None,
            "hc22000_pmkid": pmkid_hash,
            "hc22000_eapol": eapol_hash,
            # Written whatever the answer, like `pin_attack_status` and for the same reason:
            # a true-only boolean cannot tell "ruled out" from "not yet captured", and the
            # difference decides whether an operator keeps listening or moves on.
            "hc22000_status": status,
            "pmkid": handshake.pmkid,
            "identity": handshake.identity,
            "eap_methods": self.eap_method_names or None,
            "eap_outcome": handshake.eap_outcome,
            "certificates": len(handshake.certificates) or None,
            # -- 802.11r --------------------------------------------------------------------
            "pmkr0name": self.ft.pmkr0name.hex() if self.ft and self.ft.pmkr0name else None,
            "mdid": self.ft.mdid.hex() if self.ft and self.ft.mdid else None,
            "r0kh_id": _decode_kh(self.ft.r0kh_id) if self.ft else None,
            "r1kh_id": _decode_kh(self.ft.r1kh_id) if self.ft else None,
            "hc37100": ft_hash,
            "hc37100_status": ft_status,
            "first_time_seen": format_timestamp(handshake.first_ts, tz),
            "last_time_seen": format_timestamp(handshake.last_ts, tz),
        })


class CertificateRecord:
    """One X.509 certificate from an authentication server's chain.

    Keyed by SHA-256 fingerprint rather than by common name: a CN is neither unique across
    organisations nor stable across a re-issue, and collapsing two different certificates
    that share a CN would erase exactly the signal worth having. Two APs presenting the *same*
    certificate converging on one node is the other half of that - it is how a single RADIUS
    deployment becomes visible behind many BSSIDs.
    """

    __slots__ = ("info", "chain_depth")

    def __init__(self, info, chain_depth=None):
        self.info = info
        #: Position in the chain it was first seen in; 0 is the server's own certificate.
        self.chain_depth = chain_depth

    @property
    def id(self) -> str:
        return self.info.fingerprint

    def to_node_dict(self, tz=None) -> dict:
        info = self.info
        return compact({
            "id": info.fingerprint,
            "node_type": "TLSCertificate",
            "name": info.name,
            "fingerprint": info.fingerprint,
            "common_name": info.common_name,
            "subject": info.subject,
            "issuer": info.issuer,
            "issuer_common_name": info.issuer_common_name,
            "serial": info.serial,
            # Already UTC and explicit in the certificate, unlike airodump's local-time
            # columns, so these are not shifted by --capture-tz.
            "not_before": info.not_before,
            "not_after": info.not_after,
            "signature_algorithm": info.signature_algorithm,
            "san": ",".join(info.san) or None,
            "is_ca": True if info.is_ca else None,
            "self_signed": True if info.self_signed else None,
            "chain_depth": self.chain_depth,
        })


class WPSRecord:
    """One AP's WPS implementation, as a node rather than a boolean on the radio.

    `APRecord.wps` stays exactly as it was - the flag is already documented, already queried,
    and costs nothing. What the node adds is the state the flag cannot hold: whether the AP
    is in setup lockout, whether it is configured, and which config methods it advertises.
    Those together are what decides whether a PIN attack is worth the hours, and that verdict
    is a property of the WPS implementation rather than of the radio carrying it.
    """

    __slots__ = ("bssid", "essid", "info", "first_ts", "last_ts")

    def __init__(self, bssid, info, essid=None, first_ts=None, last_ts=None):
        self.bssid = bssid
        self.info = info
        self.essid = essid
        self.first_ts = first_ts
        self.last_ts = last_ts

    @property
    def id(self) -> str:
        """Suffixed, and the suffix is not cosmetic.

        Node ids are globally unique across every label. The id index is `NOTUNIQUE`, so
        nothing would reject a duplicate, and `Exposes` matches its source on `Device` - which
        every type nests under - so a WPS node sharing the BSSID would let the edge resolve
        onto the AP itself and write a self-loop.
        """
        return f"{self.bssid}|wps"

    @property
    def name(self) -> str:
        return f"WPS - {self.essid or self.bssid}"

    def to_node_dict(self, tz=None) -> dict:
        info = self.info
        return compact({
            "id": self.id,
            "node_type": "WPS",
            "name": self.name,
            "bssid": self.bssid,
            "version": info.version_name,
            "state": info.state_name,
            "config_methods": info.config_methods_names or None,
            "device_password_id": info.device_password_name,
            "ap_setup_locked": True if info.ap_setup_locked else None,
            "selected_registrar": True if info.selected_registrar else None,
            # Written whatever the answer, unlike every boolean here. A true-only property
            # cannot distinguish "ruled out" from "never observed", and ruling an AP out from
            # a passive capture is half of why this node exists.
            "pin_attack_status": info.pin_attack_status,
            "pin_attack_viable": True if info.pin_attack_viable else None,
            "first_time_seen": format_timestamp(self.first_ts, tz),
            "last_time_seen": format_timestamp(self.last_ts, tz),
        })
