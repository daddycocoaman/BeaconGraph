"""RSN / WPA information element parsing and encryption classification.

Replaces the substring chain in ``backend.parser._classifyBssid``, which tests
``"WPA2" in privacy`` then ``"WPA" in privacy`` and therefore *cannot* express WPA3 - the
string "WPA3" contains "WPA", and the WPA2 test runs first. That is why ``WPA3`` is declared
in ``labels.py``, in ``arcadedb.VERTEX_LABELS`` and in the frontend icon map, yet no CSV
ingest has ever produced one.

Classifying from the elements instead makes WPA3 reachable, and picks up three things the CSV
column set has nowhere to put: the real AKM suite names (802.1X and FT-802.1X both flatten to
``MGT``), management frame protection, and WPA2/WPA3 transition mode - which is a single RSN
element listing both PSK and SAE, so it is genuinely both and must render as both.
"""
import struct

from .constants import (
    AKM_AUTH_TOKENS,
    AKM_ENTERPRISE,
    AKM_OWE,
    AKM_SUITE_B,
    AKM_SUITES,
    AKM_WPA3_PERSONAL,
    CAP_PRIVACY,
    CIPHER_SUITES,
    EXTCAP_BEACON_PROTECTION,
    RSN_CAP_MFPC,
    RSN_CAP_MFPR,
    RSN_CAP_OCVC,
    RSNX_SAE_H2E,
    RSNX_SAE_PK,
)
from .ie import bit


class SuiteInfo:
    """One parsed RSN-shaped element: RSN itself, or the WPA1 vendor element."""

    __slots__ = ("version", "group_cipher", "pairwise_ciphers", "akms",
                 "mfp_capable", "mfp_required", "pmkid", "capabilities")

    def __init__(self, version=1, group_cipher=None, pairwise_ciphers=(), akms=(),
                 mfp_capable=False, mfp_required=False, pmkid=None, capabilities=None):
        self.version = version
        self.group_cipher = group_cipher
        self.pairwise_ciphers = tuple(pairwise_ciphers)
        self.akms = tuple(akms)
        self.mfp_capable = mfp_capable
        self.mfp_required = mfp_required
        self.pmkid = pmkid
        #: Raw RSN Capabilities u16; None when the element was too short to carry it.
        self.capabilities = capabilities

    @property
    def ocv(self):
        """Operating Channel Validation Capable, or ``None`` if the field was absent."""
        if self.capabilities is None:
            return None
        return bool(self.capabilities & RSN_CAP_OCVC)


def _suites(body, offset, count, oui_length=3):
    """Read `count` 4-byte suite selectors, returning their type bytes."""
    found = []
    for index in range(count):
        start = offset + index * 4
        if start + 4 > len(body):
            break
        found.append(body[start + oui_length])
    return found


def parse_suite_element(body, expect_vendor_header: bool = False):
    """Parse an RSN element, or a WPA1 vendor element with the same layout.

    Set `expect_vendor_header` only when passing a raw vendor element that still carries its
    4-byte OUI+type prefix; ``IEMap.wpa1`` has already stripped that.

    Every field after the version is optional in the sense that the element may simply end,
    so the cursor is bounds-checked at each step and a short element yields a partial result
    rather than raising.
    """
    if body is None:
        return None
    body = bytes(body)

    position = 4 if expect_vendor_header else 0
    if len(body) < position + 2:
        return None

    version = struct.unpack_from("<H", body, position)[0]
    position += 2

    group = None
    if position + 4 <= len(body):
        group = body[position + 3]
        position += 4

    pairwise = ()
    if position + 2 <= len(body):
        count = struct.unpack_from("<H", body, position)[0]
        position += 2
        pairwise = _suites(body, position, count)
        position += 4 * count

    akms = ()
    if position + 2 <= len(body):
        count = struct.unpack_from("<H", body, position)[0]
        position += 2
        akms = _suites(body, position, count)
        position += 4 * count

    mfp_capable = mfp_required = False
    capabilities = None
    if position + 2 <= len(body):
        capabilities = struct.unpack_from("<H", body, position)[0]
        position += 2
        mfp_required = bool(capabilities & RSN_CAP_MFPR)
        mfp_capable = bool(capabilities & RSN_CAP_MFPC)

    pmkid = None
    if position + 2 <= len(body):
        count = struct.unpack_from("<H", body, position)[0]
        position += 2
        if count and position + 16 <= len(body):
            pmkid = body[position:position + 16]

    return SuiteInfo(version, group, pairwise, akms, mfp_capable, mfp_required, pmkid,
                     capabilities)


class SecurityInfo:
    """The security posture of one BSSID, in both airodump's vocabulary and a fuller one."""

    __slots__ = ("protocols", "group_cipher", "pairwise_ciphers", "akms",
                 "mfp_capable", "mfp_required", "pmkid", "has_rsn", "has_wpa1", "privacy_bit",
                 "ocv", "override_akms", "rsn_overriding", "sae_h2e", "sae_pk",
                 "beacon_protection")

    def __init__(self, protocols=(), group_cipher=None, pairwise_ciphers=(), akms=(),
                 mfp_capable=False, mfp_required=False, pmkid=None,
                 has_rsn=False, has_wpa1=False, privacy_bit=False, ocv=None,
                 override_akms=(), rsn_overriding=False, sae_h2e=None, sae_pk=None,
                 beacon_protection=None):
        self.protocols = tuple(protocols)
        self.group_cipher = group_cipher
        self.pairwise_ciphers = tuple(pairwise_ciphers)
        self.akms = tuple(akms)
        self.mfp_capable = mfp_capable
        self.mfp_required = mfp_required
        self.pmkid = pmkid
        self.has_rsn = has_rsn
        self.has_wpa1 = has_wpa1
        self.privacy_bit = privacy_bit
        #: Tri-state: True, False, or None for "the element was too short to say".
        self.ocv = ocv
        #: AKMs from an RSNE Override. Kept out of `akms`, which stays the real RSNE's set for
        #: CSV parity - it is also what a legacy client actually sees.
        self.override_akms = tuple(override_akms)
        self.rsn_overriding = rsn_overriding
        self.sae_h2e = sae_h2e
        self.sae_pk = sae_pk
        self.beacon_protection = beacon_protection

    @property
    def all_akms(self) -> tuple:
        """Every AKM reachable on this BSS, real element and override alike."""
        return self.akms + tuple(a for a in self.override_akms if a not in self.akms)

    @property
    def offers_sae(self) -> bool:
        """Whether SAE can be negotiated here at all, however well hidden."""
        return bool(set(self.all_akms) & AKM_WPA3_PERSONAL)

    @property
    def compatibility_mode(self) -> bool:
        """SAE reachable *only* through an override element - WPA3 spec §2.4.

        A client without RSN-overriding support cannot see the SAE half, so it associates as
        WPA2-PSK over the same passphrase with no attacker involved.
        """
        return bool(set(self.override_akms) & AKM_WPA3_PERSONAL) and not (
            set(self.akms) & AKM_WPA3_PERSONAL)

    @property
    def override_akm(self) -> str:
        """The AKM names reachable only through an override element."""
        hidden = [a for a in self.override_akms if a not in self.akms]
        names = []
        for akm in hidden:
            name = AKM_SUITES.get(akm, f"AKM-{akm}")
            if name not in names:
                names.append(name)
        return ",".join(names)

    @property
    def privacy(self):
        """airodump's Privacy column: "WPA2", "WPA3 WPA2", "WPA2 WPA", "WEP", "OPN".

        Note "OPN" rather than "Open": the CSV column and the graph node type use different
        spellings for the same thing, and this property is the CSV dialect. `node_type` is
        the graph one, and has to stay "Open" to match the existing label set in
        ``backend/backend/labels.py`` and the frontend icon map.
        """
        if not self.protocols:
            return None
        return " ".join("OPN" if p == "Open" else p for p in self.protocols)

    @property
    def node_type(self):
        """The graph type: the most modern protocol the AP speaks."""
        return self.protocols[0] if self.protocols else "AP"

    @property
    def cipher(self):
        """airodump's Cipher column. Multi-value is space-separated, first-seen order."""
        names = [CIPHER_SUITES.get(c, f"?{c}") for c in self.pairwise_ciphers]
        deduped = list(dict.fromkeys(n for n in names if n != "GROUP"))
        if not deduped and self.group_cipher is not None:
            deduped = [CIPHER_SUITES.get(self.group_cipher, f"?{self.group_cipher}")]
        return " ".join(deduped) if deduped else None

    @property
    def auth(self):
        """airodump's Authentication column - the coarse token set, deduplicated.

        802.1X and FT-802.1X both collapse to ``MGT`` here, matching the CSV exactly. The
        distinction survives in `akm`.
        """
        tokens = [AKM_AUTH_TOKENS.get(a) for a in self.akms]
        deduped = list(dict.fromkeys(t for t in tokens if t))
        return " ".join(deduped) if deduped else None

    @property
    def akm(self):
        """The real AKM suite names, which the CSV has nowhere to put."""
        names = [AKM_SUITES.get(a, f"?{a}") for a in self.akms]
        deduped = list(dict.fromkeys(names))
        return ",".join(deduped) if deduped else None

    @property
    def pmf(self):
        """"required", "capable" or "disabled" - None when nothing is known."""
        if not self.has_rsn:
            # WEP and WPA1 predate 802.11w entirely, so PMF cannot exist. That is a fact
            # about the protocol, not a missing observation.
            return "disabled" if (self.has_wpa1 or self.privacy_bit or self.protocols) else None
        if self.mfp_required:
            return "required"
        return "capable" if self.mfp_capable else "disabled"


def classify(rsn_element=None, wpa1_element=None, capability=None,
             saw_unencrypted_data=False, saw_encrypted_data=False, saw_sae_auth=False,
             rsne_override_element=None, rsne_override_2_element=None,
             rsnx_element=None, rsnxe_override_element=None, extcap_element=None):
    """Work out what security a BSSID runs.

    Returns a SecurityInfo whose `protocols` is ordered most-modern-first, so WPA2/WPA3
    transition mode renders as "WPA3 WPA2" and a WPA/WPA2 mixed AP as "WPA2 WPA".

    Compatibility Mode goes through the same branch: SAE in the override and PSK in the real
    element is genuinely both. What differs is reachability, which `compatibility_mode` reports.
    """
    rsn = parse_suite_element(rsn_element)
    # No vendor-header skip here: IEMap.wpa1 already returns the body past the 4-byte
    # OUI+type, so the remainder is laid out exactly like an RSN element.
    wpa1 = parse_suite_element(wpa1_element)
    # Override bodies are verbatim RSNE bodies.
    overrides = [parse_suite_element(e)
                 for e in (rsne_override_element, rsne_override_2_element) if e is not None]
    overrides = [o for o in overrides if o is not None]

    override_akms = []
    for override in overrides:
        override_akms += [a for a in override.akms if a not in override_akms]

    protocols, ciphers, akms = [], [], []
    group = None
    mfp_capable = mfp_required = False
    pmkid = None

    if rsn is not None or override_akms:
        akm_set = set(rsn.akms) if rsn is not None else set()
        # Same test transition mode uses: an override's SAE makes the BSS WPA3-capable.
        reachable = akm_set | set(override_akms)
        is_wpa3 = bool(
            reachable & AKM_WPA3_PERSONAL
            or reachable & AKM_OWE
            or reachable & AKM_SUITE_B
            # WPA3-Enterprise is "802.1X plus MFP required". Deliberately not extended to
            # WPA2-PSK+MFPR: plenty of WPA2 APs require MFP without being WPA3.
            or (rsn is not None and rsn.mfp_required and akm_set & AKM_ENTERPRISE)
            or any(o.mfp_required and set(o.akms) & AKM_ENTERPRISE for o in overrides)
        )
        is_wpa2 = bool(akm_set - AKM_WPA3_PERSONAL - AKM_OWE)

        if is_wpa3:
            protocols.append("WPA3")
        if is_wpa2 or not protocols:
            protocols.append("WPA2")

        if rsn is not None:
            ciphers += list(rsn.pairwise_ciphers)
            akms += list(rsn.akms)
            group = rsn.group_cipher
            mfp_capable, mfp_required = rsn.mfp_capable, rsn.mfp_required
            pmkid = rsn.pmkid

    if wpa1 is not None:
        protocols.append("WPA")
        ciphers += list(wpa1.pairwise_ciphers)
        akms += list(wpa1.akms)
        if group is None:
            group = wpa1.group_cipher

    if saw_sae_auth and "WPA3" not in protocols:
        # An SAE authentication frame proves WPA3 even when the beacon was never captured -
        # the cheapest WPA3 signal available on a partial capture.
        protocols.insert(0, "WPA3")

    privacy_bit = bool(capability is not None and capability & CAP_PRIVACY)

    if not protocols:
        if capability is not None:
            protocols = ["WEP"] if privacy_bit else ["Open"]
            if privacy_bit:
                ciphers = [1]
        elif saw_encrypted_data:
            protocols = ["WEP"]
        elif saw_unencrypted_data:
            # How airodump reaches "OPN" for a BSSID it never saw beacon: an unencrypted data
            # frame is enough. Reproducing it is the only way to match those CSV rows.
            protocols = ["Open"]

    return SecurityInfo(
        protocols=protocols,
        group_cipher=group,
        pairwise_ciphers=ciphers,
        akms=akms,
        mfp_capable=mfp_capable,
        mfp_required=mfp_required,
        pmkid=pmkid,
        has_rsn=rsn is not None,
        has_wpa1=wpa1 is not None,
        privacy_bit=privacy_bit,
        ocv=rsn.ocv if rsn is not None else None,
        override_akms=override_akms,
        rsn_overriding=bool(overrides) or rsnxe_override_element is not None,
        # The override twin stands in where present - it describes the SAE half of the BSS.
        sae_h2e=bit(rsnxe_override_element if rsnxe_override_element is not None
                    else rsnx_element, RSNX_SAE_H2E),
        sae_pk=bit(rsnxe_override_element if rsnxe_override_element is not None
                   else rsnx_element, RSNX_SAE_PK),
        beacon_protection=bit(extcap_element, EXTCAP_BEACON_PROTECTION),
    )


#: The bare parent, for a pair whose AKM the capture never established - as `AP` is for
#: encryption.
HANDSHAKE = "Handshake"


def handshake_type(akms=(), has_rsn=True, mfp_required=False) -> str:
    """The node type for one authentication exchange, from the AKM it negotiated.

    Same tables as `classify`, so an AP and a handshake on it can never disagree about what an
    AKM number means. The split is by where the PMK comes from, because that is the only thing
    an operator actually asks a handshake:

    * SAE family (8, 9, 24, 25) and Suite-B (11, 12) -> ``WPA3Handshake``, as is plain 802.1X
      with PMF required - `classify`'s definition, applied here so an AP and its own handshake
      cannot disagree.
    * OWE (18) -> ``OWEHandshake``. Unauthenticated by design - there is no passphrase to
      recover, which makes it a different answer from "we failed to recover one".
    * anything else under RSN -> ``WPA2Handshake``, FT-PSK included: 802.11r changes the
      exchange, not the credential.
    * no RSN at all -> ``WPAHandshake``, i.e. WPA1/TKIP.

    An empty `akms` returns the bare parent rather than guessing.
    """
    akm_set = set(akms)
    if not akm_set:
        return HANDSHAKE if has_rsn else "WPAHandshake"
    if (akm_set & AKM_WPA3_PERSONAL or akm_set & AKM_SUITE_B
            or (mfp_required and akm_set & AKM_ENTERPRISE)):
        return "WPA3Handshake"
    if akm_set & AKM_OWE:
        return "OWEHandshake"
    return "WPA2Handshake" if has_rsn else "WPAHandshake"


def band_for_channel(channel, has_he: bool = False):
    """Band from the channel number.

    Ambiguous between 2.4 and 6 GHz by construction - both number from 1 - so a low channel
    is only 6 GHz when the AP also advertises HE, and even then a radiotap frequency would be
    the authoritative answer. A DLT 105 capture has no frequency field to consult.
    """
    if channel is None:
        return None
    if 1 <= channel <= 14:
        return "2.4 GHz"
    if 36 <= channel <= 177:
        return "5 GHz"
    if has_he and channel <= 233:
        return "6 GHz"
    return None


def standard_for(elements, band=None):
    """PHY generation from the advertised elements, most modern first."""
    if elements.he_capabilities is not None:
        return "802.11ax"
    if elements.vht_capabilities is not None:
        return "802.11ac"
    if elements.ht_capabilities is not None:
        return "802.11n"
    if band == "5 GHz":
        return "802.11a"
    rates = elements.rates()
    if elements.erp is not None or any(r in rates for r in (6, 9, 12, 18, 24, 36, 48, 54)):
        return "802.11g"
    return "802.11b" if rates else None
