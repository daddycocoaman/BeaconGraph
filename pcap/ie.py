"""Information element walking and typed accessors.

Two rules govern the walker, and both exist because element lengths are attacker-controlled:

1. Never trust the declared length - always bounds-check it against the real buffer.
2. On overrun, keep everything parsed so far rather than discarding it. A beacon with a valid
   SSID followed by a bogus `len=255` element should still yield the SSID.

The sample capture happens to have no truncation at all (every record has
``incl_len == orig_len``), so this path is purely defensive there - but a capture taken with
``-s 256`` ends most beacons mid-element, and a naive walker is the most common way an 802.11
parser crashes.
"""
from .constants import (
    EID,
    MS_OUI,
    RATE_SELECTORS,
    VENDOR_RSNE_OVERRIDE,
    VENDOR_RSNE_OVERRIDE_2,
    VENDOR_RSNXE_OVERRIDE,
    VENDOR_WPS,
)


def bit(body, index: int):
    """One bit of a little-endian capability bitfield, or None if the field is too short.

    The tri-state matters: Beacon Protection is bit 84, needing an 11-octet element, and most
    APs send 8. False there would manufacture a finding; None omits the property instead.
    """
    if body is None:
        return None
    octet, offset = divmod(index, 8)
    if octet >= len(body):
        return None
    return bool(body[octet] & (1 << offset))


def walk(buf, start: int):
    """Yield ``(element_id, body)`` pairs, stopping cleanly at a malformed or truncated tail.

    ``body`` is a memoryview slice into ``buf`` - nothing is copied. For the Element ID
    Extension (255) the id is yielded as the tuple ``(255, ext_id)`` and the body excludes
    that first byte, so HE and EHT elements slot in without reworking callers.
    """
    position, end = start, len(buf)
    while position + 2 <= end:
        eid = buf[position]
        length = buf[position + 1]
        body_end = position + 2 + length
        if body_end > end:
            return  # truncated tail; keep what the caller already has
        body = buf[position + 2:body_end]
        if eid == EID.EXTENSION:
            if length >= 1:
                yield (EID.EXTENSION, body[0]), body[1:]
        else:
            yield eid, body
        position = body_end


class IEMap:
    """The elements of one frame, keyed by id.

    Elements can legitimately repeat (multiple vendor-specific elements are the norm), so
    every id maps to a list and ``first()`` is the common accessor.
    """

    __slots__ = ("_elements", "truncated")

    def __init__(self, elements=None, truncated: bool = False):
        self._elements = elements if elements is not None else {}
        self.truncated = truncated

    def __contains__(self, eid) -> bool:
        return eid in self._elements

    def __len__(self) -> int:
        return sum(len(v) for v in self._elements.values())

    def first(self, eid):
        found = self._elements.get(eid)
        return found[0] if found else None

    def all(self, eid) -> list:
        return self._elements.get(eid, [])

    def vendor(self, oui: bytes, vendor_type: int):
        """The body of a vendor-specific element, past its 4-byte OUI+type header."""
        for body in self._elements.get(EID.VENDOR_SPECIFIC, []):
            if len(body) >= 4 and bytes(body[0:3]) == oui and body[3] == vendor_type:
                return body[4:]
        return None

    def vendor_all(self, oui: bytes, vendor_type: int):
        """Every matching vendor element body, concatenated, or None if there are none.

        A vendor payload longer than 251 bytes is legally split across consecutive
        vendor-specific elements that the receiver joins back together - WSC says so
        explicitly, and a probe response carrying Device Name, Model Name and Serial Number
        gets there. ``vendor()`` returns only the first, which silently truncates exactly the
        attributes that arrive last. Callers that can see a long payload use this instead.
        """
        found = [
            body[4:]
            for body in self._elements.get(EID.VENDOR_SPECIFIC, [])
            if len(body) >= 4 and bytes(body[0:3]) == oui and body[3] == vendor_type
        ]
        if not found:
            return None
        if len(found) == 1:
            return found[0]  # the common case: no copy, still a memoryview
        return b"".join(bytes(part) for part in found)

    def vendor_ouis(self) -> set:
        """Every ``(oui, type)`` pair present. A cheap device fingerprint."""
        return {
            (bytes(body[0:3]), body[3])
            for body in self._elements.get(EID.VENDOR_SPECIFIC, [])
            if len(body) >= 4
        }

    # -- typed accessors --------------------------------------------------

    @property
    def ssid(self):
        """``(name, raw_bytes, hidden)``, or None when no SSID element is present.

        Three states have to stay distinct, and conflating them is the classic bug:
        zero-length means broadcast-suppressed; a non-zero run of nulls means the length was
        preserved but the name masked (Cisco style), which is where airodump's ``ID-length``
        column comes from; anything else is a real name.

        SSIDs are an opaque octet string, not text, so the decode is lossy by necessity -
        ``errors="replace"`` rather than ``surrogateescape`` because surrogates cannot be
        serialized through the Bolt driver or ArcadeDB's JSON batch endpoint and would raise
        at write time. The exact bytes are returned alongside for callers that need them.
        """
        body = self.first(EID.SSID)
        if body is None:
            return None
        raw = bytes(body)
        if not raw or all(byte == 0 for byte in raw):
            return None, raw, True
        return raw.decode("utf-8", errors="replace"), raw, False

    @property
    def channel(self):
        """Primary channel from the DS Parameter Set, falling back to HT Operation."""
        body = self.first(EID.DS_PARAMETER_SET)
        if body is not None and len(body) >= 1:
            return body[0]
        body = self.first(EID.HT_OPERATION)
        if body is not None and len(body) >= 1:
            return body[0]
        return None

    def rates(self, include_extended: bool = True) -> list:
        """Advertised legacy rates in Mbps.

        Each byte is a rate in 500 kbps units with bit 7 flagging it as basic. Values 126 and
        127 are HT/VHT membership selectors rather than rates and are dropped - leaving them
        in yields a nonsense 63 Mbps maximum.
        """
        found = []
        elements = [EID.SUPPORTED_RATES]
        if include_extended:
            elements.append(EID.EXTENDED_RATES)
        for eid in elements:
            for body in self.all(eid):
                for byte in body:
                    value = byte & 0x7F
                    if value not in RATE_SELECTORS:
                        found.append(value / 2)
        return found

    @property
    def ht_capabilities(self):
        return self.first(EID.HT_CAPABILITIES)

    @property
    def ht_operation(self):
        return self.first(EID.HT_OPERATION)

    @property
    def vht_capabilities(self):
        return self.first(EID.VHT_CAPABILITIES)

    @property
    def vht_operation(self):
        return self.first(EID.VHT_OPERATION)

    @property
    def he_capabilities(self):
        return self.first((EID.EXTENSION, 35))

    @property
    def erp(self):
        return self.first(EID.ERP)

    @property
    def rsn(self):
        return self.first(EID.RSN)

    @property
    def wpa1(self):
        """The WPA1 vendor element (OUI 00:50:F2, type 1), body past the header.

        Its layout is identical to RSN's but with 00-50-F2 suite selectors.
        """
        return self.vendor(MS_OUI, 1)

    @property
    def wps(self):
        """The WPS vendor element (OUI 00:50:F2, type 4), reassembled if fragmented.

        ``vendor_all`` rather than ``vendor``: the WSC payload is the one in this file that
        routinely outgrows a single element.
        """
        return self.vendor_all(*VENDOR_WPS)

    @property
    def rsnx(self):
        """Extended RSN Capabilities (EID 244). Carries the SAE H2E and SAE-PK bits."""
        return self.first(EID.RSNX)

    @property
    def extended_capabilities(self):
        """Extended Capabilities (EID 127). Bit 84 is Beacon Protection Enabled."""
        return self.first(EID.EXTENDED_CAPABILITIES)

    @property
    def rsne_override(self):
        """The RSNE Override element, body past the header - a verbatim RSNE body.

        Where Compatibility Mode hides SAE. Reading only `rsn` on such an AP sees PSK with
        PMF off and calls it WPA2 - which is what a non-RSNO client concludes too.
        """
        return self.vendor(*VENDOR_RSNE_OVERRIDE)

    @property
    def rsne_override_2(self):
        """The RSNE Override 2 element. A second variant, offered alongside the first."""
        return self.vendor(*VENDOR_RSNE_OVERRIDE_2)

    @property
    def rsnxe_override(self):
        """The RSNXE Override element - a verbatim RSNXE body."""
        return self.vendor(*VENDOR_RSNXE_OVERRIDE)


def parse(buf, start: int) -> IEMap:
    """Walk a frame body into an IEMap, retaining whatever parsed before any malformed tail."""
    elements = {}
    consumed = start
    for eid, body in walk(buf, start):
        elements.setdefault(eid, []).append(body)
        consumed += 2 + len(body) + (1 if isinstance(eid, tuple) else 0)
    return IEMap(elements, truncated=consumed != len(buf))


def snapshot(ie_map: IEMap) -> IEMap:
    """Copy every element body to real bytes.

    Needed before retaining an IEMap past the frame it came from: the bodies are memoryview
    slices, and holding one keeps the entire frame buffer alive.
    """
    return IEMap(
        {eid: [bytes(body) for body in bodies] for eid, bodies in ie_map._elements.items()},
        truncated=ie_map.truncated,
    )
