"""802.11 fixed-header decode and address-role resolution.

The two rules in here are what the whole parity result rests on, so they are stated once and
used everywhere:

**BSSID resolution** depends on the ToDS/FromDS pair, not the frame subtype. Management
frames always have both clear, which is why beacons, probe responses, deauths and auths all
resolve through the same branch.

**Station resolution** additionally drops any frame whose transmitter *is* the BSSID. That
single clause is what stops a beacon from creating a Client node for every AP, and what stops
the *receiver* of an AP-sent deauth from being promoted to a station - the case that produced
the one false positive when this was first measured against the ground-truth CSV.

Control frames are excluded before either rule runs. They have no ToDS/FromDS semantics, so
attributing their addresses to an AP or a station would be guesswork, and including them
inflates the station count well past what airodump reports.
"""
from .constants import BROADCAST, DATA_SUBTYPE_QOS_BIT, FrameType

#: Distinct MACs are few (a couple of hundred in a typical capture) while frames are many, so
#: formatting is cached by raw bytes. Without this, MAC formatting dominates the whole parse.
_MAC_CACHE = {}

#: Bounded so a pathological capture full of corrupted addresses cannot grow it without
#: limit. Clearing wholesale is fine - it is a pure cache.
_MAC_CACHE_LIMIT = 500_000


def fmt_mac(raw: bytes) -> str:
    """Canonical MAC form: uppercase, colon-separated.

    This is the *only* place raw bytes become a MAC string. scapy emits lowercase while
    airodump and macaddress.io-db.json are uppercase; mixing the two forks every node and
    silently breaks vendor lookup, so there is exactly one call site by design.
    """
    cached = _MAC_CACHE.get(raw)
    if cached is None:
        if len(_MAC_CACHE) >= _MAC_CACHE_LIMIT:
            _MAC_CACHE.clear()
        cached = _MAC_CACHE[raw] = raw.hex(":").upper()
    return cached


def is_group(mac: str) -> bool:
    """Whether the address is group-addressed (broadcast or multicast).

    Tests the I/G bit of the first octet rather than matching known prefixes. That is
    exhaustive by construction - it covers FF:FF:FF:FF:FF:FF, 01:00:5E (IPv4 multicast),
    33:33 (IPv6), 01:80:C2 (802.1D) and everything else - whereas a prefix list is always one
    protocol behind.
    """
    return bool(int(mac[0:2], 16) & 0x01)


def is_locally_administered(mac: str) -> bool:
    """Whether the address is locally administered, i.e. almost certainly randomized.

    Worth recording: most modern stations randomize, OUI lookup returns nothing for them, and
    the flag explains the gap instead of leaving it unexplained.
    """
    return bool(int(mac[0:2], 16) & 0x02)


class Frame:
    """One decoded 802.11 frame.

    Addresses are decoded eagerly but formatted through the shared cache, and the object is
    slotted because one is built per frame.
    """

    __slots__ = (
        "ts", "raw", "type", "subtype", "to_ds", "from_ds", "protected", "retry",
        "more_frag", "order", "addr1", "addr2", "addr3", "addr4", "seq", "frag",
        "body_offset", "radio",
    )

    def __init__(self, ts, raw, type_, subtype, to_ds, from_ds, protected, retry,
                 more_frag, order, addr1, addr2, addr3, addr4, seq, frag, body_offset, radio):
        self.ts = ts
        self.raw = raw
        self.type = type_
        self.subtype = subtype
        self.to_ds = to_ds
        self.from_ds = from_ds
        self.protected = protected
        self.retry = retry
        self.more_frag = more_frag
        self.order = order
        self.addr1 = addr1
        self.addr2 = addr2
        self.addr3 = addr3
        self.addr4 = addr4
        self.seq = seq
        self.frag = frag
        self.body_offset = body_offset
        self.radio = radio

    # -- role resolution --------------------------------------------------

    @property
    def bssid(self):
        """The BSSID this frame belongs to, or None if it cannot be resolved.

        | ToDS | FromDS | BSSID | addr1 | addr2 | addr3 | addr4 |
        |------|--------|-------|-------|-------|-------|-------|
        |   0  |    0   | addr3 |  DA   |  SA   | BSSID |   -   |
        |   1  |    0   | addr1 | BSSID |  SA   |  DA   |   -   |
        |   0  |    1   | addr2 |  DA   | BSSID |  SA   |   -   |
        |   1  |    1   | addr2 |  RA   |  TA   |  DA   |  SA   |

        Control frames have no such semantics and always return None. A group-addressed
        result is the wildcard BSSID of a probe request, not a real AP, so it is rejected
        here rather than at every call site.
        """
        if self.type == FrameType.CTRL:
            return None

        if self.to_ds:
            candidate = self.addr1 if not self.from_ds else self.addr2
        else:
            candidate = self.addr2 if self.from_ds else self.addr3

        if candidate is None or candidate == BROADCAST or is_group(candidate):
            return None
        return candidate

    def station(self, bssid=None):
        """The station this frame is attributable to, or None.

        `bssid` is passed in when the caller already resolved it, to avoid resolving twice.
        """
        if self.type == FrameType.CTRL:
            return None

        if self.to_ds and self.from_ds:
            # WDS / mesh: addr2 is the transmitting AP and addr4 the original source.
            # Neither endpoint is a station, which is what airodump also concludes.
            return None

        if self.to_ds:
            candidate = self.addr2                  # STA -> AP, so addr2 is the source
        elif self.from_ds:
            candidate = self.addr1                  # AP -> STA, so addr1 is the destination
        else:
            if bssid is None:
                bssid = self.bssid
            # An AP transmitting its own management frame is not a station. This is a
            # transmitter-identity test rather than a subtype allowlist, so it cannot drift
            # as subtypes are added.
            if self.addr2 is not None and self.addr2 == bssid:
                return None
            candidate = self.addr2

        if candidate is None or candidate == BROADCAST or is_group(candidate):
            return None
        return candidate

    @property
    def is_null_data(self) -> bool:
        """Null / QoS-Null: a data frame carrying no payload.

        Counts toward a station's packet total but never toward the WEP IV count, which is
        what airodump's '# IV' column means.
        """
        return self.type == FrameType.DATA and bool(self.subtype & 0x04)

    def __repr__(self):
        return (f"<Frame t={self.type} s={self.subtype} "
                f"{self.addr2}->{self.addr1} bssid={self.bssid}>")


def decode(ts, raw, radio=None):
    """Decode one frame's fixed header. Returns None if it is too short to be meaningful.

    Everything after the header is left as a memoryview slice for the IE walker; nothing is
    copied here.
    """
    length = len(raw)
    if length < 10:
        return None

    fc0 = raw[0]
    fc1 = raw[1]
    type_ = (fc0 >> 2) & 0x03
    subtype = (fc0 >> 4) & 0x0F

    to_ds = bool(fc1 & 0x01)
    from_ds = bool(fc1 & 0x02)
    more_frag = bool(fc1 & 0x04)
    retry = bool(fc1 & 0x08)
    protected = bool(fc1 & 0x40)
    order = bool(fc1 & 0x80)

    addr1 = fmt_mac(bytes(raw[4:10])) if length >= 10 else None
    addr2 = fmt_mac(bytes(raw[10:16])) if length >= 16 else None
    addr3 = fmt_mac(bytes(raw[16:22])) if length >= 22 else None

    seq = frag = None
    if length >= 24:
        sc = raw[22] | (raw[23] << 8)
        frag = sc & 0x0F
        seq = sc >> 4

    four_address = to_ds and from_ds
    addr4 = fmt_mac(bytes(raw[24:30])) if four_address and length >= 30 else None

    # Body offset: 24-byte base, +6 for the fourth address, +2 for QoS Control on a QoS data
    # frame, +4 for HT Control when the Order/+HTC bit is set. Getting the HT Control case
    # wrong shifts every information element by four bytes, which typically drops the last IE
    # in the chain - and that is often the RSN element.
    body_offset = 24
    if four_address:
        body_offset += 6
    if type_ == FrameType.DATA and (subtype & DATA_SUBTYPE_QOS_BIT):
        body_offset += 2
        if order:
            body_offset += 4
    elif type_ == FrameType.MGMT and order:
        body_offset += 4

    return Frame(ts, raw, type_, subtype, to_ds, from_ds, protected, retry, more_frag,
                 order, addr1, addr2, addr3, addr4, seq, frag, body_offset, radio)
