"""EAPOL decoding: 4-way handshake tracking, PMKID extraction, EAP identities.

A handshake is the highest-confidence association evidence there is, and - with a PMKID or
the right message pair - the thing an operator most wants the graph to surface.
"""
import struct

from . import tls
from .constants import (
    EAP_CODE_FAILURE,
    EAP_CODE_RESPONSE,
    EAP_CODE_SUCCESS,
    EAP_TLS_FLAG_LENGTH,
    EAP_TLS_FLAG_MORE,
    EAP_TLS_METHODS,
    EAPOL_TYPE_EAP_PACKET,
    EAPOL_TYPE_KEY,
    HC22000_EAPOL_MAX,
    KEY_INFO_ACK,
    KEY_INFO_MIC,
    KEY_INFO_PAIRWISE,
    KEY_INFO_SECURE,
    KEY_INFO_VERSION_MASK,
    RSN_OUI,
)

#: Offset of key_data_length within an EAPOL-Key body, for each plausible MIC width. The MIC
#: is 16 bytes for most AKMs but 24 for Suite-B SHA-384, so it cannot simply be assumed -
#: guessing wrong is the single biggest source of silently-wrong PMKID extraction.
_MIC_WIDTHS = (16, 24, 32)

#: An M4 whose SNonce was never filled in. Such a frame cannot contribute to a hc22000 line -
#: the nonce is half the PTK input - and hcxpcapngtool discards it outright.
_ZERO_NONCE = b"\x00" * 32
_FIXED_BEFORE_MIC = 1 + 2 + 2 + 8 + 32 + 16 + 8 + 8  # type, info, len, replay, nonce, iv, rsc, id


class KeyFrame:
    """One decoded EAPOL-Key frame."""

    __slots__ = ("descriptor_type", "key_info", "replay_counter", "nonce", "mic",
                 "key_data", "message")

    def __init__(self, descriptor_type, key_info, replay_counter, nonce, mic, key_data, message):
        self.descriptor_type = descriptor_type
        self.key_info = key_info
        self.replay_counter = replay_counter
        self.nonce = nonce
        self.mic = mic
        self.key_data = key_data
        self.message = message

    @property
    def from_authenticator(self) -> bool:
        """The Key ACK bit identifies the authenticator, i.e. the AP.

        Useful as an AP-versus-station discriminator that is completely independent of
        ToDS/FromDS - handy for corroborating the address-role matrix.
        """
        return bool(self.key_info & KEY_INFO_ACK)


def classify_message(key_info: int, key_data_length: int):
    """Which of M1-M4 an EAPOL-Key frame is, or a group-key message, or None.

    Verified against the real handshake in the sample capture, whose four frames carry
    key_info 0x008B, 0x010B, 0x13CB and 0x030B respectively.
    """
    if not key_info & KEY_INFO_PAIRWISE:
        return "G1" if key_info & KEY_INFO_ACK else "G2"

    ack = bool(key_info & KEY_INFO_ACK)
    mic = bool(key_info & KEY_INFO_MIC)
    secure = bool(key_info & KEY_INFO_SECURE)

    if ack and not mic:
        return "M1"
    if mic and ack:
        return "M3"
    if mic and not ack:
        # M2 carries the supplicant's RSN element; M4 carries no key data at all. On older
        # stacks that leave Secure clear on M4, the key data length is the tiebreak.
        if secure or key_data_length == 0:
            return "M4"
        return "M2"
    return None


def parse_key_frame(body):
    """Parse an EAPOL-Key body (everything past the 4-byte EAPOL header).

    The MIC width is resolved by trying each plausible value and keeping the one whose
    declared key_data_length matches the bytes actually remaining.
    """
    if len(body) < _FIXED_BEFORE_MIC + 2:
        return None

    descriptor_type = body[0]
    key_info = struct.unpack_from(">H", body, 1)[0]
    replay_counter = struct.unpack_from(">Q", body, 5)[0]
    nonce = bytes(body[13:45])

    for mic_width in _MIC_WIDTHS:
        offset = _FIXED_BEFORE_MIC + mic_width
        if offset + 2 > len(body):
            continue
        declared = struct.unpack_from(">H", body, offset)[0]
        if offset + 2 + declared == len(body):
            mic = bytes(body[_FIXED_BEFORE_MIC:offset])
            key_data = bytes(body[offset + 2:offset + 2 + declared])
            return KeyFrame(descriptor_type, key_info, replay_counter, nonce, mic,
                            key_data, classify_message(key_info, declared))

    # Nothing lined up - fall back to the common 16-byte MIC and take what is there, so a
    # slightly malformed frame still contributes its message type.
    offset = _FIXED_BEFORE_MIC + 16
    declared = struct.unpack_from(">H", body, offset)[0] if offset + 2 <= len(body) else 0
    return KeyFrame(descriptor_type, key_info, replay_counter, nonce,
                    bytes(body[_FIXED_BEFORE_MIC:offset]),
                    bytes(body[offset + 2:offset + 2 + declared]),
                    classify_message(key_info, declared))


def extract_pmkid(key_frame):
    """The PMKID from an M1's key data, or None.

    Key data is a sequence of KDEs (``dd len oui[3] type data``), not a plain element chain,
    and in M3 it is AES-key-wrapped - so only M1 is worth reading. A PMKID alone is enough to
    attack, which is why it is tracked independently of handshake completeness.
    """
    if key_frame is None or key_frame.message != "M1" or not key_frame.key_data:
        return None

    data = key_frame.key_data
    position = 0
    while position + 2 <= len(data):
        eid, length = data[position], data[position + 1]
        end = position + 2 + length
        if end > len(data):
            return None
        if eid == 0xDD and length >= 20:
            body = data[position + 2:end]
            if body[0:3] == RSN_OUI and body[3] == 4:
                return body[4:20].hex()
        position = end
    return None


class EapPacket:
    """One decoded EAP packet.

    ``tls_data`` is the fragment payload of a TLS-carrying method, already past the flags and
    the optional 4-byte total length; it is a *fragment*, not a message, and means nothing
    until ``EapTlsReassembler`` has joined it to its neighbours.
    """

    __slots__ = ("code", "eap_type", "identity", "tls_flags", "tls_data")

    def __init__(self, code, eap_type=None, identity=None, tls_flags=None, tls_data=None):
        self.code = code
        self.eap_type = eap_type
        self.identity = identity
        self.tls_flags = tls_flags
        self.tls_data = tls_data

    @property
    def more_fragments(self) -> bool:
        return bool(self.tls_flags is not None and self.tls_flags & EAP_TLS_FLAG_MORE)

    def __repr__(self):
        return f"<EapPacket code={self.code} type={self.eap_type}>"


def parse_eap(body):
    """``EapPacket`` for one EAP packet, or None.

    An EAP Response/Identity carries a real username or anonymous outer identity in
    plaintext - high value on an enterprise assessment, and free corroboration that the
    network really is 802.1X.

    Success and Failure are four bytes with no type field at all, which is why the length
    test is split: requiring five would silently discard the only frame that says whether the
    authentication actually worked.
    """
    if len(body) < 4:
        return None
    code = body[0]
    if code in (EAP_CODE_SUCCESS, EAP_CODE_FAILURE):
        return EapPacket(code)
    if len(body) < 5:
        return None

    eap_type = body[4]
    identity = None
    if code == EAP_CODE_RESPONSE and eap_type == 1 and len(body) > 5:
        identity = bytes(body[5:]).decode("utf-8", errors="replace")

    tls_flags = tls_data = None
    if eap_type in EAP_TLS_METHODS and len(body) > 5:
        tls_flags = body[5]
        offset = 6 + (4 if tls_flags & EAP_TLS_FLAG_LENGTH else 0)
        tls_data = bytes(body[offset:])

    return EapPacket(code, eap_type, identity, tls_flags, tls_data)


class MessageEvidence:
    """What a hc22000 line needs from one EAPOL-Key message, and nothing more.

    Bounded by construction: four of these per handshake at most, each holding one nonce, one
    MIC and - only for the two messages a hash can be built from - the frame itself, capped at
    ``HC22000_EAPOL_MAX``. That cap is what keeps this a fixed-size summary rather than a
    second frame buffer; an oversized frame is recorded as a length and dropped, because
    hcxpcapngtool would refuse to write it anyway.
    """

    __slots__ = ("ts", "nonce", "mic", "key_info", "replay_counter", "frame", "frame_length")

    def __init__(self, ts, key_frame, frame=None):
        self.ts = ts
        self.nonce = key_frame.nonce
        self.mic = key_frame.mic
        self.key_info = key_frame.key_info
        self.replay_counter = key_frame.replay_counter
        self.frame_length = len(frame) if frame is not None else 0
        self.frame = frame if frame is not None and self.frame_length <= HC22000_EAPOL_MAX else None

    @property
    def key_version(self) -> int:
        return self.key_info & KEY_INFO_VERSION_MASK

    @property
    def nonce_zeroed(self) -> bool:
        return self.nonce == _ZERO_NONCE

    @property
    def mic_zeroed(self) -> bool:
        return not any(self.mic)


class Handshake:
    """Observed EAPOL state for one (BSSID, station) pair."""

    __slots__ = ("bssid", "station", "messages", "replay_counters", "pmkid",
                 "eap_methods", "identity", "eap_outcome", "certificates",
                 "first_ts", "last_ts", "evidence")

    def __init__(self, bssid, station):
        self.bssid = bssid
        self.station = station
        self.messages = {}
        self.replay_counters = {}
        self.pmkid = None
        self.eap_methods = set()
        self.identity = None
        self.eap_outcome = None
        #: The authentication server's chain, leaf first. Order is significant - index 0 is
        #: the identity a client was asked to trust, the rest are the CAs vouching for it.
        self.certificates = []
        self.first_ts = None
        self.last_ts = None
        #: Per-message nonce/MIC/frame, for hc22000. Keyed like `messages`, so a
        #: retransmission replaces its predecessor exactly as the timestamp does.
        self.evidence = {}

    def observe(self, ts, key_frame, frame=None):
        if key_frame.message is None or not key_frame.message.startswith("M"):
            return
        self.messages[key_frame.message] = ts
        self.replay_counters[key_frame.message] = key_frame.replay_counter
        self.evidence[key_frame.message] = MessageEvidence(ts, key_frame, frame)
        if self.first_ts is None:
            self.first_ts = ts
        self.last_ts = ts
        if self.pmkid is None:
            self.pmkid = extract_pmkid(key_frame)

    @property
    def message_list(self) -> str:
        return ",".join(m[1] for m in sorted(self.messages, key=lambda m: int(m[1])))

    @property
    def count(self) -> int:
        return len(self.messages)

    @property
    def complete(self) -> bool:
        return {"M1", "M2", "M3", "M4"} <= set(self.messages)

    @property
    def has_key_material(self) -> bool:
        """Whether enough was captured to attempt a key recovery *in principle*.

        Deliberately weaker than `complete`: M1+M2 is sufficient on its own, as is a PMKID
        with no handshake at all. Replay counters must chain, otherwise two interleaved
        attempts from the same pair would look like one usable capture.

        Not the same question as `WPAHandshakeRecord.crackable`, which is what the graph
        reports. This one knows nothing about the AKM or the 255-byte frame cap, so it says
        yes to an 802.1X exchange whose PMK never came from a passphrase. Kept separate
        rather than merged because it is the honest answer to "was there key material here",
        which is a real question even when no runnable hash comes out of it.
        """
        if self.pmkid:
            return True
        seen, counters = set(self.messages), self.replay_counters
        if {"M1", "M2"} <= seen and counters["M1"] == counters["M2"]:
            return True
        if {"M2", "M3"} <= seen and counters["M3"] == counters["M2"] + 1:
            return True
        return {"M3", "M4"} <= seen and counters["M3"] == counters["M4"]


class EapTlsReassembler:
    """Joins EAP-TLS fragments back into whole TLS streams.

    A certificate chain does not fit in one 802.11 frame - the sample capture's is 4,047 bytes
    across five fragments, each acknowledged by an empty EAP-TLS frame from the peer. Keyed by
    (BSSID, station, code) because the two directions interleave: the server's chain and the
    client's response are separate streams over the same pair, told apart by Request vs
    Response.

    Both bounds are deliberate. A fragment chain whose More bit never clears would otherwise
    grow without limit on attacker-controlled input, and this is the only structure in the
    parser that buffers frame *contents* rather than a fixed-size summary of them.
    """

    def __init__(self, max_stream: int = 65_536, max_streams: int = 256):
        self.streams = {}
        self.max_stream = max_stream
        self.max_streams = max_streams
        self.dropped = 0

    def observe(self, bssid, station, packet):
        """Add one fragment; return the completed stream, or None while more is coming."""
        if packet.tls_data is None:
            return None
        key = (bssid, station, packet.code)
        buffer = self.streams.get(key)
        if buffer is None:
            if not packet.tls_data and not packet.more_fragments:
                return None  # a bare ACK with nothing to start a stream with
            if len(self.streams) >= self.max_streams:
                self.dropped += 1
                return None
            buffer = self.streams[key] = bytearray()

        if len(buffer) + len(packet.tls_data) > self.max_stream:
            del self.streams[key]
            self.dropped += 1
            return None
        buffer += packet.tls_data

        if packet.more_fragments:
            return None
        del self.streams[key]
        return bytes(buffer) or None


class HandshakeTracker:
    """Collects handshakes across a capture, keyed by (BSSID, station)."""

    def __init__(self, limit: int = 10_000):
        self.handshakes = {}
        self.limit = limit
        self.dropped = 0
        self.reassembler = EapTlsReassembler()

    def observe_key(self, ts, bssid, station, key_frame, frame=None):
        """Record one EAPOL-Key frame.

        ``frame`` is the complete 802.1X frame starting at the version byte - the form
        hc22000's EAPOL field wants. It is optional so that callers which only need message
        classification (the parity harness, most tests) need not carry it.
        """
        if bssid is None or station is None:
            return None
        key = (bssid, station)
        handshake = self.handshakes.get(key)
        if handshake is None:
            if len(self.handshakes) >= self.limit:
                self.dropped += 1
                return None
            handshake = self.handshakes[key] = Handshake(bssid, station)
        handshake.observe(ts, key_frame, frame)
        return handshake

    def ensure(self, ts, bssid, station):
        """Get or create the handshake for a pair, with no EAPOL evidence of its own.

        For an 802.11r roam, which completes without a 4-way. EAPOL-derived fields stay empty
        and so are absent from the node.
        """
        if bssid is None or station is None:
            return None
        key = (bssid, station)
        handshake = self.handshakes.get(key)
        if handshake is None:
            if len(self.handshakes) >= self.limit:
                self.dropped += 1
                return None
            handshake = self.handshakes[key] = Handshake(bssid, station)
        if ts is not None:
            if handshake.first_ts is None or ts < handshake.first_ts:
                handshake.first_ts = ts
            if handshake.last_ts is None or ts > handshake.last_ts:
                handshake.last_ts = ts
        return handshake

    def observe_eap(self, ts, bssid, station, parsed):
        if bssid is None or station is None or parsed is None:
            return None
        key = (bssid, station)
        handshake = self.handshakes.get(key)
        if handshake is None:
            if len(self.handshakes) >= self.limit:
                self.dropped += 1
                return None
            handshake = self.handshakes[key] = Handshake(bssid, station)
        if parsed.eap_type is not None:
            handshake.eap_methods.add(parsed.eap_type)
        if parsed.identity and not handshake.identity:
            handshake.identity = parsed.identity
        if parsed.code == EAP_CODE_SUCCESS:
            handshake.eap_outcome = "success"
        elif parsed.code == EAP_CODE_FAILURE and handshake.eap_outcome is None:
            # Success wins: a failed method often precedes a successful renegotiation, and
            # what matters is whether the station got on the network in the end.
            handshake.eap_outcome = "failure"

        stream = self.reassembler.observe(bssid, station, parsed)
        if stream and not handshake.certificates:
            # First chain only. A renegotiation re-sends the same certificates, and keeping
            # the first keeps the graph stable across a re-run of the same capture.
            handshake.certificates = tls.chain_from_stream(stream)

        if handshake.first_ts is None:
            handshake.first_ts = ts
        handshake.last_ts = ts
        return handshake

    def for_pair(self, bssid, station):
        return self.handshakes.get((bssid, station))
