"""LLC/SNAP demultiplexing: EAPOL, ARP and IPv4 out of unencrypted data frames.

Yield on a modern capture is close to zero - almost every data frame is CCMP-protected - but
the code is short and pays for itself on open-network captures. In the sample capture the
entire set of LLC ethertypes across 494 data frames is ``{0x0800: 1, 0x888E: 9}``: one
unencrypted IPv4 frame and the EAPOL exchanges. Every ``LAN IP`` in the matching CSV is
``0.0.0.0``, so that is agreement, not a gap.
"""
from .constants import ETHERTYPE_ARP, ETHERTYPE_EAPOL, ETHERTYPE_IPV4, FrameType

#: LLC header for SNAP-encapsulated traffic: DSAP/SSAP 0xAA, control 0x03.
_LLC_SNAP = b"\xaa\xaa\x03"
#: SNAP organisation codes: RFC 1042 encapsulation, and the bridge-tunnel variant.
_SNAP_OUIS = (b"\x00\x00\x00", b"\x00\x00\xf8")


def snap_payload(frame):
    """``(ethertype, payload)`` for an unencrypted SNAP-framed data frame, else ``(None, None)``.

    Skips protected frames (the payload is ciphertext), Null/QoS-Null (no payload at all) and
    non-initial fragments (only fragment 0 carries the LLC header).
    """
    if frame.type != FrameType.DATA or frame.protected or frame.is_null_data:
        return None, None
    if frame.frag:
        return None, None

    body = frame.raw[frame.body_offset:]
    if len(body) < 8 or bytes(body[0:3]) != _LLC_SNAP:
        return None, None
    if bytes(body[3:6]) not in _SNAP_OUIS:
        return None, None

    return (body[6] << 8) | body[7], body[8:]


def is_eapol(ethertype) -> bool:
    return ethertype == ETHERTYPE_EAPOL


def eapol_body(payload):
    """``(packet_type, body)`` from an EAPOL frame's header, or ``(None, None)``."""
    if payload is None or len(payload) < 4:
        return None, None
    packet_type = payload[1]
    declared = (payload[2] << 8) | payload[3]
    body = payload[4:4 + declared] if declared else payload[4:]
    return packet_type, body


def _ipv4(raw) -> str:
    return ".".join(str(byte) for byte in raw)


def source_ip(ethertype, payload):
    """Source IPv4 address from an ARP or IPv4 payload, or None.

    ARP's sender protocol address is preferred where present - it is what airodump reports -
    and both are the *transmitter's* address, which the caller has to attribute correctly:
    for a ToDS frame that is the station, for FromDS it is a host behind the AP rather than
    the AP itself.
    """
    if payload is None:
        return None
    if ethertype == ETHERTYPE_ARP and len(payload) >= 28:
        return _ipv4(payload[14:18])
    if ethertype == ETHERTYPE_IPV4 and len(payload) >= 20:
        return _ipv4(payload[12:16])
    return None
