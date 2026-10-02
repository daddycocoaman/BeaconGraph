"""Capture file layer: open, detect the link type, strip the radio header, stream frames.

scapy's ``RawPcapReader``/``RawPcapNgReader`` handle the container - pcap and pcapng, both
endiannesses, gzip - and yield raw bytes *without* invoking the packet dissector. That
distinction is the single largest performance lever in the whole parser: 94% of a typical
capture is control frames that are discarded immediately, and full ``Dot11`` dissection would
allocate an object per information element for all of them. scapy's real dissectors are used
for exactly one thing here, ``RadioTap``, whose alignment rules and extended present-bitmap
chaining are genuinely fiddly and which only appears on captures that carry it.
"""
import struct

from scapy.utils import RawPcapNgReader, RawPcapReader

from . import ie
from .constants import (
    DLT_IEEE802_11,
    DLT_IEEE802_11_AVS,
    DLT_IEEE802_11_RADIOTAP,
    DLT_PRISM,
    LINK_TYPES,
    Ctrl,
    FrameType,
)


class UnsupportedDltError(Exception):
    """Raised for a link type that is not 802.11 at all."""


# pcap in both endiannesses and both timestamp resolutions, pcapng's section header block,
# and gzip - scapy's readers open gzipped captures transparently.
CAPTURE_MAGICS = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                  b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
                  b"\x0a\x0d\x0d\x0a",
                  b"\x1f\x8b")


def looks_like_capture(path) -> bool:
    """True if the file starts with a pcap, pcapng or gzip magic number."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(4)
    except OSError:
        return False
    return any(head.startswith(magic) for magic in CAPTURE_MAGICS)


class RadioInfo:
    """Radio-layer metadata, when the capture carries any.

    Any field may be None: a radiotap header can be present while carrying no dBm antenna
    signal at all (some drivers emit only a relative dB value). Presence of the header is not
    presence of signal strength, which is why the reader reports which fields it actually
    observed rather than just whether a header existed.
    """

    __slots__ = ("signal_dbm", "noise_dbm", "channel_freq", "rate_mbps", "bad_fcs")

    def __init__(self, signal_dbm=None, noise_dbm=None, channel_freq=None,
                 rate_mbps=None, bad_fcs=False):
        self.signal_dbm = signal_dbm
        self.noise_dbm = noise_dbm
        self.channel_freq = channel_freq
        self.rate_mbps = rate_mbps
        self.bad_fcs = bad_fcs


class CaptureMeta:
    """What the reader learned about the file. Populated as it streams."""

    __slots__ = ("path", "linktype", "linktype_name", "has_radio_metadata", "radio_fields",
                 "fcs_present", "packet_count", "first_ts", "last_ts", "truncated_count",
                 "bad_fcs_count")

    def __init__(self, path, linktype, linktype_name, has_radio_metadata):
        self.path = path
        self.linktype = linktype
        self.linktype_name = linktype_name
        self.has_radio_metadata = has_radio_metadata
        self.radio_fields = set()
        self.fcs_present = None
        self.packet_count = 0
        self.first_ts = None
        self.last_ts = None
        self.truncated_count = 0
        self.bad_fcs_count = 0

    @property
    def duration(self):
        if self.first_ts is None or self.last_ts is None:
            return 0.0
        return self.last_ts - self.first_ts

    def missing_properties(self) -> list:
        """Node properties this capture structurally cannot supply.

        Surfaced by the CLI at startup. Omitting a property silently would be worse than the
        placeholder the design rejected, so the gap is named out loud.
        """
        gaps = []
        if not self.has_radio_metadata or "signal" not in self.radio_fields:
            gaps.append("power")
        return gaps


def _strip_radio(linktype, data):
    """Return ``(frame_bytes, RadioInfo|None)`` with any radio header removed."""
    if linktype == DLT_IEEE802_11:
        return data, None

    if linktype == DLT_IEEE802_11_RADIOTAP:
        if len(data) < 4:
            return b"", None
        header_len = struct.unpack_from("<H", data, 2)[0]
        if header_len < 8 or header_len > len(data):
            return b"", None
        return data[header_len:], _parse_radiotap(data[:header_len])

    if linktype == DLT_PRISM:
        return (data[144:], None) if len(data) > 144 else (b"", None)

    if linktype == DLT_IEEE802_11_AVS:
        if len(data) < 8:
            return b"", None
        header_len = struct.unpack_from(">I", data, 4)[0]
        if header_len < 8 or header_len > len(data):
            return b"", None
        return data[header_len:], None

    raise UnsupportedDltError(linktype)


def _parse_radiotap(header):
    """Pull signal, noise, channel and the bad-FCS flag out of a radiotap header.

    Delegated to scapy rather than hand-rolled: the present-bitmap chaining and per-field
    alignment rules are the part of radiotap that is easy to get subtly wrong, and this runs
    at most once per frame on the minority of captures that have it.
    """
    from scapy.layers.dot11 import RadioTap

    try:
        parsed = RadioTap(bytes(header))
    except Exception:
        return None

    def field(name):
        value = getattr(parsed, name, None)
        return value if value not in (None, "") else None

    flags = getattr(parsed, "Flags", None)
    bad_fcs = bool(flags and "badFCS" in str(flags))

    return RadioInfo(
        signal_dbm=field("dBm_AntSignal"),
        noise_dbm=field("dBm_AntNoise"),
        channel_freq=field("ChannelFrequency"),
        rate_mbps=field("Rate"),
        bad_fcs=bad_fcs,
    )


def _fcs_probe(frames) -> bool:
    """Decide whether frames carry a trailing 4-byte FCS.

    Walks the information elements of sampled management frames: if the chain lands exactly
    on the end of the frame there is no FCS, and if it lands four bytes short there is one.
    Corroborated by ACK/CTS length, which is 10 bytes without an FCS and 14 with.

    Getting this wrong changes nothing in the fixed header but makes every IE walk overrun by
    four bytes, which silently drops the last element in the chain - and that is very often
    the RSN element, i.e. the entire security classification.
    """
    with_fcs = without_fcs = 0

    for data in frames:
        if len(data) < 2:
            continue
        fc0, fc1 = data[0], data[1]
        type_ = (fc0 >> 2) & 0x03
        subtype = (fc0 >> 4) & 0x0F

        if type_ == FrameType.CTRL and subtype in (Ctrl.ACK, Ctrl.CTS):
            if len(data) == 10:
                without_fcs += 1
            elif len(data) == 14:
                with_fcs += 1
            continue

        if type_ != FrameType.MGMT or subtype not in (5, 8) or len(data) < 40:
            continue

        start = 24 + (4 if fc1 & 0x80 else 0) + 12  # timestamp + interval + capability
        consumed = start
        for eid, body in ie.walk(memoryview(data), start):
            consumed += 2 + len(body) + (1 if isinstance(eid, tuple) else 0)

        if consumed == len(data):
            without_fcs += 1
        elif consumed == len(data) - 4:
            with_fcs += 1

    return with_fcs > without_fcs


class FrameSource:
    """Streams ``(timestamp, frame_bytes, RadioInfo|None)`` from a capture file.

    Always an iterator, never a list: aggregator state is O(distinct MACs) while a capture is
    O(frames), so streaming keeps memory flat no matter how large the file is.
    """

    def __init__(self, path, assume_fcs=None, max_frames=None, fcs_sample=200):
        self.path = str(path)
        self.max_frames = max_frames
        self._assume_fcs = assume_fcs
        self._fcs_sample = fcs_sample

        self._reader, linktype = self._open()
        if linktype is not None and linktype not in LINK_TYPES:
            self._reader.close()
            raise UnsupportedDltError(
                f"{self.path} has link type {linktype}, which is not 802.11. "
                f"Convert it with `editcap -T ieee-802-11 in out` if the frames really are "
                f"802.11, otherwise this capture holds nothing BeaconGraph can use."
            )

        name, _, has_radio = LINK_TYPES.get(linktype, ("UNKNOWN", 0, False))
        self.meta = CaptureMeta(self.path, linktype, name, has_radio)
        if assume_fcs is not None:
            self.meta.fcs_present = assume_fcs

    def _open(self):
        try:
            reader = RawPcapReader(self.path)
            return reader, reader.linktype
        except Exception:
            pass
        reader = RawPcapNgReader(self.path)
        return reader, None  # pcapng carries link type per packet, read from metadata

    def _detect_fcs(self):
        """Sample the head of the file, then reopen so nothing is consumed."""
        sample, reader = [], self._open()[0]
        try:
            for index, (data, _meta) in enumerate(reader):
                if index >= self._fcs_sample * 20 or len(sample) >= self._fcs_sample:
                    break
                stripped, _ = _strip_radio(self.meta.linktype or DLT_IEEE802_11, bytes(data))
                if stripped:
                    sample.append(stripped)
        finally:
            reader.close()
        return _fcs_probe(sample)

    def __iter__(self):
        if self.meta.fcs_present is None and self.meta.linktype is not None:
            self.meta.fcs_present = self._detect_fcs()

        trim = 4 if self.meta.fcs_present else 0
        count = 0

        for data, meta in self._reader:
            if self.max_frames is not None and count >= self.max_frames:
                break

            linktype = getattr(meta, "linktype", None)
            if linktype is None:
                linktype = self.meta.linktype
                timestamp = meta.sec + meta.usec / 1_000_000
            else:
                # pcapng: a file can mix link types across interfaces, so resolve per frame.
                resolution = getattr(meta, "tsresol", 1_000_000) or 1_000_000
                timestamp = ((meta.tshigh << 32) | meta.tslow) / resolution
                if linktype in LINK_TYPES and not self.meta.has_radio_metadata:
                    self.meta.has_radio_metadata = LINK_TYPES[linktype][2]

            if linktype not in LINK_TYPES:
                continue

            raw = bytes(data)
            if getattr(meta, "caplen", None) and meta.caplen != getattr(meta, "wirelen", meta.caplen):
                self.meta.truncated_count += 1

            frame, radio = _strip_radio(linktype, raw)
            if trim and len(frame) > trim:
                frame = frame[:-trim]
            if not frame:
                continue

            if radio is not None:
                if radio.bad_fcs:
                    self.meta.bad_fcs_count += 1
                    continue
                if radio.signal_dbm is not None:
                    self.meta.radio_fields.add("signal")
                if radio.channel_freq is not None:
                    self.meta.radio_fields.add("channel")

            count += 1
            self.meta.packet_count = count
            if self.meta.first_ts is None:
                self.meta.first_ts = timestamp
            self.meta.last_ts = timestamp

            yield timestamp, memoryview(frame), radio

        self.close()

    def close(self):
        if self._reader is not None:
            try:
                self._reader.close()
            finally:
                self._reader = None
