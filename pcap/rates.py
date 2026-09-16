"""Maximum PHY rate, in airodump's dialect and in an honest one.

airodump's ``Speed`` column is not a single consistent formula, and the inconsistencies are
load-bearing for parity. Measured against the 148-row ground-truth CSV:

- **HT channel width is ignored.** An AP advertising HT40 reports the HT20 rate. Applying the
  2.0769 HT40 factor drops parity from 144/144 to 143/144.
- **Guard interval is applied for VHT but not for HT.** A 2.4 GHz AP advertising short GI
  still reports 260 (4 streams x 65, long GI) rather than 289, while a VHT AP reports 1733
  (4 x 390 / 0.9, short GI) rather than 1560.
- **Only the Supported Rates element is read**, not Extended Supported Rates, so an AP whose
  extended element advertises 54 Mbps still reports 48.
- Results are truncated, not rounded: 390 x 2 / 0.9 is 866.67, and airodump prints 866.

``mode="airodump"`` reproduces all of that exactly and is the default, because a graph where
the same AP has one speed from the CSV path and another from the pcap path forks on every
property comparison. ``mode="physical"`` computes the real maximum for callers who want it.
"""
import struct

from .constants import HT40_FACTOR, HT_MCS_20MHZ_LGI, SGI_FACTOR, VHT_80MHZ_LGI

#: HT20, one spatial stream, long guard interval, MCS 7 - the unit airodump multiplies by the
#: stream count.
HT_BASE_MBPS = 65


def ht_streams(ht_capabilities) -> int:
    """Spatial streams from the Rx MCS bitmask (bytes 3-6 of the HT Capabilities element).

    One byte per stream: 0xFF means MCS 0-7 supported on that stream, 0x00 means unsupported.
    """
    if ht_capabilities is None or len(ht_capabilities) < 7:
        return 0
    return sum(1 for index in range(4) if ht_capabilities[3 + index] != 0)


def ht_flags(ht_capabilities):
    """``(supports_40mhz, short_gi)`` from the HT Capability Info field."""
    if ht_capabilities is None or len(ht_capabilities) < 2:
        return False, False
    info = struct.unpack("<H", bytes(ht_capabilities[0:2]))[0]
    width40 = bool(info & 0x0002)
    short_gi = bool(info & (0x0040 if width40 else 0x0020))
    return width40, short_gi


def vht_streams_and_mcs(vht_capabilities):
    """``(streams, max_mcs)`` from the Rx VHT-MCS Map (bytes 4-5).

    Eight 2-bit fields, one per spatial stream: 0 = MCS 0-7, 1 = MCS 0-8, 2 = MCS 0-9,
    3 = stream unsupported.
    """
    if vht_capabilities is None or len(vht_capabilities) < 6:
        return 0, 0
    mcs_map = struct.unpack("<H", bytes(vht_capabilities[4:6]))[0]
    supported = [index for index in range(8) if ((mcs_map >> (2 * index)) & 3) != 3]
    if not supported:
        return 0, 0
    highest = max((mcs_map >> (2 * index)) & 3 for index in supported)
    return len(supported), {0: 7, 1: 8, 2: 9}[highest]


def vht_width(vht_operation) -> int:
    """Channel width in MHz from the VHT Operation element."""
    if vht_operation is None or len(vht_operation) < 3:
        return 80
    width = vht_operation[0]
    if width == 0:
        return 40
    if width in (2, 3):
        return 160
    segment0, segment1 = vht_operation[1], vht_operation[2]
    if segment1 and abs(segment0 - segment1) == 8:
        return 160
    return 80


def legacy_max_mbps(elements, include_extended: bool = False):
    """Highest advertised legacy rate. airodump reads only Supported Rates, hence the default."""
    rates = elements.rates(include_extended=include_extended)
    return max(rates) if rates else None


def max_rate(elements, mode: str = "airodump"):
    """Maximum PHY rate in Mbps, or None when no rate information was advertised.

    None rather than airodump's ``-1`` sentinel: an AP that was never seen beaconing has an
    unknown speed, and under the omit rule an unknown property is absent rather than filled
    with a placeholder. The CSV exporter re-introduces ``-1`` because that format has no way
    to express absence.
    """
    if mode not in ("airodump", "physical"):
        raise ValueError(f"unknown rate mode: {mode}")

    vht_cap = elements.vht_capabilities
    streams, max_mcs = vht_streams_and_mcs(vht_cap)
    if streams:
        base = VHT_80MHZ_LGI[max_mcs] * streams
        if mode == "airodump":
            return int(base * SGI_FACTOR)
        width = vht_width(elements.vht_operation)
        info = struct.unpack("<I", bytes(vht_cap[0:4]))[0] if len(vht_cap) >= 4 else 0
        short_gi = bool(info & (0x0040 if width >= 160 else 0x0020))
        scaled = base * {40: 0.45, 80: 1.0, 160: 2.0}.get(width, 1.0)
        return int(scaled * (SGI_FACTOR if short_gi else 1.0))

    ht_cap = elements.ht_capabilities
    streams = ht_streams(ht_cap)
    if streams:
        if mode == "airodump":
            return HT_BASE_MBPS * streams
        width40, short_gi = ht_flags(ht_cap)
        rate = HT_MCS_20MHZ_LGI[7] * streams
        if width40:
            rate *= HT40_FACTOR
        if short_gi:
            rate *= SGI_FACTOR
        return int(rate)

    legacy = legacy_max_mbps(elements, include_extended=(mode == "physical"))
    return int(legacy) if legacy else None
