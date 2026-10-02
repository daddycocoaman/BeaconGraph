"""airodump-ng-compatible CSV export.

The output has to be byte-compatible enough that ``beacongraph-csv`` can ingest it, which
means reproducing airodump's actual layout rather than well-formed RFC-4180 CSV: a leading
blank line, CRLF terminators, ``", "`` separators, right-aligned numeric columns, and a
probed-ESSID list joined by bare commas in the trailing field. ``AirodumpProcessor._cleanup``
depends on that last detail, and the AP header must match ``AIRODUMP_SNIFF_TOKEN`` exactly or
the file is rejected outright.

**This is the one place the omit rule is suspended**, and only because the format leaves no
choice: a CSV column cannot be absent, so an underivable value is written as airodump's own
sentinel (``-1`` for power and speed, ``0.0.0.0`` for LAN IP). That is a property of the
interchange format, not a change of policy - the graph writers still omit.
"""
from .records import format_timestamp

AP_HEADER = ("BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, "
             "Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key")
STATION_HEADER = ("Station MAC, First time seen, Last time seen, Power, # packets, BSSID, "
                  "Probed ESSIDs")

NOT_ASSOCIATED = "(not associated) "
UNKNOWN_IP = "  0.  0.  0.  0"
LINE_END = "\r\n"

#: airodump's own "not observed" sentinel for the numeric columns.
UNKNOWN_NUMERIC = -1


def _ip(address):
    if not address:
        return UNKNOWN_IP
    parts = address.split(".")
    if len(parts) != 4:
        return UNKNOWN_IP
    return ".".join(f"{int(part):3d}" for part in parts)


def _sanitize(value):
    """Neutralize characters that would corrupt the row.

    An SSID may legitimately contain a comma or a pipe, and both break the reader on the
    other side: the AP table has no quoting at all, so a comma shifts every later column,
    and the station table is read with ``quotechar="|"``, so a pipe terminates the field
    early. Escaping keeps the file parseable; the graph node still carries the true name, so
    only the interchange copy is lossy.
    """
    if not value:
        return ""
    return value.replace(",", "\\x2c").replace("|", "\\x7c").replace("\r", "").replace("\n", "")


def ap_row(record, tz=None) -> str:
    security = record.security
    return ", ".join([
        record.bssid,
        format_timestamp(record.first_ts, tz) or "",
        format_timestamp(record.last_ts, tz) or "",
        f"{record.channel if record.channel is not None else UNKNOWN_NUMERIC:2d}",
        f"{record.max_rate if record.max_rate is not None else UNKNOWN_NUMERIC:3d}",
        (security.privacy if security else None) or "",
        (security.cipher if security else None) or "",
        (security.auth if security else None) or "",
        # No radiotap means no signal strength anywhere in the capture.
        f"{UNKNOWN_NUMERIC:3d}",
        f"{record.beacons:8d}",
        f"{record.ivs:8d}",
        _ip(record.lan_ip),
        f"{record.ssid_len if record.ssid_len is not None else 0:3d}",
        _sanitize(record.essid),
        "",
    ])


def station_row(record, tz=None) -> str:
    probed = ",".join(_sanitize(name) for name in record.probed)
    associated = record.base_bssid if record.base_bssid else NOT_ASSOCIATED
    return ", ".join([
        record.mac,
        format_timestamp(record.first_ts, tz) or "",
        format_timestamp(record.last_ts, tz) or "",
        f"{record.power if record.power is not None else UNKNOWN_NUMERIC:3d}",
        f"{record.packets:8d}",
        f"{associated},{probed}",
    ])


def render(result, tz=None) -> str:
    """The whole file, ordered by first-seen the way airodump writes it."""
    lines = [""]

    lines.append(AP_HEADER)
    for record in sorted(result.aps.values(), key=lambda r: (r.first_ts or 0, r.bssid)):
        lines.append(ap_row(record, tz))

    lines.append("")
    lines.append(STATION_HEADER)
    for record in sorted(result.stations.values(), key=lambda r: (r.first_ts or 0, r.mac)):
        lines.append(station_row(record, tz))

    lines.append("")
    return LINE_END.join(lines)


def write(result, path, tz=None) -> None:
    """Write to a path, or to stdout when the path is ``-``."""
    text = render(result, tz)
    if str(path) == "-":
        import sys

        sys.stdout.write(text)
        return
    with open(path, "w", encoding="utf-8", newline="") as handle:
        handle.write(text)
