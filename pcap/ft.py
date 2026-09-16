"""802.11r Fast BSS Transition: the material an FT-PSK roam leaks, and the hashcat line for it.

The FT Authentication frame carries `PMKR0Name` in the clear, in the RSNE's PMKID field, and
for FT-PSK it is a deterministic function of the passphrase::

    PMK-R0Name = SHA-256("FT-R0N" || KDF(PBKDF2(passphrase, SSID), "FT-R0", ...))[:16]

Every other input is on the air, so **one management frame is a complete offline verifier** -
no 4-way handshake, no nonces, no deauthentication, no association.

FT-SAE (9, 25) roots PMK-R0 in the SAE PMK and yields nothing; FT-PSK (4, 19) roots it in
PBKDF2. A network running `SAE FT-SAE WPA-PSK FT-PSK` for legacy roaming therefore leaks a
crackable verifier over the same passphrase SAE uses - which is why the AKM gate below refuses
rather than emitting a line that could never crack.

The FTE needs its own walker: a fixed 82-byte header (MIC Control 2, MIC 16, ANonce 32,
SNonce 32) and only then 1-byte-id/1-byte-length subelements.
"""
import hashlib

from .constants import (
    AKM_FT_PSK,
    AKM_FT_SAE,
    FTE_HEADER_LEN,
    FTE_SUBELEM_R0KH_ID,
    FTE_SUBELEM_R1KH_ID,
)

#: Mode 37100's PMKID type. Type `04` verifies the FTE MIC and is not emitted.
HC37100_TYPE_PMKID = "03"

#: Unread by the type-3 decoder; carried for the token count. `01` matches the module's
#: own reference hash.
HC37100_MP = "01"

STATUS_OK = "ok"
#: No R1KH-ID, so PMK-R1-Name cannot be derived. It arrives in the AP's half of the exchange.
STATUS_NO_R1KH = "r1kh_id_missing"
#: FT-SAE: PMK-R0 comes from dragonfly, not a passphrase.
STATUS_SAE_AKM = "sae_akm"
#: An enterprise FT AKM, whose PMK comes from EAP.
STATUS_ENTERPRISE = "enterprise_akm"
#: An FT exchange with no PMKID - the initial mobility-domain association, not a roam.
STATUS_NO_ROAM = "no_roam_captured"
#: The ESSID is the PBKDF2 salt; without it there is no line.
STATUS_NO_ESSID = "essid_unknown"
#: FT elements present but incomplete.
STATUS_INCOMPLETE = "ft_material_incomplete"


def subelements(body):
    """Yield ``(id, value)`` per FTE subelement, stopping at a malformed tail.

    Not `ie.walk`: the 82-byte header in front of these is not an element, so a generic
    walker would read MIC bytes as element ids.
    """
    if body is None or len(body) <= FTE_HEADER_LEN:
        return
    position = FTE_HEADER_LEN
    while position + 2 <= len(body):
        sub_id, length = body[position], body[position + 1]
        end = position + 2 + length
        if end > len(body):
            return  # truncated tail; keep whatever already yielded
        yield sub_id, bytes(body[position + 2:end])
        position = end


def parse_fte(body) -> dict:
    """``{"r0kh_id": ..., "r1kh_id": ..., "anonce": ..., "snonce": ...}`` from an FTE."""
    if body is None or len(body) < FTE_HEADER_LEN:
        return {}
    found = {
        "anonce": bytes(body[18:50]),
        "snonce": bytes(body[50:82]),
    }
    for sub_id, value in subelements(body):
        if sub_id == FTE_SUBELEM_R0KH_ID and "r0kh_id" not in found:
            found["r0kh_id"] = value
        elif sub_id == FTE_SUBELEM_R1KH_ID and "r1kh_id" not in found:
            found["r1kh_id"] = value
    return found


class FTRecord:
    """FT material for one (BSSID, station) pair, merged across both directions.

    The station's seq-1 frame carries the selected AKM and R0KH-ID; the AP's seq-2 adds the
    R1KH-ID. First non-empty value wins, like `wps.merge`.
    """

    __slots__ = ("bssid", "station", "mdid", "pmkr0name", "r0kh_id", "r1kh_id",
                 "anonce", "snonce", "akms")

    def __init__(self, bssid, station):
        self.bssid = bssid
        self.station = station
        self.mdid = None
        self.pmkr0name = None
        self.r0kh_id = None
        self.r1kh_id = None
        self.anonce = None
        self.snonce = None
        self.akms = ()

    def absorb(self, mdid=None, pmkr0name=None, akms=(), fte=None) -> None:
        if mdid is not None and self.mdid is None:
            self.mdid = mdid
        if pmkr0name is not None and self.pmkr0name is None:
            self.pmkr0name = pmkr0name
        if akms and not self.akms:
            self.akms = tuple(akms)
        for key, value in (fte or {}).items():
            if getattr(self, key, None) in (None, ()) and value:
                setattr(self, key, value)

    @property
    def roamed(self) -> bool:
        """A real roam, rather than an initial mobility-domain association."""
        return self.pmkr0name is not None

    @property
    def pmkr1name(self):
        """PMK-R1-Name, derived rather than captured - what mode 37100 type 3 compares against.

        ``Truncate-128(SHA-256("FT-R1N" || PMKR0Name || R1KH-ID || S1KH-ID))``, 802.11r-2008
        §8.5.1.5.4. No key input, so the FT Authentication exchange alone is enough and the
        Reassociation Request that normally carries this value is not needed.
        """
        if not (self.pmkr0name and self.r1kh_id and self.station):
            return None
        s1kh = bytes.fromhex(self.station.replace(":", ""))
        return hashlib.sha256(b"FT-R1N" + self.pmkr0name + self.r1kh_id + s1kh).digest()[:16]

    def status(self, essid_raw=None) -> str:
        akm_set = set(self.akms)
        if akm_set & AKM_FT_SAE:
            return STATUS_SAE_AKM
        if self.akms and not akm_set & AKM_FT_PSK:
            return STATUS_ENTERPRISE
        if not self.roamed:
            return STATUS_NO_ROAM
        if not essid_raw:
            return STATUS_NO_ESSID
        if not (self.mdid and self.r0kh_id):
            return STATUS_INCOMPLETE
        if self.r1kh_id is None or len(self.r1kh_id) != 6:
            return STATUS_NO_R1KH
        return STATUS_OK


def render(record: FTRecord, essid_raw) -> str:
    """One hashcat mode 37100 type-3 line, or None if the material is incomplete.

    Twelve tokens, per `src/modules/module_37100.c` in hashcat PR #4645 - mode 22000's nine,
    then MDID, R0KH-ID and R1KH-ID::

        WPA*03*PMKR1NAME*MACAP*MACSTA*ESSID_HEX*ANONCE*EAPOL*MP*MDID*R0KH-ID*R1KH-ID

    Mode 37100 is not in mainline hashcat; these lines need a build from that PR.
    """
    if record is None or record.status(essid_raw) != STATUS_OK:
        return None
    pmkr1name = record.pmkr1name
    if pmkr1name is None:
        return None
    return "*".join((
        "WPA",
        HC37100_TYPE_PMKID,
        pmkr1name.hex(),
        record.bssid.replace(":", "").lower(),
        record.station.replace(":", "").lower(),
        essid_raw.hex(),
        "",                       # ANonce - type 4 only
        "",                       # EAPOL  - type 4 only
        HC37100_MP,
        record.mdid.hex(),
        record.r0kh_id.hex(),
        record.r1kh_id.hex(),
    ))


def render_all(result) -> str:
    """Every mode 37100 line a capture yields, ordered for reproducibility."""
    from .graph import handshake_records

    records = handshake_records(result)
    lines = []
    for key in sorted(records):
        line, _ = records[key].ft_hashes
        if line:
            lines.append(line)
    return "".join(line + "\n" for line in lines)


def write(result, path) -> int:
    """Write the hash file, or stdout when the path is ``-``. Returns the line count.

    An empty file is still written - it says the capture held no crackable roam.
    """
    text = render_all(result)
    count = text.count("\n")
    if str(path) == "-":
        import sys

        sys.stdout.write(text)
        return count
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return count
