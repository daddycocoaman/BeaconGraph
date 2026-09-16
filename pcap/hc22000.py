"""hc22000 line assembly - hashcat mode 22000, "WPA-PBKDF2-PMKID+EAPOL".

A semantics module beside the generic walkers, following `crypto.py` and `wps.py`: `eapol.py`
decodes EAPOL-Key frames and stays ignorant of what a cracker wants; this interprets what it
collected. Nothing here hashes anything - hashcat does the PBKDF2. The whole job is choosing
the right pair of messages and assembling bytes the way hashcat expects to find them.

The format, from the upstream hcxtools source rather than from folklore::

    WPA*TYPE*PMKID-OR-MIC*MACAP*MACSTA*ESSID_HEX*ANONCE*EAPOL*MP

Always nine `*`-separated tokens. A PMKID line leaves fields 6 and 7 empty rather than
dropping them, so it carries a literal `***` before the message pair.

Three details are where an implementation usually goes wrong, and each is load-bearing here:

- **Field 7 starts at the 802.1X version byte**, not at the Key Descriptor Type byte. Getting
  this wrong shifts every offset by four, including the MIC's, and yields a line that parses
  cleanly and never cracks.
- **The MIC is snapshotted before it is zeroed.** Field 2 and field 7 come from the same
  frame; read field 2 from the zeroed copy and every hash is 32 zeros.
- **Key Data stays in full.** It is MIC input, not padding, which is why an M3 line is long.

Field 6 is documented as ANONCE but is really "the nonce that is *not* inside field 7" -
hashcat sorts the two nonces before building the PKE, so for the pairs that carry the AP's
frame it holds the client's SNonce instead.
"""
from .constants import (
    AKM_OWE,
    AKM_PSK,
    AKM_WPA3_PERSONAL,
    HC22000_EAPOL_MAX,
    HC22000_EAPOL_MIN,
    HC22000_MIC_LENGTH,
    HC22000_MIC_OFFSET,
    HC22000_SIGNATURE,
    HC22000_TYPE_EAPOL,
    HC22000_TYPE_PMKID,
    MP_M12_E2,
    MP_M14_E4,
    MP_M32_E2,
    MP_M34_E4,
    PMKID_AP,
)

#: Tried in order, and the order is a ranking rather than a convenience. M1+M2 is last because
#: it is the only pair that does not prove the AP accepted the client's answer: a passphrase
#: recovered from it is the one the *station* offered, which the network may well have
#: rejected. Everything above it is authorized. Within the authorized pairs the client's own
#: frame is preferred over the AP's, since the AP's M3 carries an encrypted GTK and is usually
#: the frame that busts the length cap.
#:
#: Each entry is (message pair byte, frame message, nonce message, replay-counter rule).
_PAIRS = (
    (MP_M34_E4, "M4", "M3", lambda rc: rc["M3"] == rc["M4"]),
    (MP_M32_E2, "M2", "M3", lambda rc: rc["M3"] == rc["M2"] + 1),
    (MP_M14_E4, "M4", "M1", lambda rc: rc["M1"] == rc["M4"] - 1),
    (MP_M12_E2, "M2", "M1", lambda rc: rc["M1"] == rc["M2"]),
)

#: Why no EAPOL line could be built. Reported rather than inferred, because the reasons are
#: not equivalent: `eapol_too_large` and `m4_nonce_zeroed` mean the capture is unusable for
#: this pair however long you wait, while `no_pair_captured` means keep listening.
STATUS_OK = "ok"
STATUS_ENTERPRISE = "enterprise_akm"
#: Split out of `enterprise_akm`: an SAE PMKID is built from ephemeral scalars with no
#: password dependence, so unlike 802.1X there is nothing offline to attempt at all.
STATUS_SAE = "sae_akm"
#: Enhanced Open - no passphrase exists to recover.
STATUS_OWE = "owe_akm"
#: The AP was never classified, so there is no AKM to judge by.
STATUS_UNKNOWN_AKM = "akm_unknown"
STATUS_NO_ESSID = "essid_unknown"
STATUS_NO_PAIR = "no_pair_captured"
STATUS_TOO_LARGE = "eapol_too_large"
STATUS_NONCE_ZEROED = "m4_nonce_zeroed"
STATUS_REPLAY_MISMATCH = "replay_counter_mismatch"
STATUS_BAD_KEY_VERSION = "unsupported_key_version"
STATUS_MIC_ZEROED = "mic_zeroed"


def is_psk(akms) -> bool:
    """Whether a wordlist attack against this network could ever work.

    An 802.1X network's PMK comes out of EAP, and a WPA3-SAE network's out of dragonfly;
    neither is PBKDF2 over a passphrase, so a mode 22000 line for them is uncrackable in a way
    that looks exactly like a crackable one. Suppressing those is the difference between a
    hash file an operator can run and one that quietly wastes a day.
    """
    return bool(akms) and any(akm in AKM_PSK for akm in akms)


def no_hash_reason(akms) -> str:
    """Which non-PSK answer this is. One status per reason, since each calls for a different
    response from an operator."""
    akm_set = set(akms or ())
    if not akm_set:
        return STATUS_UNKNOWN_AKM
    if akm_set & AKM_WPA3_PERSONAL:
        return STATUS_SAE
    if akm_set & AKM_OWE:
        return STATUS_OWE
    return STATUS_ENTERPRISE


def _hex_mac(mac: str) -> str:
    """`30:86:2D:1F:E1:C2` -> `30862d1fe1c2`. hashcat wants 12 bare lowercase hex digits."""
    return mac.replace(":", "").replace("-", "").lower()


def _essid_hex(essid_raw, essid) -> str:
    """The SSID's real octets as hex.

    `essid_raw` is preferred and `essid` is the fallback, because an SSID is an arbitrary byte
    string and the decoded form is a lossy utf-8/replace rendering - re-encoding it would
    silently substitute U+FFFD for whatever was really on the wire, and the ESSID is the
    PBKDF2 salt, so one wrong byte makes every candidate passphrase fail.
    """
    if essid_raw:
        return essid_raw.hex()
    if essid:
        return essid.encode("utf-8", errors="strict").hex()
    return ""


def zero_mic(frame: bytes) -> bytes:
    """The 802.1X frame with its Key MIC blanked, which is what hashcat recomputes."""
    end = HC22000_MIC_OFFSET + HC22000_MIC_LENGTH
    return frame[:HC22000_MIC_OFFSET] + b"\x00" * HC22000_MIC_LENGTH + frame[end:]


def pmkid_line(pmkid: str, bssid: str, station: str, essid_raw=None, essid=None) -> str:
    """A `WPA*01*` line. Fields 6 and 7 are empty, not absent - hence the `***`."""
    return "*".join((
        HC22000_SIGNATURE,
        f"{HC22000_TYPE_PMKID:02d}",
        pmkid,
        _hex_mac(bssid),
        _hex_mac(station),
        _essid_hex(essid_raw, essid),
        "",
        "",
        f"{PMKID_AP:02x}",
    ))


def eapol_line(mic: bytes, bssid: str, station: str, essid_hex: str, nonce: bytes,
               frame: bytes, message_pair: int) -> str:
    """A `WPA*02*` line. `mic` must have been read before `frame` was zeroed."""
    return "*".join((
        HC22000_SIGNATURE,
        f"{HC22000_TYPE_EAPOL:02d}",
        mic.hex(),
        _hex_mac(bssid),
        _hex_mac(station),
        essid_hex,
        nonce.hex(),
        zero_mic(frame).hex(),
        f"{message_pair:02x}",
    ))


def _reject_reason(evidence, frame_message):
    """Why this candidate pair cannot be used, or None if it can."""
    frame = evidence[frame_message]
    if frame.frame is None:
        # `MessageEvidence` refuses to keep an oversized frame, so a recorded length with no
        # bytes is precisely the too-large case rather than a frame that was never seen.
        return STATUS_TOO_LARGE if frame.frame_length > HC22000_EAPOL_MAX else STATUS_NO_PAIR
    if len(frame.frame) < HC22000_EAPOL_MIN:
        return STATUS_NO_PAIR
    if frame_message == "M4" and frame.nonce_zeroed:
        return STATUS_NONCE_ZEROED
    if frame.mic_zeroed:
        return STATUS_MIC_ZEROED
    if frame.key_version not in (1, 2, 3):
        return STATUS_BAD_KEY_VERSION
    return None


def best_eapol(handshake):
    """`(line_parts, status)` for the best usable message pair, or `(None, reason)`.

    `line_parts` is `(mic, nonce, frame, message_pair)`; the caller supplies the identifiers.
    Every candidate pair is tried in `_PAIRS` order and the first usable one wins, mirroring
    hcxpcapngtool's default of emitting one best hash per AP/client pair rather than every
    variant. The reason returned on failure is the most specific one encountered, so a
    handshake rejected purely for size says so instead of claiming nothing was captured.
    """
    evidence, counters = handshake.evidence, handshake.replay_counters
    reasons = []

    for message_pair, frame_message, nonce_message, replay_ok in _PAIRS:
        if frame_message not in evidence or nonce_message not in evidence:
            continue
        if not replay_ok(counters):
            reasons.append(STATUS_REPLAY_MISMATCH)
            continue
        reason = _reject_reason(evidence, frame_message)
        if reason is not None:
            reasons.append(reason)
            continue
        frame = evidence[frame_message]
        return (frame.mic, evidence[nonce_message].nonce, frame.frame, message_pair), STATUS_OK

    for specific in (STATUS_TOO_LARGE, STATUS_NONCE_ZEROED, STATUS_REPLAY_MISMATCH,
                     STATUS_BAD_KEY_VERSION, STATUS_MIC_ZEROED):
        if specific in reasons:
            return None, specific
    return None, STATUS_NO_PAIR


def build(handshake, bssid: str, station: str, akms=None, essid_raw=None, essid=None):
    """`(pmkid_line, eapol_line, status)` for one handshake.

    Either line may be None while the other is present - a capture can hold a PMKID with no
    usable 4-way, and a 4-way with no PMKID - so they are returned separately rather than
    ranked against each other.

    `status` describes the EAPOL line specifically, since the PMKID line has only one way to
    be absent (no PMKID was seen) while the EAPOL line has several that an operator would act
    on differently.
    """
    if not is_psk(akms):
        return None, None, no_hash_reason(akms)

    essid_hex = _essid_hex(essid_raw, essid)
    if not essid_hex:
        # The ESSID is the PBKDF2 salt. hashcat accepts an empty one, but the resulting line
        # can never crack, so emitting it would be the same false promise as an enterprise
        # hash.
        return None, None, STATUS_NO_ESSID

    pmkid = None
    if handshake.pmkid:
        pmkid = pmkid_line(handshake.pmkid, bssid, station, essid_raw, essid)

    parts, status = best_eapol(handshake)
    eapol = None
    if parts is not None:
        mic, nonce, frame, message_pair = parts
        eapol = eapol_line(mic, bssid, station, essid_hex, nonce, frame, message_pair)

    return pmkid, eapol, status


def render(result) -> str:
    """Every hash a capture yields, one per line, newest format first.

    Both line types for a handshake are written when both exist - they attack the same PSK by
    different routes, and hashcat is happy to be given both. Ordering is by BSSID then station
    so two runs over one capture produce identical files.
    """
    from .graph import handshake_records

    records = handshake_records(result)
    lines = []
    for key in sorted(records):
        pmkid, eapol, _ = records[key].hashes
        lines.extend(line for line in (pmkid, eapol) if line)

    return "".join(line + "\n" for line in lines)


def write(result, path) -> int:
    """Write the hash file, or stdout when the path is ``-``. Returns the line count.

    An empty result still writes the file. A zero-byte hash file is a finding - it says the
    capture holds nothing crackable - and silently skipping the write would leave an operator
    unsure whether the tool ran.
    """
    text = render(result)
    count = text.count("\n")
    if str(path) == "-":
        import sys

        sys.stdout.write(text)
        return count
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return count
