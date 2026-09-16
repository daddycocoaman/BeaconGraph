"""TLS record walking and X.509 field extraction, for the certificate chain EAP sends in clear.

An enterprise network's authentication server presents its whole certificate chain before the
tunnel closes, so a capture of the first few frames of any 802.1X association carries the
internal PKI: the RADIUS server's identity, the CA that signs for it, and the root a client is
configured to trust. That is what an evil twin has to impersonate, which makes it worth a node.

Lengths here are attacker-supplied, so every walk is bounds-checked and a malformed tail
truncates rather than raising - the same posture as ``pcap.ie``, and for the same reason: a
chain whose third certificate is corrupt should still yield the first two.

Certificate parsing delegates to scapy's X.509 layer. scapy is already a dependency, the layer
is pure Python, and this is the handful-of-frames case its real dissectors are reserved for -
there are 20 EAP frames in the 47,795-frame sample capture.
"""
import hashlib

from .constants import TLS_CONTENT_HANDSHAKE, TLS_HANDSHAKE_CERTIFICATE

#: RFC 5280: a 2-digit year of 50 or more is 19xx, below 50 is 20xx.
_UTCTIME_PIVOT = 50


def handshake_messages(stream):
    """Yield ``(handshake_type, body)`` from a reassembled TLS stream.

    Two walks, and the order matters: every type-22 record payload is concatenated *first*,
    then handshake headers are read out of the join. A handshake message legitimately spans
    record boundaries - the certificate chain here is 4,047 bytes across several records - so
    parsing each record independently would truncate it at the first boundary.
    """
    body = bytearray()
    offset = 0
    while offset + 5 <= len(stream):
        content_type = stream[offset]
        length = int.from_bytes(stream[offset + 3:offset + 5], "big")
        end = offset + 5 + length
        if end > len(stream):
            body += stream[offset + 5:]  # truncated final record: keep what arrived
            break
        if content_type == TLS_CONTENT_HANDSHAKE:
            body += stream[offset + 5:end]
        offset = end

    offset = 0
    while offset + 4 <= len(body):
        handshake_type = body[offset]
        length = int.from_bytes(body[offset + 1:offset + 4], "big")
        end = offset + 4 + length
        if end > len(body):
            return  # declared past the end - nothing after this can be trusted
        yield handshake_type, bytes(body[offset + 4:end])
        offset = end


def certificates(body):
    """Yield DER bytes from a Certificate handshake message, leaf first.

    Layout is a 3-byte length for the whole list, then each certificate behind its own 3-byte
    length. Chain order is significant and preserved: index 0 is the server's own certificate.
    """
    if len(body) < 3:
        return
    total = int.from_bytes(body[0:3], "big")
    end = min(3 + total, len(body))
    offset = 3
    while offset + 3 <= end:
        length = int.from_bytes(body[offset:offset + 3], "big")
        offset += 3
        if offset + length > end:
            return
        yield bytes(body[offset:offset + length])
        offset += length


def _format_asn1_time(value) -> str:
    """ASN.1 UTCTime/GeneralizedTime to the repo's ``"%Y-%m-%d %H:%M:%S"``.

    Returned as a plain string rather than a datetime because every property written to the
    graph is a ``str``, ``int`` or ``bool``. The value is UTC - unlike airodump's local-time
    columns, a certificate's validity carries its zone explicitly - so it is not shifted by
    ``--capture-tz``.
    """
    text = value.decode("ascii", "replace") if isinstance(value, bytes) else str(value)
    text = text.strip().rstrip("Z")
    digits = "".join(c for c in text if c.isdigit())
    if len(digits) == 12:  # UTCTime: YYMMDDHHMMSS
        year = int(digits[0:2])
        year += 1900 if year >= _UTCTIME_PIVOT else 2000
        rest = digits[2:]
    elif len(digits) >= 14:  # GeneralizedTime: YYYYMMDDHHMMSS
        year, rest = int(digits[0:4]), digits[4:14]
    else:
        return None
    return (f"{year:04d}-{rest[0:2]}-{rest[2:4]} "
            f"{rest[4:6]}:{rest[6:8]}:{rest[8:10]}")


def _rdn_values(name_seq):
    """Flatten an X.509 Name into ``[(attribute_name, value), ...]``."""
    out = []
    for rdn_set in name_seq or ():
        for attribute in getattr(rdn_set, "rdn", ()) or ():
            try:
                key = attribute.type.oidname
                value = attribute.value.val
            except AttributeError:
                continue
            if isinstance(value, bytes):
                value = value.decode("utf-8", "replace")
            out.append((str(key), str(value)))
    return out


def _distinguished_name(pairs) -> str:
    """``"C=US, O=BNSF Railway, CN=host"`` - the form openssl prints, for eyeballing."""
    short = {"countryName": "C", "stateOrProvinceName": "ST", "localityName": "L",
             "organizationName": "O", "organizationUnitName": "OU", "commonName": "CN",
             "emailAddress": "emailAddress"}
    return ", ".join(f"{short.get(k, k)}={v}" for k, v in pairs)


def _common_name(pairs):
    for key, value in pairs:
        if key == "commonName":
            return value
    return None


class CertificateInfo:
    """One parsed certificate. Every field may be None - see the omit rule in ``records``."""

    __slots__ = ("fingerprint", "common_name", "subject", "issuer", "issuer_common_name",
                 "serial", "not_before", "not_after", "signature_algorithm", "san",
                 "is_ca", "self_signed")

    def __init__(self, fingerprint, common_name=None, subject=None, issuer=None,
                 issuer_common_name=None, serial=None, not_before=None, not_after=None,
                 signature_algorithm=None, san=(), is_ca=False, self_signed=False):
        self.fingerprint = fingerprint
        self.common_name = common_name
        self.subject = subject
        self.issuer = issuer
        self.issuer_common_name = issuer_common_name
        self.serial = serial
        self.not_before = not_before
        self.not_after = not_after
        self.signature_algorithm = signature_algorithm
        self.san = tuple(san)
        self.is_ca = is_ca
        self.self_signed = self_signed

    @property
    def name(self) -> str:
        """What the UI renders. Falls back to the fingerprint for a certificate with no CN -
        legal, and increasingly common where the identity lives entirely in the SAN."""
        return self.common_name or (self.san[0] if self.san else self.fingerprint)

    def __repr__(self):
        return f"<CertificateInfo {self.name}>"


def _extensions(tbs):
    """``(san_names, is_ca)`` from the extensions scapy exposes, both optional."""
    san, is_ca = [], False
    for extension in getattr(tbs, "extensions", None) or ():
        oid = getattr(getattr(extension, "extnID", None), "oidname", None)
        value = getattr(extension, "extnValue", None)
        if oid == "subjectAltName":
            # Each entry is a GeneralName wrapper around one of several typed alternatives,
            # so the value is two levels down rather than an attribute of the entry itself.
            for entry in getattr(value, "subjectAltName", None) or ():
                general = getattr(entry, "generalName", entry)
                for attr in ("dNSName", "iPAddress", "rfc822Name",
                             "uniformResourceIdentifier"):
                    raw = getattr(general, attr, None)
                    if raw is None:
                        continue
                    raw = getattr(raw, "val", raw)
                    if isinstance(raw, bytes):
                        raw = raw.decode("utf-8", "replace")
                    san.append(str(raw))
        elif oid == "basicConstraints":
            is_ca = bool(getattr(value, "cA", False))
    return san, is_ca


def parse_certificate(der):
    """``CertificateInfo`` for one DER certificate, or None if it will not parse.

    Never raises: one unparsable certificate must not cost the rest of the chain, and the
    bytes come off the wire from a host we are only observing.
    """
    fingerprint = hashlib.sha256(der).hexdigest()
    try:
        from scapy.layers.x509 import X509_Cert

        tbs = X509_Cert(der).tbsCertificate
        subject = _rdn_values(tbs.subject)
        issuer = _rdn_values(tbs.issuer)
        san, is_ca = _extensions(tbs)
        serial = getattr(getattr(tbs, "serialNumber", None), "val", None)
        return CertificateInfo(
            fingerprint=fingerprint,
            common_name=_common_name(subject),
            subject=_distinguished_name(subject) or None,
            issuer=_distinguished_name(issuer) or None,
            issuer_common_name=_common_name(issuer),
            serial=f"{serial:X}" if serial is not None else None,
            not_before=_format_asn1_time(tbs.validity.not_before.val),
            not_after=_format_asn1_time(tbs.validity.not_after.val),
            signature_algorithm=str(getattr(tbs.signature.algorithm, "oidname", "")) or None,
            san=san,
            is_ca=is_ca,
            self_signed=bool(subject) and subject == issuer,
        )
    except Exception:
        return CertificateInfo(fingerprint=fingerprint)


def chain_from_stream(stream):
    """Every certificate in the first Certificate message of a reassembled TLS stream."""
    for handshake_type, body in handshake_messages(stream):
        if handshake_type != TLS_HANDSHAKE_CERTIFICATE:
            continue
        return [parse_certificate(der) for der in certificates(body)]
    return []
