"""Authentication-frame decode: the algorithm, and what an SAE Commit reveals.

Three things a beacon cannot say:

* **Which AKM this association took.** Algorithm 0 is Open System (a PSK-family 4-way
  follows); 3 is SAE. On a BSS offering both, this is the only passive evidence of which half
  a given client used, and so of whether its handshake is crackable.
* **Hunting-and-Pecking vs Hash-to-Element**, from the Commit status code: 0 is HnP, 126 H2E.
  Not the same question as the RSNXE H2E bit, which says only that the AP is capable.
* **Group negotiation.** Status 77 is a rejected group - the shape of a downgrade attempt.

Bounds-checking is `ie.py`'s: a short or malformed body yields None rather than raising.
"""
import struct

from .constants import (
    AUTH_ALG_SAE,
    SAE_STATUS_HASH_TO_ELEMENT,
    SAE_STATUS_PK,
    SAE_STATUS_SUCCESS,
    SAE_STATUS_UNSUPPORTED_GROUP,
    SAE_PWE_HASH_TO_ELEMENT,
    SAE_PWE_HUNTING_AND_PECKING,
)

#: Authentication fixed fields: algorithm, transaction sequence, status code, each u16 LE.
FIXED_LEN = 6

#: SAE transaction sequence numbers.
SEQ_COMMIT = 1
SEQ_CONFIRM = 2


class AuthInfo:
    """One Authentication frame's fixed fields, plus the SAE group when it carries one."""

    __slots__ = ("algorithm", "sequence", "status", "group")

    def __init__(self, algorithm, sequence, status, group=None):
        self.algorithm = algorithm
        self.sequence = sequence
        self.status = status
        #: Finite cyclic group from a Commit. 19/20 are NIST curves; 15-18 MODP.
        self.group = group

    @property
    def is_sae(self) -> bool:
        return self.algorithm == AUTH_ALG_SAE

    @property
    def is_commit(self) -> bool:
        return self.is_sae and self.sequence == SEQ_COMMIT

    @property
    def pwe(self):
        """The password-to-element method, or None if this frame does not say.

        Only a Commit says, and only via status 0 or 126. A status meaning something else
        (76 anti-clogging, 77 rejected group) is not a vote for Hunting-and-Pecking.
        """
        if not self.is_commit:
            return None
        if self.status in (SAE_STATUS_HASH_TO_ELEMENT, SAE_STATUS_PK):
            return SAE_PWE_HASH_TO_ELEMENT
        if self.status == SAE_STATUS_SUCCESS:
            return SAE_PWE_HUNTING_AND_PECKING
        return None

    @property
    def group_rejected(self) -> bool:
        return self.is_sae and self.status == SAE_STATUS_UNSUPPORTED_GROUP

    def __repr__(self):
        return f"<AuthInfo alg={self.algorithm} seq={self.sequence} status={self.status}>"


def parse(body) -> AuthInfo:
    """Decode an Authentication frame body, or ``None`` if it is too short to be one."""
    if body is None or len(body) < FIXED_LEN:
        return None
    algorithm, sequence, status = struct.unpack_from("<HHH", body, 0)

    group = None
    if algorithm == AUTH_ALG_SAE and sequence == SEQ_COMMIT and len(body) >= FIXED_LEN + 2:
        group = struct.unpack_from("<H", body, FIXED_LEN)[0]

    return AuthInfo(algorithm, sequence, status, group)
