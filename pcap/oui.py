"""Vendor lookup by MAC prefix.

A dict-per-prefix-length replacement for ``backend.parser.macLookup``, which does nine full
scans of a 41,271-row pandas DataFrame per MAC (~371k row comparisons) and pays a DataFrame
build at import time even for callers that never look anything up. Importing it would also
drag pandas and the Neo4j driver into the pcap path for no reason.

Only three prefix lengths exist in the database - 8, 10 and 13 characters, i.e. MA-L, MA-M
and MA-S registries - so three dicts probed longest-first reproduce the original's
longest-prefix-wins behaviour exactly, and a trie would buy nothing.
"""
import json
from functools import lru_cache
from importlib import resources
from pathlib import Path

#: Falls back to the checkout layout, where the backend package sits at backend/backend/.
_CHECKOUT_DB = (Path(__file__).resolve().parent.parent
                / "backend" / "backend" / "macaddress.io-db.json")


def default_database_path() -> Path:
    """Locate the OUI database that ships with the backend package.

    Resolved through the package rather than by walking up from this file, because the two
    layouts differ: a checkout has it at ``backend/backend/macaddress.io-db.json`` while an
    installed wheel flattens it to ``site-packages/backend/macaddress.io-db.json``. A
    relative path works in one and not the other.
    """
    try:
        packaged = resources.files("backend").joinpath("macaddress.io-db.json")
        if packaged.is_file():
            return Path(str(packaged))
    except (ModuleNotFoundError, AttributeError, TypeError):
        pass
    return _CHECKOUT_DB

#: MA-S (28-bit), MA-M (24-bit) and MA-L (36-bit) prefix widths as colon-separated text.
#: Probed longest-first so a specific assignment wins over the block it sits inside.
PREFIX_LENGTHS = (13, 10, 8)


class OuiDatabase:
    """Vendor names keyed by MAC prefix."""

    __slots__ = ("_by_length", "source")

    def __init__(self, by_length, source=None):
        self._by_length = by_length
        self.source = source

    @classmethod
    def load(cls, path=None) -> "OuiDatabase":
        target = Path(path) if path is not None else default_database_path()
        by_length = {length: {} for length in PREFIX_LENGTHS}

        with open(target, "rb") as handle:
            for line in handle:
                if not line.strip():
                    continue
                record = json.loads(line)
                prefix = record.get("oui")
                company = record.get("companyName")
                if not prefix or not company:
                    continue
                bucket = by_length.get(len(prefix))
                if bucket is not None:
                    bucket.setdefault(prefix.upper(), company)

        return cls(by_length, source=target)

    def lookup(self, mac: str):
        """The vendor for a canonical uppercase MAC, or None.

        Returns None for locally administered addresses without touching the table - a
        randomized MAC has no registered owner by definition, and skipping them removes most
        of the remaining per-MAC cost on a modern capture where the majority of stations
        randomize.
        """
        if not mac or len(mac) < 8:
            return None
        if int(mac[0:2], 16) & 0x02:
            return None
        for length in PREFIX_LENGTHS:
            found = self._by_length[length].get(mac[:length])
            if found is not None:
                return found
        return None

    def __len__(self) -> int:
        return sum(len(bucket) for bucket in self._by_length.values())


_INSTANCE = None


def database(path=None) -> OuiDatabase:
    """The shared database, loaded on first use."""
    global _INSTANCE
    if _INSTANCE is None or path is not None:
        loaded = OuiDatabase.load(path)
        if path is None:
            _INSTANCE = loaded
        return loaded
    return _INSTANCE


@lru_cache(maxsize=100_000)
def lookup(mac: str):
    """Cached vendor lookup against the shared database."""
    return database().lookup(mac)
