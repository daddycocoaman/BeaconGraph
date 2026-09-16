"""WPS (Wi-Fi Simple Config) attribute parsing, and the PIN-attack verdict it supports.

`ie.py` stays a dumb 802.11 IE walker; this module interprets the vendor payload it hands
back, the same split `crypto.py` has against the RSN element and `tls.py` against the TLS
stream.

"WPS is on" is not actionable. What decides whether a tester spends hours on Reaver or Bully
is the state around it: whether the AP is in setup lockout, whether it is in the configured
state, and whether it advertises a config method that implies a PIN at all. The inverse is
worth as much - an AP in lockout, or one that is push-button only, is ruled out from a passive
capture rather than from a day of failed attempts.

Three encodings meet here and only one of them is the 802.11 convention, which is the whole
reason this file is separate:

* the enclosing 802.11 element is 1-byte id, 1-byte length, little-endian fields;
* a WPS attribute is **2-byte big-endian id, 2-byte big-endian length**;
* a subelement *inside* a Vendor Extension is back to **1-byte id, 1-byte length**.

Both walkers here follow the two rules `pcap.ie` states: never trust a declared length
against the real buffer, and on overrun return what parsed so far rather than discarding it.

One asymmetry drives the rest of the design. The WPS IE in a **Beacon** does not carry Config
Methods (0x1008) at all - that attribute is specified for the **Probe Response**. A verdict
that needs config methods therefore cannot be reached from beacons alone, so `WPSInfo`
distinguishes "ruled out" from "not enough data" rather than reporting a confident false.
"""
from .constants import (
    WFA_SUBELEM_VERSION2,
    WFA_VENDOR_EXT_OUI,
    WPS_CONFIG_METHODS,
    WPS_DEVICE_PASSWORD_IDS,
    WPS_PIN_METHODS,
    WPS_STATE_CONFIGURED,
    WPS_STATE_NAMES,
    WPS_STATE_UNCONFIGURED,
    WPSAttr,
)

#: Config method bits, high to low, so ``config_method_names`` is stable across runs and
#: across captures. Sorting the dict at call time would do the same; precomputing keeps the
#: per-frame cost off the hot path.
_METHOD_BITS = tuple(sorted(WPS_CONFIG_METHODS.items(), reverse=True))


def walk(body):
    """Yield ``(attribute_id, value)`` from a WPS attribute payload.

    2-byte big-endian id, 2-byte big-endian length, value. ``body`` may be a memoryview -
    values are yielded as ``bytes`` because they routinely outlive the frame buffer.
    """
    position, end = 0, len(body)
    while position + 4 <= end:
        attribute = (body[position] << 8) | body[position + 1]
        length = (body[position + 2] << 8) | body[position + 3]
        value_end = position + 4 + length
        if value_end > end:
            return  # declared past the buffer; keep what the caller already has
        yield attribute, bytes(body[position + 4:value_end])
        position = value_end


def _vendor_subelements(body):
    """Yield ``(subelement_id, value)`` from a Vendor Extension body, past its 3-byte OUI.

    Deliberately not ``walk()``: subelements are **1-byte id, 1-byte length**. Reusing the
    2+2 walker here parses the first two subelement headers as one id and returns garbage,
    and the garbage is plausible - it is a small integer where a version byte is expected.
    """
    position, end = 0, len(body)
    while position + 2 <= end:
        subelement = body[position]
        length = body[position + 1]
        value_end = position + 2 + length
        if value_end > end:
            return
        yield subelement, bytes(body[position + 2:value_end])
        position = value_end


def _uint16(value):
    return (value[0] << 8) | value[1] if len(value) >= 2 else None


def config_method_names(mask) -> str:
    """Comma-joined method names for a config-methods bitmask.

    Decoded bit by bit. The registry lists Physical Push Button as ``0x0280`` and Virtual
    Display as ``0x2008``, but those are ``0x0200|0x0080`` and ``0x2000|0x0008`` - a table
    keyed on composite values both misses the single bits and double-reports the pairs. An
    unrecognised bit is kept as its hex value rather than dropped: a bit nobody has a name
    for is still evidence about the device.
    """
    if not mask:
        return ""
    names = [name for bit, name in _METHOD_BITS if mask & bit]
    unknown = mask & ~sum(WPS_CONFIG_METHODS)
    if unknown:
        names.append(f"0x{unknown:04X}")
    return ",".join(names)


class WPSInfo:
    """The attack-decision state of one AP's WPS implementation.

    Every field defaults to None meaning "not observed", which `merge()` and the verdict both
    depend on: absent is not the same as off, and an AP whose lockout state was never seen is
    not an AP that is unlocked.
    """

    __slots__ = ("version", "version2", "wps_state", "ap_setup_locked", "selected_registrar",
                 "config_methods", "selected_registrar_config_methods", "device_password_id")

    def __init__(self, version=None, version2=None, wps_state=None, ap_setup_locked=None,
                 selected_registrar=None, config_methods=None,
                 selected_registrar_config_methods=None, device_password_id=None):
        self.version = version
        #: From the WFA Vendor Extension, and the only version signal worth reporting - see
        #: ``version_name``.
        self.version2 = version2
        self.wps_state = wps_state
        self.ap_setup_locked = ap_setup_locked
        self.selected_registrar = selected_registrar
        self.config_methods = config_methods
        self.selected_registrar_config_methods = selected_registrar_config_methods
        self.device_password_id = device_password_id

    @property
    def version_name(self):
        """``"2.0"``/``"1.0"``, from Version2 where present.

        The legacy Version attribute (0x104A) is frozen at 0x10 on essentially every modern
        AP, so reporting it would call every WPS 2.0 device a 1.0 device - and 2.0 is exactly
        what mandates the lockout behaviour the verdict turns on, so the error inverts the
        finding rather than blurring it.
        """
        raw = self.version2 if self.version2 is not None else self.version
        if raw is None:
            return None
        return f"{raw >> 4}.{raw & 0x0F}"

    @property
    def effective_config_methods(self):
        """Config methods, falling back to the Selected Registrar's.

        Config Methods (0x1008) is a Probe Response attribute; Selected Registrar Config
        Methods (0x1053) is one of the few that a Beacon does carry. On a capture with no
        probe responses the fallback is the only way to reach a verdict at all.
        """
        if self.config_methods is not None:
            return self.config_methods
        return self.selected_registrar_config_methods

    @property
    def config_methods_names(self) -> str:
        return config_method_names(self.effective_config_methods)

    @property
    def device_password_name(self):
        if self.device_password_id is None:
            return None
        return WPS_DEVICE_PASSWORD_IDS.get(self.device_password_id,
                                           f"0x{self.device_password_id:04X}")

    @property
    def state_name(self):
        if self.wps_state is None:
            return None
        return WPS_STATE_NAMES.get(self.wps_state, f"0x{self.wps_state:02X}")

    @property
    def pin_attack_status(self) -> str:
        """Why a PIN attack is or is not worth attempting, as one word.

        Ordered by how conclusive each answer is. Lockout is checked first because it settles
        the question whichever way everything else points, and ``unknown`` is last because it
        is the honest answer when a beacon-only capture never carried config methods - the
        alternative, reporting "not viable", is a confident false.
        """
        if self.ap_setup_locked:
            return "locked"
        if self.wps_state == WPS_STATE_UNCONFIGURED:
            return "unconfigured"
        methods = self.effective_config_methods
        if methods is None or self.wps_state is None:
            return "unknown"
        if not methods & WPS_PIN_METHODS:
            return "pbc_only"
        if self.wps_state != WPS_STATE_CONFIGURED:
            return "unknown"
        return "viable"

    @property
    def pin_attack_viable(self) -> bool:
        return self.pin_attack_status == "viable"

    @property
    def complete(self) -> bool:
        """Whether enough has been seen to stop re-parsing this BSSID's WPS IE.

        The aggregator's sampling gate consults this: config methods arrive in probe
        responses and the state fields in beacons, so a BSSID is done only once both halves
        have landed.
        """
        return self.effective_config_methods is not None and self.wps_state is not None

    def __repr__(self) -> str:
        return f"<WPSInfo {self.state_name} {self.pin_attack_status}>"


def parse(body):
    """Parse a WPS IE body into a `WPSInfo`, or None if nothing usable was in it.

    Never raises. A malformed tail truncates and whatever parsed before it is kept, so a
    probe response whose last attribute is corrupt still yields the lockout state.
    """
    if not body:
        return None

    info = WPSInfo()
    found = False
    for attribute, value in walk(body):
        if not value:
            continue  # a zero-length attribute is legal framing, not a value
        found = True
        if attribute == WPSAttr.VERSION:
            info.version = value[0]
        elif attribute == WPSAttr.WPS_STATE:
            info.wps_state = value[0]
        elif attribute == WPSAttr.AP_SETUP_LOCKED:
            info.ap_setup_locked = bool(value[0])
        elif attribute == WPSAttr.SELECTED_REGISTRAR:
            info.selected_registrar = bool(value[0])
        elif attribute == WPSAttr.CONFIG_METHODS:
            info.config_methods = _uint16(value)
        elif attribute == WPSAttr.SELECTED_REGISTRAR_CONFIG_METHODS:
            info.selected_registrar_config_methods = _uint16(value)
        elif attribute == WPSAttr.DEVICE_PASSWORD_ID:
            info.device_password_id = _uint16(value)
        elif attribute == WPSAttr.VENDOR_EXTENSION:
            if len(value) > 3 and value[0:3] == WFA_VENDOR_EXT_OUI:
                for subelement, subvalue in _vendor_subelements(value[3:]):
                    if subelement == WFA_SUBELEM_VERSION2 and subvalue:
                        info.version2 = subvalue[0]

    return info if found else None


def merge(existing, new):
    """Fill fields still unknown on ``existing`` from ``new``, rather than last-write-wins.

    WPS attributes are split across frame types by the spec - a beacon carries the state and
    lockout, a probe response adds config methods - so overwriting would make the result
    depend on which frame happened to arrive last. Filling only what is still None means a
    partial beacon and a partial probe response accumulate into one complete picture, and
    also means a later frame cannot erase something already observed.
    """
    if existing is None:
        return new
    if new is None:
        return existing
    for field in WPSInfo.__slots__:
        if getattr(existing, field) is None:
            setattr(existing, field, getattr(new, field))
    return existing
