"""Numeric tables and enums for 802.11 decoding. Pure data - no logic, no heavy imports."""
from enum import IntEnum

# -- link types -----------------------------------------------------------

DLT_IEEE802_11 = 105
DLT_PRISM = 119
DLT_IEEE802_11_RADIOTAP = 127
DLT_IEEE802_11_AVS = 163

# dlt -> (name, fixed radio header length or None if variable, carries radio metadata)
LINK_TYPES = {
    DLT_IEEE802_11: ("IEEE802_11", 0, False),
    DLT_PRISM: ("PRISM_HEADER", 144, True),
    DLT_IEEE802_11_RADIOTAP: ("IEEE802_11_RADIOTAP", None, True),
    DLT_IEEE802_11_AVS: ("IEEE802_11_AVS", None, True),
}


# -- frame control --------------------------------------------------------


class FrameType(IntEnum):
    MGMT = 0
    CTRL = 1
    DATA = 2
    EXT = 3


class Mgmt(IntEnum):
    ASSOC_REQ = 0
    ASSOC_RESP = 1
    REASSOC_REQ = 2
    REASSOC_RESP = 3
    PROBE_REQ = 4
    PROBE_RESP = 5
    BEACON = 8
    ATIM = 9
    DISASSOC = 10
    AUTH = 11
    DEAUTH = 12
    ACTION = 13
    ACTION_NO_ACK = 14


class Ctrl(IntEnum):
    VHT_NDP_ANNOUNCE = 5
    BLOCK_ACK_REQ = 8
    BLOCK_ACK = 9
    PS_POLL = 10
    RTS = 11
    CTS = 12
    ACK = 13
    CF_END = 14
    CF_END_ACK = 15


#: Data-frame subtype bit 0x04 means "no data carried" - Null, QoS Null and friends. They
#: count toward a station's packet total but never toward the WEP IV count.
DATA_SUBTYPE_NULL_BIT = 0x04
#: Data-frame subtype bit 0x08 means a 2-byte QoS Control field follows the addresses.
DATA_SUBTYPE_QOS_BIT = 0x08

#: Control subtypes that carry a transmitter address (addr2) as well as a receiver. ACK, CTS
#: and CF-End carry only addr1, so they can never attribute a frame to anyone.
CTRL_SUBTYPES_WITH_TA = frozenset({Ctrl.BLOCK_ACK_REQ, Ctrl.BLOCK_ACK, Ctrl.PS_POLL, Ctrl.RTS})

BROADCAST = "FF:FF:FF:FF:FF:FF"


# -- information elements -------------------------------------------------


class EID(IntEnum):
    SSID = 0
    SUPPORTED_RATES = 1
    DS_PARAMETER_SET = 3
    TIM = 5
    COUNTRY = 7
    ERP = 42
    HT_CAPABILITIES = 45
    RSN = 48
    EXTENDED_RATES = 50
    MOBILITY_DOMAIN = 54
    FAST_BSS_TRANSITION = 55
    HT_OPERATION = 61
    EXTENDED_CAPABILITIES = 127
    VHT_CAPABILITIES = 191
    VHT_OPERATION = 192
    VENDOR_SPECIFIC = 221
    RSNX = 244
    EXTENSION = 255


#: Element ID Extension values, keyed as (255, ext_id) so HE/EHT slot in without reworking
#: the map.
EXT_HE_CAPABILITIES = 35
EXT_HE_OPERATION = 36
EXT_EHT_OPERATION = 106
EXT_EHT_CAPABILITIES = 108

RSN_OUI = b"\x00\x0f\xac"
MS_OUI = b"\x00\x50\xf2"      # Microsoft: WPA1 (type 1), WMM (2), WPS (4)
WFA_OUI = b"\x50\x6f\x9a"     # Wi-Fi Alliance: OWE transition (0x1c), MBO, P2P

VENDOR_WPA1 = (MS_OUI, 1)
VENDOR_WMM = (MS_OUI, 2)
VENDOR_WPS = (MS_OUI, 4)
VENDOR_OWE_TRANSITION = (WFA_OUI, 0x1C)

#: RSN overriding (WPA3 spec v3.4+ §2.4/§14). Compatibility Mode advertises PSK-only with PMF
#: off in the real RSNE and hides SAE here, so a non-RSNO client joins as WPA2-PSK over the
#: same passphrase. Bodies past the 4-byte header are verbatim RSNE/RSNXE bodies.
#: Types from hostap `src/common/ieee802_11_defs.h`.
VENDOR_RSNE_OVERRIDE = (WFA_OUI, 0x29)
VENDOR_RSNE_OVERRIDE_2 = (WFA_OUI, 0x2A)
VENDOR_RSNXE_OVERRIDE = (WFA_OUI, 0x2B)
VENDOR_RSN_SELECTION = (WFA_OUI, 0x2C)

#: Capability Information field, present in Beacon and Probe Response after the 8-byte
#: timestamp and 2-byte beacon interval.
CAP_ESS = 0x0001
CAP_IBSS = 0x0002
CAP_PRIVACY = 0x0010


# -- RSN cipher and AKM suites -------------------------------------------

#: Suite type -> airodump's cipher token. Applies to both 00-0F-AC (RSN) and 00-50-F2 (WPA1);
#: WPA1 only ever uses 1, 2, 4 and 5.
CIPHER_SUITES = {
    0: "GROUP",        # "use the group cipher"
    1: "WEP40",
    2: "TKIP",
    3: "WRAP",
    4: "CCMP",
    5: "WEP104",
    6: "CMAC",         # BIP-CMAC-128
    8: "GCMP",
    9: "GCMP-256",
    10: "CCMP-256",
    11: "GMAC",        # BIP-GMAC-128
    12: "GMAC-256",
    13: "CMAC-256",
}

#: Suite type -> the coarse token airodump prints in its Authentication column. Several
#: distinct AKMs collapse onto one token here (802.1X and FT-802.1X both print MGT), which is
#: exactly the flattening the CSV performs - keep it for parity and carry the real suite
#: names in AKM_SUITES.
AKM_AUTH_TOKENS = {
    1: "MGT", 2: "PSK", 3: "MGT", 4: "PSK", 5: "MGT", 6: "PSK",
    7: "TDLS", 8: "SAE", 9: "SAE", 10: "APPEER", 11: "MGT", 12: "MGT",
    13: "MGT", 14: "FILS", 15: "FILS", 16: "FILS", 17: "FILS",
    18: "OWE", 19: "PSK", 20: "PSK", 24: "SAE", 25: "SAE",
}

#: Suite type -> the actual AKM name, which the CSV cannot express.
AKM_SUITES = {
    1: "802.1X", 2: "PSK", 3: "FT-802.1X", 4: "FT-PSK",
    5: "802.1X-SHA256", 6: "PSK-SHA256", 7: "TDLS",
    8: "SAE", 9: "FT-SAE", 10: "AP-PeerKey",
    11: "802.1X-SuiteB", 12: "802.1X-SuiteB-192", 13: "FT-802.1X-SHA384",
    14: "FILS-SHA256", 15: "FILS-SHA384", 16: "FT-FILS-SHA256", 17: "FT-FILS-SHA384",
    18: "OWE", 19: "FT-PSK-SHA384", 20: "PSK-SHA384",
    24: "SAE-EXT-KEY", 25: "FT-SAE-EXT-KEY",
}

#: AKMs whose PMK comes from a passphrase, and therefore the only ones a hashcat mode 22000
#: hash can ever recover. SAE is deliberately absent: WPA3-Personal derives its PMK through
#: dragonfly rather than PBKDF2, so a 22000 line for it would be uncrackable in a way that
#: looks exactly like a crackable one.
AKM_PSK = frozenset({2, 4, 6, 19, 20})

#: AKMs that make a network WPA3 rather than WPA2.
AKM_WPA3_PERSONAL = frozenset({8, 9, 24, 25})     # SAE family
AKM_OWE = frozenset({18})                          # Enhanced Open
AKM_SUITE_B = frozenset({11, 12})                  # WPA3-Enterprise
AKM_ENTERPRISE = frozenset({1, 3, 5, 11, 12, 13})  # 802.1X family

#: 802.11r AKMs by PMK-R0 source: FT-PSK from PBKDF2 (leaks a verifier in one frame), FT-SAE
#: from the SAE PMK (leaks nothing).
AKM_FT_PSK = frozenset({4, 19})
AKM_FT_SAE = frozenset({9, 25})

#: RSN Capabilities bits. Bit 6 is "required", bit 7 is "capable" - the pair distinguishes
#: WPA2, WPA2-with-PMF and WPA3.
RSN_CAP_MFPR = 1 << 6
RSN_CAP_MFPC = 1 << 7
#: Operating Channel Validation Capable. The multi-channel MITM countermeasure; optional
#: everywhere in the WPA3 spec, so clear-with-PMF-required is the common case and a finding.
RSN_CAP_OCVC = 1 << 14

#: Extended Capabilities bit 84. Beacon Protection is the complete fix for CSA beacon forgery
#: under PMF. Needs an 11-octet element and most APs send 8, so absent != off.
EXTCAP_BEACON_PROTECTION = 84

#: RSNXE (EID 244) bits. Advertising H2E is not the same as using it - the SAE Commit status
#: below says which was negotiated.
RSNX_SAE_H2E = 5
RSNX_SAE_PK = 6

#: Authentication algorithm in a Management/Auth frame. Algorithm 3 is SAE, which promotes a
#: BSSID to WPA3 even when its beacon was never captured.
AUTH_ALG_OPEN = 0
AUTH_ALG_SHARED_KEY = 1
AUTH_ALG_FT = 2
AUTH_ALG_SAE = 3

AUTH_ALG_NAMES = {
    AUTH_ALG_OPEN: "open",
    AUTH_ALG_SHARED_KEY: "shared_key",
    AUTH_ALG_FT: "ft",
    AUTH_ALG_SAE: "sae",
}

#: SAE Commit status codes. 0 is Hunting-and-Pecking (timing-side-channel affected on its MODP
#: path, still spec-legal on 2.4/5 GHz), 126 Hash-to-Element, 77 a rejected group.
SAE_STATUS_SUCCESS = 0
SAE_STATUS_ANTI_CLOGGING = 76
SAE_STATUS_UNSUPPORTED_GROUP = 77
SAE_STATUS_HASH_TO_ELEMENT = 126
SAE_STATUS_PK = 127

#: The value `sae_pwe` takes on an AP node, by the status code observed in its SAE Commit.
SAE_PWE_HUNTING_AND_PECKING = "hunting_and_pecking"
SAE_PWE_HASH_TO_ELEMENT = "h2e"

#: FTE subelement ids (802.11-2020 §9.4.2.48). The body is MIC Control(2) MIC(16) ANonce(32)
#: SNonce(32) and only then these 1+1 subelements.
FTE_SUBELEM_R1KH_ID = 1
FTE_SUBELEM_GTK = 2
FTE_SUBELEM_R0KH_ID = 3
FTE_HEADER_LEN = 2 + 16 + 32 + 32


# -- deauthentication / disassociation ------------------------------------

REASON_CODES = {
    1: "Unspecified",
    2: "Previous authentication no longer valid",
    3: "Deauthenticated because STA is leaving",
    4: "Disassociated due to inactivity",
    5: "Disassociated because AP is unable to handle all associated STAs",
    6: "Class 2 frame received from nonauthenticated STA",
    7: "Class 3 frame received from nonassociated STA",
    8: "Disassociated because STA is leaving",
    9: "STA requesting association is not authenticated",
    13: "Invalid information element",
    14: "MIC failure",
    15: "4-way handshake timeout",
    16: "Group key handshake timeout",
    17: "Information element mismatch",
    18: "Invalid group cipher",
    19: "Invalid pairwise cipher",
    20: "Invalid AKMP",
    23: "IEEE 802.1X authentication failed",
    24: "Cipher suite rejected by security policy",
}


# -- PHY rates ------------------------------------------------------------

#: HT MCS 0-7, 20 MHz, one spatial stream, long guard interval (Mbps).
HT_MCS_20MHZ_LGI = (6.5, 13.0, 19.5, 26.0, 39.0, 52.0, 58.5, 65.0)

#: HT40 is 2.0769x HT20 (108 vs 52 data subcarriers).
HT40_FACTOR = 2.0769

#: Short guard interval shortens the symbol from 4.0us to 3.6us.
SGI_FACTOR = 1 / 0.9

#: VHT 80 MHz, one spatial stream, long guard interval, by max MCS (Mbps).
VHT_80MHZ_LGI = {7: 292.5, 8: 351.0, 9: 390.0}

#: Rate-set sentinels: 127 is "HT PHY", 126 is "VHT PHY". They are membership selectors, not
#: rates, and including them in a max computation yields a nonsense 63 Mbps.
RATE_SELECTORS = frozenset({126, 127})


# -- EAPOL ----------------------------------------------------------------

ETHERTYPE_EAPOL = 0x888E
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806

EAPOL_TYPE_EAP_PACKET = 0
EAPOL_TYPE_START = 1
EAPOL_TYPE_LOGOFF = 2
EAPOL_TYPE_KEY = 3

#: Key Information bitfield of an EAPOL-Key frame.
KEY_INFO_PAIRWISE = 1 << 3
KEY_INFO_INSTALL = 1 << 6
KEY_INFO_ACK = 1 << 7
KEY_INFO_MIC = 1 << 8
KEY_INFO_SECURE = 1 << 9
KEY_INFO_ERROR = 1 << 10
KEY_INFO_REQUEST = 1 << 11
KEY_INFO_ENCRYPTED = 1 << 12

#: The Key Descriptor Version lives in the low three bits: 1 = HMAC-MD5/RC4, 2 = HMAC-SHA1/AES,
#: 3 = AES-CMAC. hashcat recovers it from inside the EAPOL blob rather than from a field of its
#: own, and rejects anything outside 1-3, so a frame carrying 0 cannot produce a usable line.
KEY_INFO_VERSION_MASK = 0x07


# -- hc22000 (hashcat mode 22000) -----------------------------------------

HC22000_SIGNATURE = "WPA"
HC22000_TYPE_PMKID = 1
HC22000_TYPE_EAPOL = 2

#: Offset of the Key MIC within a complete 802.1X frame: the 4-byte 802.1X header plus the
#: 77 bytes of EAPOL-Key fields that precede it. Zeroing at 77 instead - i.e. forgetting the
#: header - is the single most common way to produce a line that parses but never cracks.
HC22000_MIC_OFFSET = 4 + 77
HC22000_MIC_LENGTH = 16

#: Shortest legal 802.1X frame (4-byte header + 95 bytes of fixed EAPOL-Key fields). hashcat
#: rejects field 7 below this.
HC22000_EAPOL_MIN = 99

#: hcxpcapngtool refuses to write a frame longer than this into its hash file, even though
#: hashcat itself accepts 256. Matching the stricter of the two keeps our output loadable
#: anywhere theirs is.
HC22000_EAPOL_MAX = 255

#: Message pair, low three bits. The M1+M2 case is the odd one out: it proves only that the
#: station answered a challenge, not that the AP accepted the answer, so the passphrase it
#: recovers may be one the network would have rejected. Every other pair is authorized.
MP_M12_E2 = 0x00
MP_M14_E4 = 0x01
MP_M32_E2 = 0x02
MP_M32_E3 = 0x03
MP_M34_E3 = 0x04
MP_M34_E4 = 0x05

MP_APLESS = 0x10
MP_LE = 0x20
MP_BE = 0x40
#: Set when a replay-counter gap was tolerated, telling hashcat to run nonce-error-correction.
MP_NC = 0x80

#: The message pair byte hcxpcapngtool writes for an AP-sourced PMKID.
PMKID_AP = 0x01


# -- EAP ------------------------------------------------------------------

EAP_CODE_REQUEST = 1
EAP_CODE_RESPONSE = 2
EAP_CODE_SUCCESS = 3
EAP_CODE_FAILURE = 4

#: EAP method types. Only the ones worth naming in a graph property - the registry has
#: dozens, but an unlisted method still renders as its number rather than disappearing.
EAP_METHODS = {
    1: "Identity",
    2: "Notification",
    3: "Nak",
    4: "MD5-Challenge",
    6: "GTC",
    13: "TLS",
    17: "LEAP",
    18: "SIM",
    21: "TTLS",
    23: "AKA",
    25: "PEAP",
    29: "MSCHAPv2",
    43: "FAST",
    50: "AKA'",
}

#: Methods that carry a TLS handshake, and therefore the authentication server's certificate
#: chain in the clear before the tunnel closes. PEAP and TTLS encrypt only the *inner*
#: exchange; the outer ServerHello/Certificate is readable for all three.
EAP_TLS_METHODS = frozenset({13, 21, 25})

#: First byte of an EAP-TLS/TTLS/PEAP payload. Length-included adds a 4-byte total length
#: before the TLS data; More-fragments means another frame continues this message.
EAP_TLS_FLAG_LENGTH = 0x80
EAP_TLS_FLAG_MORE = 0x40
EAP_TLS_FLAG_START = 0x20


# -- TLS ------------------------------------------------------------------

TLS_CONTENT_HANDSHAKE = 22
TLS_HANDSHAKE_CERTIFICATE = 11


# -- WPS ------------------------------------------------------------------

#: Inside the WPS Vendor Extension attribute (0x1049). Not the 00:50:F2 that wraps the IE.
WFA_VENDOR_EXT_OUI = b"\x00\x37\x2a"

#: Subelement ids within a Vendor Extension body. These are 1-byte id + 1-byte length,
#: unlike the 2+2 of the enclosing WPS TLV.
WFA_SUBELEM_VERSION2 = 0x00


class WPSAttr(IntEnum):
    """WPS (Wi-Fi Simple Config) attribute ids, big-endian 2-byte.

    Only the attributes that bear on whether a PIN attack is worth attempting. The
    device-fingerprint set (Manufacturer 0x1021, Model Name 0x1023, Serial 0x1042,
    Device Name 0x1011, UUID-E 0x1047, Primary Device Type 0x1054, RF Bands 0x103C) is
    deliberately not here yet.
    """

    CONFIG_METHODS = 0x1008
    DEVICE_PASSWORD_ID = 0x1012
    SELECTED_REGISTRAR = 0x1041
    WPS_STATE = 0x1044
    VENDOR_EXTENSION = 0x1049
    VERSION = 0x104A
    SELECTED_REGISTRAR_CONFIG_METHODS = 0x1053
    AP_SETUP_LOCKED = 0x1057


WPS_STATE_UNCONFIGURED = 1
WPS_STATE_CONFIGURED = 2

WPS_STATE_NAMES = {
    WPS_STATE_UNCONFIGURED: "Unconfigured",
    WPS_STATE_CONFIGURED: "Configured",
}

WPS_DEVICE_PASSWORD_IDS = {
    0x0000: "Default PIN",
    0x0001: "User-specified",
    0x0002: "Machine-specified",
    0x0003: "Rekey",
    0x0004: "PushButton",
    0x0005: "Registrar-specified",
}

#: Decoded bit by bit, never by matching composite values. The registry lists Physical Push
#: Button as 0x0280 and Virtual Display as 0x2008, but those are 0x0200|0x0080 and
#: 0x2000|0x0008 - a table keyed on composites both misses single bits and double-reports.
WPS_CONFIG_METHODS = {
    0x0001: "USBA",
    0x0002: "Ethernet",
    0x0004: "Label",
    0x0008: "Display",
    0x0010: "ExternalNFCToken",
    0x0020: "IntegratedNFCToken",
    0x0040: "NFCInterface",
    0x0080: "PushButton",
    0x0100: "Keypad",
    0x0200: "PhysicalPushButton",
    0x0400: "VirtualPushButton",
    0x2000: "VirtualDisplay",
    0x4000: "PhysicalDisplay",
}

#: The methods that imply a PIN the registrar will accept - the mask behind
#: ``WPSInfo.pin_attack_viable``. Push-button methods are deliberately absent: PBC requires
#: physical presence and is not remotely brute-forceable.
WPS_PIN_METHODS = 0x0004 | 0x0008 | 0x0100 | 0x2000 | 0x4000
