"""IT/OT classification.

Tags a Device with one of {class:ot, class:it, class:mixed} based on two independent signals:

1. Observed protocols (Service.name from Zeek's network.protocol or Nmap service detection).
   The OT_PROTOCOLS allowlist is keyed on names that match the lowercased protocol values
   Malcolm's logstash filters emit (verified against cisagov/Malcolm/logstash/pipelines/zeek/
   filenames: 1037_zeek_modbus, 1019_zeek_dnp3, 1022_zeek_enip, 1047_zeek_profinet,
   1051_zeek_s7comm, etc.).

2. OUI vendor (from netbox_bridge.oui). Devices whose MAC resolves to a known OT vendor count
   as OT even when no OT protocol has been observed yet.

Combination logic:
  has_ot AND has_it -> class:mixed
  has_ot only       -> class:ot
  has_it only       -> class:it
  neither           -> no class tag (don't guess)

Mutual exclusion: at most one class:* tag is set at a time. Switching is handled in upsert by
stripping existing class:* tags before recomputing.
"""
from __future__ import annotations

from .model import Host

# Protocol names verified against Malcolm's zeek logstash pipeline filenames.
# Names are lowercased; the comparison is case-insensitive.
OT_PROTOCOLS: set[str] = {
    "modbus", "modbus-tcp", "modbus_tcp",
    "dnp3",
    "enip",                          # EtherNet/IP
    "cip",                           # Common Industrial Protocol (over EIP)
    "profinet",
    "s7comm", "s7-comm",             # Siemens S7
    "bacnet",
    "opcua", "opcua-binary", "opcua_binary",
    "hart-ip", "hart_ip",
    "ecat", "ethercat",
    "c1222",
    "bsap", "bsap-ip", "bsap_ip",
    "cotp",                          # COTP often used as ISO-TSAP for S7
    "omron-fins", "omron_fins",
    "ge-srtp", "ge_srtp",
    "genisys",
    "roc-plus", "roc_plus",
    "synchrophasor",
    "iec104", "iec-104",
    "iec61850-mms", "iec61850-goose", "iec61850-sv",
}

OT_VENDORS: set[str] = {
    "Siemens AG",
    "Rockwell Automation",
    "Schneider Electric",
    "ABB",
    "Honeywell",
    # Future: GE, Emerson, Yokogawa, Mitsubishi, Omron, Beckhoff, Pilz, Phoenix Contact,
    # Hirschmann, Moxa, Westermo. Add as their OUIs land in oui.OUI_VENDORS.
}

IT_PROTOCOLS: set[str] = {
    "http", "https",
    "ssh", "telnet",
    "ftp", "ftps", "sftp", "tftp",
    "smtp", "smtps", "submission",
    "imap", "imaps", "pop3", "pop3s",
    "ldap", "ldaps",
    "kerberos",
    "smb", "smb2", "smb3", "netbios-ssn",
    "rdp", "vnc",
    "mysql", "postgresql", "mssql", "oracle", "mongodb",
    "redis", "memcached", "elasticsearch",
    "dns",
    "ssl", "tls",                    # generic encrypted (often web)
    "snmp",
    "ntp",
    "syslog",
    "krb5",
    "ntlm",
    "ssdp",                          # SOHO/IT discovery
}

CLASS_OT = "class:ot"
CLASS_IT = "class:it"
CLASS_MIXED = "class:mixed"
ALL_CLASS_TAGS: set[str] = {CLASS_OT, CLASS_IT, CLASS_MIXED}


def classify_tags(host: Host, vendor: str | None) -> set[str]:
    """Return the set of class:* tags to apply.

    Returns at most one of {class:ot, class:it, class:mixed}. Returns the empty set when there
    is no signal in either direction (don't guess).
    """
    has_ot = False
    has_it = False

    for svc in host.services:
        name = (svc.name or "").lower()
        if not name:
            continue
        if name in OT_PROTOCOLS:
            has_ot = True
        if name in IT_PROTOCOLS:
            has_it = True

    if vendor and vendor in OT_VENDORS:
        has_ot = True

    if has_ot and has_it:
        return {CLASS_MIXED}
    if has_ot:
        return {CLASS_OT}
    if has_it:
        return {CLASS_IT}
    return set()
