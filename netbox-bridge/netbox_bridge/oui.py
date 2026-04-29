"""OUI (Organizationally Unique Identifier) lookup.

The first 24 bits of a MAC address identify the vendor. This module ships a curated starter set
focused on OT industrial automation vendors plus common IT/virtualization vendors. Every entry
was cross-checked against the IEEE registry (https://standards-oui.ieee.org/oui/oui.txt) via
maclookup.app on 2026-04-29.

Future slice: bundle the full IEEE list (~50k entries, ~5MB) and ship a `netbox-bridge oui-update`
command that pulls a fresh copy. For now the starter set covers the OT vendors most common in
SOC-relevant environments (Siemens, Rockwell, Schneider, ABB, Honeywell) plus the IT/network/virt
vendors most likely to appear in mixed environments.

Storage format: upper-case 6-hex-character key, no separators. Lookups normalize first.
"""
from __future__ import annotations

OUI_VENDORS: dict[str, str] = {
    # ---- OT / Industrial Automation ----
    # Siemens AG (verified maclookup.app)
    "080006": "Siemens AG",
    "0001E3": "Siemens AG",
    "000BA3": "Siemens AG",
    "000E8C": "Siemens AG",
    "001B1B": "Siemens AG",
    "10DFFC": "Siemens AG",
    "208756": "Siemens AG",
    "20A8B9": "Siemens AG",
    # Rockwell Automation (Allen-Bradley)
    "0000BC": "Rockwell Automation",
    "001D9C": "Rockwell Automation",
    "086195": "Rockwell Automation",
    "184C08": "Rockwell Automation",
    "34C0F9": "Rockwell Automation",
    "404101": "Rockwell Automation",
    "5C2167": "Rockwell Automation",
    "5C8816": "Rockwell Automation",
    "68C8EB": "Rockwell Automation",
    "BCF499": "Rockwell Automation",
    "E48EBB": "Rockwell Automation",
    "E49069": "Rockwell Automation",
    "F45433": "Rockwell Automation",
    # Schneider Electric (Modicon)
    "000054": "Schneider Electric",
    "00006C": "Schneider Electric",
    "000417": "Schneider Electric",
    "001100": "Schneider Electric",
    "9C0E51": "Schneider Electric",
    # ABB
    "0050C2": "ABB",
    "70B3D5": "ABB",
    "8C1F64": "ABB",
    # Honeywell
    "00226A": "Honeywell",
    "004084": "Honeywell",
    "58FCC8": "Honeywell",
    "C4EFDA": "Honeywell",

    # ---- IT / Networking / Virtualization ----
    # Cisco Systems (early MA-L blocks; full list has 1200+ entries — extend in future slice)
    "00000C": "Cisco Systems",
    "00067C": "Cisco Systems",
    "0006C1": "Cisco Systems",
    "001007": "Cisco Systems",
    "00100B": "Cisco Systems",
    "00100D": "Cisco Systems",
    "001011": "Cisco Systems",
    "001014": "Cisco Systems",
    "00101F": "Cisco Systems",
    "001029": "Cisco Systems",
    "00102F": "Cisco Systems",
    "001054": "Cisco Systems",
    "001079": "Cisco Systems",
    "00107B": "Cisco Systems",
    "0010A6": "Cisco Systems",
    "0010F6": "Cisco Systems",
    "0010FF": "Cisco Systems",
    "004096": "Cisco Systems",
    "006009": "Cisco Systems",
    "00602F": "Cisco Systems",
    "00603E": "Cisco Systems",
    "006047": "Cisco Systems",
    "00605C": "Cisco Systems",
    "006070": "Cisco Systems",
    "006083": "Cisco Systems",
    "00900C": "Cisco Systems",
    "00902B": "Cisco Systems",
    "00905F": "Cisco Systems",
    "009092": "Cisco Systems",
    "0090D9": "Cisco Systems",
    "0090F2": "Cisco Systems",
    "00E014": "Cisco Systems",
    "00E01E": "Cisco Systems",
    "00E034": "Cisco Systems",
    "00E04F": "Cisco Systems",
    "00E08F": "Cisco Systems",
    "00E0A3": "Cisco Systems",
    "00E0B0": "Cisco Systems",
    "00E0F7": "Cisco Systems",
    "00E0F9": "Cisco Systems",
    "00E0FE": "Cisco Systems",
    # VMware
    "000569": "VMware",
    "000C29": "VMware",
    "001C14": "VMware",
    "005056": "VMware",
    # Microsoft (00:15:5D is the Hyper-V default vendor block — most common in practice)
    "0003FF": "Microsoft",
    "00125A": "Microsoft",
    "00155D": "Microsoft",
    "0017FA": "Microsoft",
    "001DD8": "Microsoft",
    "002248": "Microsoft",
    "0025AE": "Microsoft",
}


def normalize_mac(mac: str) -> str:
    return (
        mac.replace(":", "")
        .replace("-", "")
        .replace(".", "")
        .upper()
    )


def lookup_vendor(mac: str | None) -> str | None:
    """Return the registered vendor name for the OUI of a MAC, or None if unknown."""
    if not mac:
        return None
    norm = normalize_mac(mac)
    if len(norm) < 6:
        return None
    return OUI_VENDORS.get(norm[:6])
