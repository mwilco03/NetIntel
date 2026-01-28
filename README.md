# NetIntel - Network Intelligence Report Generator

A self-contained XSL stylesheet that transforms Nmap XML output into an interactive, air-gapped HTML intelligence platform for SOC analysts and network managers.

## Quick Start

```bash
# Basic usage - generate report from nmap scan
xsltproc nmap-intel.xsl scan.xml > report.html

# With classification banner
xsltproc --stringparam classification "SECRET" \
         --stringparam classification-color "#c8102e" \
         nmap-intel.xsl scan.xml > report.html

# Inline with nmap (scan and generate in one command)
nmap -sV -O --traceroute -oX - 192.168.1.0/24 | xsltproc nmap-intel.xsl - > report.html

# Full scan with scripts and OS detection
nmap -sV -sC -O --traceroute -oX scan.xml 192.168.1.0/24
xsltproc nmap-intel.xsl scan.xml > report.html
```

Then open `report.html` in any modern browser (Chromium recommended).

## Features

### Core Features (Implemented)
- **Classification Banners** - Configurable top/bottom banners (UNCLASSIFIED, CUI, SECRET, etc.)
- **Executive Dashboard** - Stats cards, risk scores, cleartext warnings, OS distribution
- **Entity Cards** - Host details with ports, services, OS fingerprints, CVE counts
- **Risk Scoring** - Automated risk assessment based on open ports (0-100 scale)
- **Cleartext Detection** - Identifies insecure protocols (FTP, Telnet, HTTP, etc.)
- **Key Terrain Tagging** - Right-click to tag hosts as Crown Jewel, Choke Point, Key Terrain

### Analysis Features (Implemented)
- **Entity Grouping** - Group by OS, subnet (configurable CIDR), service type, or risk level
- **Topology View** - Interactive traceroute visualization (hierarchical or radial layout)
- **Timeline View** - Track changes across multiple scans over time
- **Scan Diff** - Compare two scans to see new/removed/changed hosts
- **Fingerprint Parsing** - Decode and display nmap OS/service fingerprints

### Data Features (Implemented)
- **Multi-scan Import** - Merge additional nmap XML files
- **Source Tracking** - Track which scan contributed each finding
- **CVE Matching** - Load vulnerability database to show CVEs per host
- **Export Options** - CSV, JSON, HTML, CPE list

### Air-gapped Design
- Zero external dependencies (no CDN, inline all CSS/JS)
- Single HTML file output
- localStorage persistence
- Works completely offline

## Recommended Nmap Commands

```bash
# Quick service scan
nmap -sV -oX scan.xml 192.168.1.0/24

# Full scan with OS detection and traceroute (recommended)
nmap -sV -O --traceroute -oX scan.xml 192.168.1.0/24

# Comprehensive scan with scripts
nmap -sV -sC -O --traceroute -oX scan.xml 192.168.1.0/24

# Fast scan of common ports
nmap -F -sV -oX scan.xml 192.168.1.0/24

# UDP scan (requires root)
sudo nmap -sU -sV -oX udp-scan.xml 192.168.1.0/24
```

## Classification Options

| Classification | Color | Hex Code |
|---------------|-------|----------|
| UNCLASSIFIED | Green | #007a33 |
| CUI | Purple | #502b85 |
| CONFIDENTIAL | Blue | #0033a0 |
| SECRET | Red | #c8102e |
| TOP SECRET | Orange | #ff8c00 |

Example:
```bash
xsltproc --stringparam classification "TOP SECRET" \
         --stringparam classification-color "#ff8c00" \
         nmap-intel.xsl scan.xml > report.html
```

## Vulnerability Database

Generate a CPE-to-CVE mapping file from the NVD API:

```bash
# Install requirements
pip install requests

# Generate vuln database (may take a while)
python tools/nvd-to-vulndb.py --output vuln-db.json

# Generate for specific vendor/product
python tools/nvd-to-vulndb.py --cpe "cpe:2.3:a:apache:*" --output apache-vulns.json

# Generate for recent CVEs only
python tools/nvd-to-vulndb.py --days 90 --output recent-vulns.json
```

Then load `vuln-db.json` in the NetIntel UI via Tools > Vuln Database.

## User Interface

### Navigation
- **Dashboard** - Executive summary with stats and top risks
- **All Entities** - Host cards with filtering and grouping
- **Topology** - Network graph from traceroute data
- **Timeline** - Multi-scan comparison over time
- **Cleartext** - Insecure protocol analysis
- **Scan Diff** - Compare baseline vs comparison scan
- **Sources** - Scan metadata and imported sources

### Keyboard/Mouse
- **Search** - Filter hosts by IP, hostname, port, or service
- **Right-click** - Tag hosts as key terrain
- **Drag-drop** - Import XML files or vuln database

### Grouping Options
- **OS Type** - Windows, Linux, Network Devices, Unknown
- **Subnet** - Configurable CIDR (/8, /16, /20, /24, /28)
- **Service** - Web, Database, Mail, File, Remote, Directory
- **Risk Level** - Critical (70+), High (50-69), Medium (25-49), Low (0-24)

## Risk Scoring

Ports are weighted based on security impact:

| Weight | Ports |
|--------|-------|
| 10 | 23 (Telnet) |
| 9 | 512, 513, 514 (r-services) |
| 8 | 445 (SMB), 1433 (MSSQL), 1521 (Oracle), 27017 (MongoDB) |
| 7 | 21 (FTP), 139 (NetBIOS), 161 (SNMP), 3306 (MySQL), 3389 (RDP), 5900 (VNC), 6379 (Redis) |
| 6 | 110 (POP3), 135 (MSRPC), 143 (IMAP), 389 (LDAP), 5432 (PostgreSQL) |

Additional +3 for cleartext protocols. Score capped at 100.

## File Structure

```
NetIntel/
├── nmap-intel.xsl      # Main stylesheet (single file, all features)
├── README.md           # This file
├── tools/
│   └── nvd-to-vulndb.py  # NVD API script for vuln database
└── examples/           # Sample scans and reports (optional)
```

## Browser Support

- Chromium/Chrome (recommended)
- Firefox
- Safari
- Edge

Requires JavaScript and localStorage.

## License

MIT License - Use freely without restriction.

## Contributing

1. Fork the repository
2. Create feature branch
3. Test with real nmap output
4. Ensure air-gap compatibility (no external deps)
5. Submit PR with description
