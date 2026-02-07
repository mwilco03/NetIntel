# NetIntel - Network Intelligence Report Generator

A self-contained XSL stylesheet that transforms Nmap XML output into an interactive, air-gapped HTML intelligence platform for SOC analysts and network managers.

## [>>> Live Demo <<<](https://mwilco03.github.io/NetIntel/examples/report.html#/dashboard)

*Click above to see NetIntel in action - no install required*

## Test Drive (30 seconds)

Try it instantly with the included sample scan:

**Windows (PowerShell)**
```powershell
choco install xsltproc -y
git clone https://github.com/mwilco03/NetIntel.git
cd NetIntel
xsltproc nmap-intel.xsl Test.xml > report.html
start report.html
```

**Linux (Debian/Ubuntu)**
```bash
sudo apt install xsltproc git -y
git clone https://github.com/mwilco03/NetIntel.git
cd NetIntel
xsltproc nmap-intel.xsl Test.xml > report.html
xdg-open report.html
```

**Linux (RHEL/Fedora)**
```bash
sudo dnf install xsltproc git -y
git clone https://github.com/mwilco03/NetIntel.git
cd NetIntel
xsltproc nmap-intel.xsl Test.xml > report.html
xdg-open report.html
```

**macOS**
```bash
brew install libxslt
git clone https://github.com/mwilco03/NetIntel.git
cd NetIntel
xsltproc nmap-intel.xsl Test.xml > report.html
open report.html
```

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

Risk is calculated using **logarithmic diminishing returns** - the highest-risk port contributes full weight, additional ports contribute progressively less. This ensures one critical exposure scores higher than many minor ones.

**Formula:** `risk = highest_weight + Σ(weight[i] / log₂(i + 2))` for i > 0

### Port Weights

| Weight | Category | Ports |
|--------|----------|-------|
| **10** | Critical RCE | 23 (Telnet), 2375/4243 (Docker API), 6443 (K8s API), 10250 (Kubelet), 2379 (etcd), 623 (IPMI) |
| **9** | Legacy/NoAuth | 512-514 (r-services), 6379 (Redis) |
| **8** | Database/Admin | 445 (SMB), 1433 (MSSQL), 1521 (Oracle), 27017 (MongoDB), 2376 (Docker TLS), 5985/5986 (WinRM), 9200 (Elasticsearch), 1099 (Java RMI) |
| **7** | Common Targets | 21 (FTP), 139 (NetBIOS), 161 (SNMP), 3306 (MySQL), 3389 (RDP), 5900 (VNC), 10000 (Webmin) |
| **6** | Sensitive | 110 (POP3), 135 (MSRPC), 143 (IMAP), 389 (LDAP), 5432 (PostgreSQL) |
| **3** | Encrypted | 22 (SSH), 53 (DNS) |
| **1-2** | Web | 80 (HTTP), 443 (HTTPS) |

### Service-Name Detection

Risk scoring uses **both port number AND service name** from nmap `-sV` detection. This catches services on non-standard ports:

| Scenario | Detection |
|----------|-----------|
| HTTP on port 9999 | Detected via `service/@name="http"` → Cleartext flagged |
| SSH on port 2222 | Detected via `service/@name="ssh"` → Risk weight 3 |
| Redis on port 7777 | Detected via `service/@name="redis"` → Risk weight 9 |

**Cleartext bonus:** +3 for unencrypted protocols (FTP, Telnet, HTTP, POP3, IMAP, SNMP, LDAP, etc.)

**Score capped at 100.**

## File Structure

```
NetIntel/
├── nmap-intel.xsl           # Main stylesheet (single file, all features)
├── README.md                # This file
├── Test.xml                 # Sample nmap scan for testing
├── tools/
│   └── nvd-to-vulndb.py     # NVD API script for vuln database
└── examples/
    ├── README.md            # Examples documentation
    ├── report.html          # Live demo report (GitHub Pages)
    └── sample-vuln-db.json  # Sample CPE-to-CVE database for testing
```

## GitHub Pages Demo

The [live demo](https://mwilco03.github.io/NetIntel/examples/report.html) is hosted via GitHub Pages from the `examples/report.html` file.

**To deploy your own:**

1. Fork this repository
2. Go to Settings > Pages
3. Set Source to "Deploy from a branch"
4. Select `main` branch and `/ (root)` folder
5. Your demo will be at `https://YOUR_USERNAME.github.io/NetIntel/examples/report.html`

**To update the demo report:**

```bash
xsltproc nmap-intel.xsl your-scan.xml > examples/report.html
git add examples/report.html
git commit -m "Update demo report"
git push
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
