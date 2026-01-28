# Network Intelligence Report Generator (NetIntel)

## Project Overview

A self-contained XSL stylesheet that transforms Nmap XML output into an interactive, air-gapped HTML intelligence platform. Designed for deployment in restricted environments where no external dependencies or network connectivity is available.

## Core Requirements

### Deployment Constraints
- **Air-gapped environments**: Zero external dependencies (no CDN links)
- **Single file output**: All CSS, JS, and assets must be inline in the generated HTML
- **Browser target**: Chromium-based browsers
- **Scale**: Hundreds of hosts per scan
- **Classification markings**: Configurable banners (top/bottom) with color coding

### License
- MIT License - No use restrictions
- Must be usable by any organization without limitation

---

## Architecture

### Input
- Primary: Nmap XML output (`-oX scan.xml`)
- Future: Masscan JSON, Nessus exports (lower priority)

### Output
- Self-contained HTML file
- All state persisted in localStorage
- Exportable as new HTML with embedded data (the HTML becomes the database)

### Data Model

```
ENTITY (Host)
├── IP Address (primary key)
├── MAC Address + Vendor (OUI)
├── Hostname(s)
├── Status (up/down)
├── OS Detection (multiple signals with confidence)
├── Ports[]
│   ├── Port number
│   ├── Protocol (tcp/udp)
│   ├── State (open/filtered/closed)
│   ├── Service name
│   ├── Product + Version
│   ├── CPE
│   └── Scripts output
├── Traceroute hops[]
├── Host scripts[]
├── Computed fields:
│   ├── Risk score (0-100)
│   ├── Risk level (critical/high/medium/low)
│   ├── OS type (windows/linux/network/unknown)
│   └── Cleartext services[]
└── User annotations:
    ├── Tags (crown-jewel, choke-point, key-terrain)
    └── Notes

SOURCE
├── Source ID
├── Tool name + version
├── Scan timestamp
├── Arguments used
└── Hosts contributed

RELATIONSHIP (inferred)
├── Source IP
├── Destination IP
├── Type (route/hop)
├── Evidence (traceroute)
└── Hop count
```

---

## Features Specification

### Phase 1: Foundation (MVP)

#### 1.1 Classification Banners
- Fixed position top and bottom
- Configurable via XSL parameters:
  - `$classification` (text, default: "UNCLASSIFIED")
  - `$classification-color` (hex color, default: "#007a33" green)
- Common classifications:
  - UNCLASSIFIED: #007a33 (green)
  - CUI: #502b85 (purple)
  - CONFIDENTIAL: #0033a0 (blue)
  - SECRET: #c8102e (red)
  - TOP SECRET: #ff8c00 (orange)

#### 1.2 Executive Dashboard
- Stats cards:
  - Hosts online (count / total)
  - Open ports (total across all hosts)
  - Cleartext services (count, links to detail)
  - Overall risk score (0-100 average)
- Cleartext warning panel (if any detected)
- Top 5 risks list with scores
- OS distribution breakdown
- Key terrain summary

#### 1.3 Entity Cards View
- Card per host showing:
  - IP address (monospace)
  - Hostname (if available)
  - OS icon (Windows/Linux/Network/Unknown)
  - Tags (user-assigned)
  - Stats: Open ports, Filtered ports, Risk score
  - Port badges (color-coded: open=green, cleartext=red)
  - Fingerprint signals section:
    - OS probe result + confidence %
    - MAC OUI + vendor
    - Top 3 service banners
- Right-click context menu for tagging

#### 1.4 Risk Scoring Engine

```javascript
const RISKY_PORTS = {
  21:  { weight: 7, reason: 'FTP exposed' },
  22:  { weight: 3, reason: 'SSH exposed' },
  23:  { weight: 10, reason: 'Telnet - critical' },
  25:  { weight: 4, reason: 'SMTP exposed' },
  53:  { weight: 3, reason: 'DNS exposed' },
  80:  { weight: 2, reason: 'HTTP exposed' },
  110: { weight: 6, reason: 'POP3 exposed' },
  111: { weight: 5, reason: 'RPC exposed' },
  135: { weight: 6, reason: 'MSRPC exposed' },
  139: { weight: 7, reason: 'NetBIOS/SMB exposed' },
  143: { weight: 6, reason: 'IMAP exposed' },
  161: { weight: 7, reason: 'SNMP exposed' },
  389: { weight: 6, reason: 'LDAP exposed' },
  443: { weight: 1, reason: 'HTTPS exposed' },
  445: { weight: 8, reason: 'SMB - high value target' },
  1433: { weight: 8, reason: 'MSSQL exposed' },
  1521: { weight: 8, reason: 'Oracle exposed' },
  3306: { weight: 7, reason: 'MySQL exposed' },
  3389: { weight: 7, reason: 'RDP exposed' },
  5432: { weight: 6, reason: 'PostgreSQL exposed' },
  5900: { weight: 7, reason: 'VNC exposed' },
  6379: { weight: 7, reason: 'Redis exposed' },
  27017: { weight: 8, reason: 'MongoDB exposed' }
};

// Score = sum of weights, capped at 100
// Level: critical >= 70, high >= 50, medium >= 25, low < 25
```

#### 1.5 Cleartext Protocol Detection

```javascript
const CLEARTEXT_PORTS = {
  21:  { name: 'FTP', risk: 'high' },
  23:  { name: 'Telnet', risk: 'critical' },
  25:  { name: 'SMTP', risk: 'medium' },
  80:  { name: 'HTTP', risk: 'medium' },
  110: { name: 'POP3', risk: 'high' },
  143: { name: 'IMAP', risk: 'high' },
  161: { name: 'SNMP', risk: 'high' },
  389: { name: 'LDAP', risk: 'high' },
  513: { name: 'rlogin', risk: 'critical' },
  514: { name: 'RSH', risk: 'critical' },
  1433: { name: 'MSSQL', risk: 'high' },
  3306: { name: 'MySQL', risk: 'high' },
  5432: { name: 'PostgreSQL', risk: 'medium' },
  8080: { name: 'HTTP-Alt', risk: 'medium' }
};
```

#### 1.6 Key Terrain Tagging
- Right-click context menu on any entity
- Tag options:
  - Crown Jewel (gold border/badge)
  - Choke Point (red border/badge)
  - Key Terrain (purple border/badge)
  - Clear Tags
- Persisted in localStorage
- Visual indicators on cards
- Summary in dashboard

#### 1.7 Source Tracking
- Display primary scan metadata:
  - Tool + version
  - Scan arguments
  - Start/end time
  - Hosts found
- Track additional imported sources
- Every finding should trace to source

#### 1.8 Data Export
- CSV: IP, Hostname, OS, Ports, Risk, Tags
- JSON: Full data model with computed fields
- HTML: Re-export current page with all data embedded
- CPE List: Extract all CPEs for vulnerability lookup

---

### Phase 2: Intelligence Features

#### 2.1 Fingerprint Confidence Scoring
- Aggregate multiple signals:
  - OS probe accuracy (from nmap)
  - Service detection confidence
  - MAC OUI match
  - Banner consistency
- Flag conflicts (e.g., banner says Apache, probe says IIS)
- Calculate composite confidence score

#### 2.2 Entity Grouping
- Group by:
  - OS type (Windows, Linux, Network, Unknown)
  - Subnet (/24 boundaries)
  - Primary service (web servers, databases, etc.)
- Collapsible group headers
- Count per group

#### 2.3 Relationships View
- Parse traceroute data from nmap XML
- Display hop paths visually
- Infer network topology
- Show routing relationships

#### 2.4 Search and Filtering
- Global search box
- Filter entities by:
  - All hosts
  - Online only
  - Has cleartext
  - High risk (score >= 50)
  - Key terrain tagged
- Real-time filtering

---

### Phase 3: Multi-Source Fusion

#### 3.1 Import Additional Scans
- Drag-and-drop or file picker
- Parse nmap XML
- Merge logic:
  - New hosts: add to collection
  - Existing hosts: merge ports, update OS if higher confidence
- Track source per finding

#### 3.2 Scan Comparison (Diff)
- Load baseline and comparison scans
- Highlight:
  - New hosts (green)
  - Removed hosts (red)
  - New ports (green)
  - Closed ports (red)
  - Changed services (yellow)
- Timeline view if multiple scans

#### 3.3 Combined Export
- Export fused data as new HTML
- Includes all sources
- Preserves tags and annotations
- Portable artifact

---

### Phase 4: Vulnerability Enrichment

#### 4.1 CPE Collection
- Extract all CPEs from scan data
- Export as JSON for external lookup
- Format: `cpe:/a:vendor:product:version`

#### 4.2 Vulnerability Database Import
- Load JSON mapping file (CPE -> CVE[])
- Generated externally from NVD feeds
- Structure:
```json
{
  "cpe:/a:apache:http_server:2.4.49": [
    { "cve": "CVE-2021-41773", "cvss": 7.5, "desc": "Path traversal" }
  ]
}
```
- Match against scan CPEs
- Display CVEs per host/service

#### 4.3 Vulnerability Dashboard
- Total CVEs found
- Critical/High/Medium/Low breakdown
- Most vulnerable hosts
- Most common CVEs

---

## UI/UX Specification

### Color Palette (Dark Theme)
```css
--bg-primary: #0a0e17;
--bg-secondary: #0d1117;
--bg-tertiary: #161b22;
--border: #21262d;
--border-hover: #30363d;
--text-primary: #e6edf3;
--text-secondary: #c9d1d9;
--text-muted: #8b949e;
--text-faint: #484f58;
--accent-blue: #58a6ff;
--accent-green: #238636;
--accent-green-light: #3fb950;
--accent-yellow: #d29922;
--accent-red: #f85149;
--accent-purple: #a371f7;
```

### Typography
- Primary: 'Segoe UI', -apple-system, sans-serif
- Monospace: 'Consolas', 'Monaco', monospace
- Base size: 14px

### Layout
- Fixed sidebar (220-240px)
- Sticky header with search
- Classification banners (24px each, fixed top/bottom)
- Content area with padding
- Responsive grid for entity cards

### Icons
- Use Unicode symbols or inline SVG
- No external icon fonts
- Keep simple and readable

---

## Technical Implementation

### XSL Structure
```xml
<xsl:stylesheet>
  <!-- Parameters -->
  <xsl:param name="classification"/>
  <xsl:param name="classification-color"/>
  
  <!-- Main template -->
  <xsl:template match="/">
    <html>
      <head>
        <style>/* All CSS inline */</style>
      </head>
      <body>
        <!-- Classification banner top -->
        <!-- App container -->
          <!-- Sidebar -->
          <!-- Main content -->
            <!-- Header -->
            <!-- Sections (dashboard, entities, etc.) -->
        <!-- Classification banner bottom -->
        <!-- Modals -->
        <!-- Embedded JSON data -->
        <script id="scan-data" type="application/json">
          <!-- Transformed scan data -->
        </script>
        <script>/* All JS inline */</script>
      </body>
    </html>
  </xsl:template>
  
  <!-- Component templates -->
  <xsl:template name="sidebar"/>
  <xsl:template name="dashboard"/>
  <xsl:template name="entity-card"/>
  <!-- etc. -->
</xsl:stylesheet>
```

### Embedded Data Format
```javascript
{
  "scanInfo": {
    "scanner": "nmap",
    "version": "7.94",
    "args": "-sV -O ...",
    "start": "1699123456",
    "startstr": "Sun Nov 5 12:34:56 2023"
  },
  "stats": {
    "hostsTotal": 256,
    "hostsUp": 47,
    "hostsDown": 209
  },
  "hosts": [
    {
      "ip": "192.168.1.1",
      "mac": "AA:BB:CC:DD:EE:FF",
      "macVendor": "Cisco",
      "hostname": "router.local",
      "status": "up",
      "os": [
        { "name": "Cisco IOS 15.x", "accuracy": 95 }
      ],
      "ports": [
        {
          "port": 22,
          "protocol": "tcp",
          "state": "open",
          "service": "ssh",
          "product": "OpenSSH",
          "version": "8.2",
          "cpe": "cpe:/a:openbsd:openssh:8.2"
        }
      ],
      "trace": [
        { "ttl": 1, "ip": "192.168.1.1", "rtt": "0.5" }
      ],
      "scripts": []
    }
  ]
}
```

### JavaScript Architecture
```javascript
// State management
let state = {
  scanData: null,      // Parsed from embedded JSON
  tags: {},            // { "ip": ["crown-jewel", "key-terrain"] }
  vulnDb: null,        // Loaded vulnerability database
  additionalSources: [], // Imported scans
  currentView: 'dashboard',
  searchQuery: ''
};

// Persistence
const STORAGE_KEY = 'netintel_data';
function loadState() { /* from localStorage */ }
function saveState() { /* to localStorage */ }

// Data processing
function calculateHostRisk(host) { /* returns {score, level, reasons} */ }
function getCleartextServices() { /* returns [{ip, port, service, risk}] */ }
function detectOS(host) { /* returns {type, name, accuracy} */ }
function groupHostsBy(criterion) { /* returns {groupKey: [hosts]} */ }

// Rendering
function renderDashboard() {}
function renderEntityCards() {}
function renderGroups() {}
function renderCleartextAnalysis() {}

// Navigation
function navigateTo(section) {}
function handleAction(action, data) {}

// Import/Export
function handleFileImport(file) {}
function parseNmapXml(doc) {}
function mergeHosts(newHosts, sourceName) {}
function exportCsv() {}
function exportJson() {}

// Context menu
function initContextMenu() {}

// Initialize
document.addEventListener('DOMContentLoaded', init);
```

---

## Testing

### Sample Nmap Commands for Test Data
```bash
# Basic service scan
nmap -sV -oX scan.xml 192.168.1.0/24

# OS detection + traceroute
nmap -sV -O --traceroute -oX scan.xml 192.168.1.0/24

# Full scan with scripts
nmap -sV -sC -O -oX scan.xml 192.168.1.0/24

# Quick scan of common ports
nmap -F -sV -oX scan.xml 192.168.1.0/24
```

### Test Cases
1. Empty scan (no hosts up)
2. Single host with few ports
3. Hundreds of hosts
4. Host with cleartext services
5. Host with high risk score
6. Multiple OS detections with varying confidence
7. Traceroute data present
8. Script output present
9. Import second scan and merge
10. Export and re-import combined data

---

## File Structure (Repository)

```
nmap-netintel/
├── README.md
├── LICENSE (MIT)
├── nmap-intel.xsl          # Main stylesheet
├── examples/
│   ├── sample-scan.xml     # Example nmap output
│   └── sample-report.html  # Generated example
├── tools/
│   └── nvd-to-vulndb.py    # Script to generate vuln database
├── docs/
│   ├── USAGE.md
│   ├── CLASSIFICATION.md
│   └── CONTRIBUTING.md
└── tests/
    ├── test-scans/
    └── validate.sh
```

---

## Usage

### Generate Report
```bash
# Basic usage
xsltproc nmap-intel.xsl scan.xml > report.html

# With classification
xsltproc --stringparam classification "SECRET" \
         --stringparam classification-color "#c8102e" \
         nmap-intel.xsl scan.xml > report.html

# Inline with nmap
nmap -sV -O -oX - 192.168.1.0/24 | xsltproc nmap-intel.xsl - > report.html
```

### Open Report
```bash
# Just open in browser
chromium report.html

# Or any browser
firefox report.html
```

---

## Development Notes

### Constraints to Remember
- No external resources (CDN, fonts, icons)
- Must work offline
- All in one file
- localStorage for persistence
- Target: Chromium browsers
- Keep file size reasonable (< 500KB for stylesheet)

### Common Pitfalls
- XSL escaping: Use `&amp;` for `&`, `&lt;` for `<` in JavaScript
- CDATA sections for inline JS: `<![CDATA[ ... ]]>`
- JSON in XSL: Escape quotes properly
- Large scans: Consider pagination or virtual scrolling

---

## Current Status

### Completed
- [x] Project specification
- [x] Color palette and UI design
- [x] Risk scoring algorithm
- [x] Cleartext detection logic
- [x] Basic CSS styles
- [x] Data model definition

### In Progress
- [ ] Complete XSL template structure
- [ ] Entity card template
- [ ] Dashboard rendering
- [ ] JavaScript core logic

### TODO
- [ ] Import/export functionality
- [ ] Context menu for tagging
- [ ] Source tracking
- [ ] Diff/comparison view
- [ ] Vulnerability database integration
- [ ] Testing with real scan data

---

## Contributing

1. Fork the repository
2. Create feature branch
3. Test with real nmap output
4. Ensure air-gap compatibility (no external deps)
5. Submit PR with description

## License

MIT License - Use freely without restriction.
