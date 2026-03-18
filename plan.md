# Nessus (.nessus) File Import — Implementation Notes

> **Status: IMPLEMENTED** — This plan was executed and merged. Kept here as a reference for the data model and design decisions.

## Overview

Nessus/ACAS `.nessus` file import is supported alongside Nmap XML import. The .nessus format (XML-based, `NessusClientData_v2` root element) contains rich vulnerability scan data including per-host findings with CVEs, CVSS scores, severity levels, CPEs, exploit availability, and remediation guidance. Data is parsed in the browser, mapped into the host data model, and displayed throughout the SPA.

## Data Mapping: Nessus → NetIntel Host Model

### From `<ReportHost>` + `<HostProperties>`:
| Nessus Field | NetIntel Field | Notes |
|---|---|---|
| `host-ip` HostProp | `host.ip` | Primary key for merge |
| `hostname` HostProp | `host.hostname` | |
| `operating-system` HostProp | `host.os[].name` | |
| `operating-system-conf` HostProp | `host.os[].accuracy` | |
| `netbios-name` HostProp | `host.netbiosName` | **New field** |
| `system-type` HostProp | used for OS enrichment | |
| `cpe-*` HostProp | `host.cpes[]` | **New field** — host-level CPEs |
| `traceroute-hop-*` HostProp | `host.trace[]` | Map to existing trace format |
| `Credentialed_Scan` HostProp | `host.credentialedScan` | **New field** — metadata |

### From `<ReportItem>` (per-host findings):
| Nessus Field | NetIntel Field | Notes |
|---|---|---|
| `port`, `protocol`, `svc_name` | `host.ports[]` port/proto/svc | Merged with existing ports |
| `pluginID`, `pluginName`, `severity` | `host.nessusFindings[]` | **New field** — array of findings |
| `cve` (multiple per item) | `host.nessusFindings[].cves[]` | Direct CVE associations |
| `cvss3_base_score` | `host.nessusFindings[].cvss3` | |
| `cvss_base_score` | `host.nessusFindings[].cvss` | |
| `risk_factor` | `host.nessusFindings[].riskFactor` | None/Low/Medium/High/Critical |
| `description` | `host.nessusFindings[].description` | |
| `solution` | `host.nessusFindings[].solution` | |
| `synopsis` | `host.nessusFindings[].synopsis` | |
| `plugin_output` | `host.nessusFindings[].output` | |
| `exploit_available` | `host.nessusFindings[].exploitAvailable` | |
| `see_also` | `host.nessusFindings[].references` | |
| `stig_severity` | `host.nessusFindings[].stigSeverity` | |
| `vpr_score` | `host.nessusFindings[].vpr` | Tenable VPR score |
| `cpe` | `host.nessusFindings[].cpe` | Per-finding CPE |
| `xref` | `host.nessusFindings[].xrefs[]` | IAVA/IAVB/MSFT etc |

## Implementation Steps

### Step 1: Add `parseNessusXml()` Function (~80 lines)
**Location:** `nmap-intel.xsl`, after `parseNmapXml()` (~line 3461)

- Parse `<NessusClientData_v2>` XML structure
- Extract `<Report>` → `<ReportHost>` elements
- For each host:
  - Read `<HostProperties>` tags into a property map
  - Map to NetIntel host object (ip, hostname, os, status='up')
  - Extract traceroute hops from `traceroute-hop-*` properties
  - Extract host-level CPEs from `cpe-*` properties
  - Parse `<ReportItem>` elements:
    - Items with `port > 0`: create port entries (deduped by port+proto)
    - Items with `severity > 0`: create nessusFindings entries
    - Collect CVEs, CVSS scores, risk factors, descriptions, solutions
    - Track exploit availability
  - Skip informational-only items (`severity=0`) for findings (but still use them for port/service detection)

### Step 2: Update `importFile()` to Auto-Detect Format (~10 lines)
**Location:** `nmap-intel.xsl`, `importFile()` function (~line 3360)

- After XML parsing, check for root element:
  - `<nmaprun>` → existing Nmap path
  - `<NessusClientData_v2>` → new Nessus path via `parseNessusXml()`
- Remove the "Not a valid Nmap XML file" error for .nessus files
- Increase `MAX_IMPORT_SIZE` from 10MB to 50MB (Nessus files are larger — the sample is 33MB)

### Step 3: Update `mergeHosts()` to Handle Nessus Data (~15 lines)
**Location:** `nmap-intel.xsl`, `mergeHosts()` function (~line 3464)

- When merging an existing host:
  - Merge `nessusFindings` arrays (dedupe by pluginID)
  - Merge `cpes` arrays (dedupe)
  - Set `netbiosName` if not already present
  - Set `credentialedScan` flag

### Step 4: Enhance Risk Scoring with Nessus Data (~15 lines)
**Location:** `nmap-intel.xsl`, `calculateRisk()` function (~line 2742)

- If `host.nessusFindings` exists, incorporate vulnerability severity:
  - Use CVSS3 scores from findings to boost risk
  - Critical findings (severity=4, CVSS≥9) add significant risk
  - High findings (severity=3, CVSS≥7) add moderate risk
  - Exploit-available findings get extra weight
- Blend with existing port-based risk (max of port-risk and vuln-risk approaches)

### Step 5: Update Entity Cards to Show Nessus Findings (~20 lines)
**Location:** `nmap-intel.xsl`, `createEntityCard()` function

- Add vulnerability severity counts badge (Critical/High/Medium/Low)
- Show top finding name if critical/high
- Show "ACAS Scanned" indicator badge
- Color-code based on highest severity finding

### Step 6: Add Nessus Findings to Entity Detail View (~40 lines)
**Location:** `nmap-intel.xsl`, `selectHost()` / detail panel rendering

- Add a "Vulnerabilities" tab/section in entity detail showing:
  - Findings sorted by severity (Critical → Info)
  - Each finding shows: plugin name, severity badge, CVSS score, CVEs, synopsis
  - Expandable detail with: description, solution, plugin output, references
  - Exploit available indicator
  - STIG severity indicator

### Step 7: Update Dashboard Stats for Nessus Data (~25 lines)
**Location:** `nmap-intel.xsl`, `renderStats()` function (~line 3129)

- Add vulnerability summary cards:
  - Total findings by severity (Critical/High/Medium/Low)
  - Hosts with critical vulnerabilities count
  - Top 5 most common vulnerabilities across all hosts
  - Exploit-available findings count
- Only show these cards when Nessus data is present

### Step 8: Update Search Index for Nessus Data (~15 lines)
**Location:** `nmap-intel.xsl`, `buildSearchIndex()` function (~line 1640)

- Index CVEs from nessusFindings (enabling `cve:CVE-2024-*` searches)
- Index plugin names (enabling `vuln:wireshark` searches)
- Index risk factors (enabling `risk_factor:critical` searches)

### Step 9: Add Vulnerabilities View (~60 lines)
**Location:** `nmap-intel.xsl`, new section + nav entry

- Add "Vulns" nav item (only visible when Nessus data loaded)
- New `#/vulns` route and `renderVulns()` function
- Aggregated vulnerability view across all hosts:
  - Group by plugin (same vulnerability across multiple hosts)
  - Show affected host count per vulnerability
  - Severity filter (Critical/High/Medium/Low)
  - Sortable by severity, host count, exploit availability
  - Click to see affected hosts list

### Step 10: Update Sources Page (~5 lines)
**Location:** `nmap-intel.xsl`, `renderSources()` function

- Show Nessus scan metadata (scan name, policy, host count, finding counts)
- Distinguish between Nmap and Nessus import sources

## File Changes Summary

| File | Change Type | Description |
|---|---|---|
| `nmap-intel.xsl` | Modified | All JavaScript changes (parser, UI, routing, indexing) |

Only one file needs modification — the entire SPA lives in `nmap-intel.xsl`.

## Key Design Decisions

1. **No separate vuln DB needed** — Nessus findings contain CVEs, CVSS, descriptions, and solutions directly. When .nessus data is imported, it enriches hosts with vulnerability data without needing the separate NVD vuln DB JSON import.

2. **Additive merge** — Nessus data supplements Nmap data. If both are imported for the same IP, they merge: Nmap contributes port fingerprinting/NSE scripts, Nessus contributes vulnerability findings. Neither overwrites the other.

3. **Severity filtering uses Nessus severity levels** (0=Info, 1=Low, 2=Medium, 3=High, 4=Critical) mapped to risk_factor strings.

4. **File size limit increase** — Nessus files can be 30MB+. Increase limit to 50MB. The browser's DOMParser handles this fine.

5. **Lazy detail rendering** — Finding descriptions/solutions are only rendered when a host detail is opened, keeping the initial card grid fast.
