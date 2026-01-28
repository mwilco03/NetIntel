<?xml version="1.0" encoding="utf-8"?>
<!--
Network Intelligence Report Generator v1.0
MIT License - No use restrictions
Air-gapped, self-contained HTML output

Usage:
  xsltproc nmap-intel.xsl scan.xml > report.html
  xsltproc - -stringparam classification "SECRET" - -stringparam classification-color "#c8102e" nmap-intel.xsl scan.xml > report.html
-->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="html" encoding="utf-8" indent="yes" doctype-system="about:legacy-compat"/>

<!-- Configurable Parameters -->
<xsl:param name="classification" select="'UNCLASSIFIED'"/>
<xsl:param name="classification-color" select="'#007a33'"/>

<!-- Main Template -->
<xsl:template match="/">
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<meta name="referrer" content="no-referrer"/>
<title>Network Intelligence Report - <xsl:value-of select="/nmaprun/@startstr"/></title>
<style>
<xsl:text disable-output-escaping="yes"><![CDATA[
/* === RESET & BASE === */
*,*::before,*::after{box-sizing:border-box}*{margin:0;padding:0}
html{font-size:14px}
body{font-family:'Segoe UI',-apple-system,BlinkMacSystemFont,sans-serif;background:#0a0e17;color:#c9d1d9;line-height:1.5;min-height:100vh}

/* === CLASSIFICATION BANNERS === */
.class-banner{position:fixed;left:0;right:0;height:24px;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:12px;letter-spacing:.5px;color:#fff;text-transform:uppercase;z-index:9999}
#class-top{top:0}
#class-bottom{bottom:0}

/* === LAYOUT === */
.app{display:flex;margin-top:24px;margin-bottom:24px;min-height:calc(100vh - 48px)}

/* Sidebar */
.sidebar{width:220px;background:#0d1117;border-right:1px solid #21262d;padding:1rem 0;position:fixed;top:24px;bottom:24px;left:0;overflow-y:auto;z-index:100}
.sidebar-logo{padding:0 1rem 1rem;border-bottom:1px solid #21262d;margin-bottom:1rem;font-size:1.2rem;font-weight:700;color:#58a6ff;display:flex;align-items:center;gap:.5rem}
.nav{list-style:none}
.nav a{display:flex;align-items:center;gap:.75rem;padding:.6rem 1rem;color:#8b949e;text-decoration:none;border-left:3px solid transparent;transition:all .15s}
.nav a:hover{background:#161b22;color:#c9d1d9}
.nav a.active{background:#161b22;color:#58a6ff;border-left-color:#58a6ff}
.nav-section{padding:.5rem 1rem;font-size:.7rem;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:#484f58;margin-top:1rem}

/* Main Content */
.main{flex:1;margin-left:220px;display:flex;flex-direction:column}
.header{background:#0d1117;border-bottom:1px solid #21262d;padding:.75rem 1.5rem;display:flex;align-items:center;justify-content:space-between;position:sticky;top:24px;z-index:50}
.header-left,.header-right{display:flex;align-items:center;gap:.75rem}
.search{display:flex;align-items:center;background:#161b22;border:1px solid #30363d;border-radius:6px;padding:.4rem .75rem;gap:.5rem}
.search input{background:transparent;border:none;color:#c9d1d9;outline:none;width:200px;font-size:.9rem}
.search input::placeholder{color:#484f58}
.content{padding:1.5rem;flex:1}

/* === BUTTONS === */
.btn{display:inline-flex;align-items:center;gap:.5rem;padding:.5rem 1rem;font-size:.875rem;font-weight:500;border-radius:6px;border:1px solid transparent;cursor:pointer;transition:all .15s;text-decoration:none}
.btn-primary{background:#238636;color:#fff;border-color:#238636}
.btn-primary:hover{background:#2ea043}
.btn-secondary{background:#21262d;color:#c9d1d9;border-color:#30363d}
.btn-secondary:hover{background:#30363d}
.btn-ghost{background:transparent;color:#8b949e;border:none;padding:.4rem .6rem}
.btn-ghost:hover{color:#c9d1d9;background:#21262d}
.btn-sm{padding:.3rem .6rem;font-size:.8rem}

/* === CARDS === */
.card{background:#0d1117;border:1px solid #21262d;border-radius:8px;overflow:hidden;margin-bottom:1rem}
.card-header{padding:1rem;border-bottom:1px solid #21262d;display:flex;align-items:center;justify-content:space-between}
.card-title{font-size:1rem;font-weight:600;color:#e6edf3}
.card-body{padding:1rem}

/* === SECTIONS === */
.section{display:none;margin-bottom:2rem}
.section.active{display:block}
.section-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem}
.section-title{font-size:1.25rem;font-weight:600;color:#e6edf3}

/* === STATS GRID === */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin-bottom:1.5rem}
.stat{background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:1.25rem;position:relative;overflow:hidden}
.stat::before{content:'';position:absolute;left:0;top:0;bottom:0;width:4px}
.stat.success::before{background:#238636}
.stat.warning::before{background:#d29922}
.stat.danger::before{background:#f85149}
.stat.info::before{background:#58a6ff}
.stat-label{font-size:.75rem;font-weight:500;text-transform:uppercase;letter-spacing:.05em;color:#8b949e;margin-bottom:.5rem}
.stat-value{font-size:2rem;font-weight:700;color:#e6edf3;line-height:1}
.stat-detail{font-size:.8rem;color:#8b949e;margin-top:.5rem}

/* === BADGES & TAGS === */
.badge{display:inline-flex;align-items:center;padding:.2rem .5rem;font-size:.75rem;font-weight:500;border-radius:4px;gap:.25rem}
.badge-critical{background:rgba(248,81,73,.2);color:#f85149}
.badge-high{background:rgba(210,153,34,.2);color:#d29922}
.badge-medium{background:rgba(88,166,255,.2);color:#58a6ff}
.badge-low{background:rgba(35,134,54,.2);color:#238636}
.badge-info{background:rgba(136,146,157,.2);color:#8b949e}
.badge-cleartext{background:rgba(248,81,73,.3);color:#ff7b72;border:1px solid #f85149}
.tag{display:inline-flex;align-items:center;padding:.15rem .4rem;font-size:.7rem;border-radius:3px;margin-right:.25rem}
.tag-crown{background:rgba(210,153,34,.2);color:#d29922;border:1px solid #d29922}
.tag-choke{background:rgba(248,81,73,.2);color:#f85149;border:1px solid #f85149}
.tag-key{background:rgba(163,113,247,.2);color:#a371f7;border:1px solid #a371f7}

/* === ENTITY CARDS === */
.entity-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:1rem}
.entity{background:#0d1117;border:1px solid #21262d;border-radius:8px;overflow:hidden;transition:border-color .15s}
.entity:hover{border-color:#30363d}
.entity.tagged{border-color:#a371f7}
.entity-head{padding:1rem;display:flex;align-items:flex-start;gap:1rem;border-bottom:1px solid #21262d}
.entity-icon{width:44px;height:44px;border-radius:8px;background:#21262d;display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:1.25rem}
.entity-icon.win{background:rgba(0,120,212,.2);color:#0078d4}
.entity-icon.lin{background:rgba(255,165,0,.2);color:#ffa500}
.entity-icon.net{background:rgba(88,166,255,.2);color:#58a6ff}
.entity-info{flex:1;min-width:0}
.entity-ip{font-family:'Consolas','Monaco',monospace;font-weight:600;color:#e6edf3}
.entity-host{font-size:.8rem;color:#8b949e}
.entity-tags{margin-top:.5rem}
.entity-body{padding:1rem}
.entity-stats{display:grid;grid-template-columns:repeat(3,1fr);gap:.5rem;margin-bottom:.75rem;text-align:center}
.entity-stat{background:#161b22;padding:.5rem;border-radius:4px}
.entity-stat b{display:block;font-size:1.1rem;color:#e6edf3}
.entity-stat span{font-size:.7rem;color:#8b949e;text-transform:uppercase}
.ports{display:flex;flex-wrap:wrap;gap:.3rem}
.port{font-family:monospace;font-size:.75rem;padding:.2rem .4rem;background:#21262d;border-radius:3px;color:#8b949e}
.port.open{background:rgba(35,134,54,.2);color:#3fb950}
.port.clear{background:rgba(248,81,73,.2);color:#f85149}
.signals{margin-top:1rem;padding-top:1rem;border-top:1px solid #21262d}
.signals-title{font-size:.75rem;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.5rem}
.signal{display:flex;align-items:center;gap:.5rem;padding:.4rem;background:#161b22;border-radius:4px;font-size:.8rem;margin-bottom:.25rem}
.signal-src{color:#8b949e;min-width:70px}
.signal-val{flex:1;font-family:monospace;color:#c9d1d9}
.signal-conf{color:#8b949e}
.entity-foot{padding:.75rem 1rem;border-top:1px solid #21262d;background:#161b22;display:flex;align-items:center;justify-content:space-between;font-size:.75rem;color:#8b949e}

/* === ENTITY GROUPS === */
.entity-groups{display:flex;flex-direction:column;gap:1.5rem}
.entity-group{background:#0d1117;border:1px solid #21262d;border-radius:8px;overflow:hidden}
.group-header{padding:1rem;background:#161b22;border-bottom:1px solid #21262d;display:flex;align-items:center;justify-content:space-between;cursor:pointer;user-select:none}
.group-header:hover{background:#1c2128}
.group-title{display:flex;align-items:center;gap:.75rem;font-weight:600;color:#e6edf3}
.group-icon{width:32px;height:32px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:1rem}
.group-icon.os-win{background:rgba(0,120,212,.2);color:#0078d4}
.group-icon.os-lin{background:rgba(255,165,0,.2);color:#ffa500}
.group-icon.os-net{background:rgba(88,166,255,.2);color:#58a6ff}
.group-icon.os-unk{background:rgba(136,146,157,.2);color:#8b949e}
.group-icon.svc{background:rgba(163,113,247,.2);color:#a371f7}
.group-icon.subnet{background:rgba(35,134,54,.2);color:#3fb950}
.group-icon.risk-crit{background:rgba(248,81,73,.2);color:#f85149}
.group-icon.risk-high{background:rgba(210,153,34,.2);color:#d29922}
.group-icon.risk-med{background:rgba(88,166,255,.2);color:#58a6ff}
.group-icon.risk-low{background:rgba(35,134,54,.2);color:#3fb950}
.group-meta{display:flex;align-items:center;gap:1rem;font-size:.8rem;color:#8b949e}
.group-toggle{color:#8b949e;transition:transform .2s}
.group-header.collapsed .group-toggle{transform:rotate(-90deg)}
.group-body{padding:1rem}
.group-body.collapsed{display:none}
.group-body .entity-grid{margin:0}

/* === VULNERABILITIES === */
.vulns{margin-top:.75rem;padding-top:.75rem;border-top:1px solid #21262d}
.vulns-title{font-size:.75rem;font-weight:600;color:#f85149;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.5rem;display:flex;align-items:center;gap:.5rem}
.vuln{display:flex;align-items:center;gap:.5rem;padding:.4rem;background:rgba(248,81,73,.1);border:1px solid rgba(248,81,73,.2);border-radius:4px;font-size:.75rem;margin-bottom:.25rem}
.vuln-id{font-family:monospace;color:#f85149;font-weight:500}
.vuln-score{padding:.1rem .3rem;border-radius:3px;font-weight:600;font-size:.7rem}
.vuln-score.critical{background:rgba(248,81,73,.3);color:#f85149}
.vuln-score.high{background:rgba(210,153,34,.3);color:#d29922}
.vuln-score.medium{background:rgba(88,166,255,.3);color:#58a6ff}
.vuln-score.low{background:rgba(35,134,54,.3);color:#3fb950}
.vuln-desc{flex:1;color:#8b949e;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.vulns-more{font-size:.75rem;color:#8b949e;padding:.25rem}

/* === RISK LIST === */
.risk-list{list-style:none}
.risk-item{display:flex;align-items:center;gap:1rem;padding:.75rem;border-bottom:1px solid #21262d}
.risk-item:last-child{border-bottom:none}
.risk-item:hover{background:#161b22}
.risk-score{width:44px;height:44px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-weight:700;flex-shrink:0}
.risk-score.critical{background:rgba(248,81,73,.2);color:#f85149}
.risk-score.high{background:rgba(210,153,34,.2);color:#d29922}
.risk-score.medium{background:rgba(88,166,255,.2);color:#58a6ff}
.risk-score.low{background:rgba(35,134,54,.2);color:#3fb950}
.risk-info{flex:1;min-width:0}
.risk-title{font-weight:500;color:#e6edf3}
.risk-desc{font-size:.8rem;color:#8b949e}

/* === CLEARTEXT PANEL === */
.cleartext-panel{background:rgba(248,81,73,.1);border:1px solid rgba(248,81,73,.3);border-radius:8px;padding:1rem;margin-bottom:1rem}
.cleartext-head{display:flex;align-items:center;gap:.5rem;font-weight:600;color:#f85149;margin-bottom:.75rem}
.cleartext-item{display:flex;align-items:center;gap:.75rem;padding:.5rem .75rem;background:rgba(0,0,0,.2);border-radius:4px;font-size:.85rem;margin-bottom:.25rem}

/* === TABLES === */
.tbl-wrap{overflow-x:auto;border:1px solid #21262d;border-radius:8px}
.tbl{width:100%;border-collapse:collapse;font-size:.875rem}
.tbl th{text-align:left;padding:.75rem 1rem;font-weight:600;color:#8b949e;background:#161b22;border-bottom:1px solid #21262d}
.tbl td{padding:.75rem 1rem;border-bottom:1px solid #21262d;vertical-align:top}
.tbl tr:hover{background:#161b22}

/* === MODALS === */
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.7);display:none;align-items:center;justify-content:center;z-index:1000;padding:2rem}
.modal-overlay.active{display:flex}
.modal{background:#0d1117;border:1px solid #30363d;border-radius:12px;max-width:700px;width:100%;max-height:80vh;overflow:hidden;display:flex;flex-direction:column}
.modal-head{padding:1rem 1.5rem;border-bottom:1px solid #21262d;display:flex;align-items:center;justify-content:space-between}
.modal-title{font-size:1.1rem;font-weight:600;color:#e6edf3}
.modal-close{background:none;border:none;color:#8b949e;cursor:pointer;font-size:1.5rem;line-height:1}
.modal-close:hover{color:#c9d1d9}
.modal-body{padding:1.5rem;overflow-y:auto;flex:1}
.modal-foot{padding:1rem 1.5rem;border-top:1px solid #21262d;display:flex;justify-content:flex-end;gap:.75rem}

/* === DROP ZONE === */
.drop-zone{border:2px dashed #30363d;border-radius:8px;padding:3rem;text-align:center;cursor:pointer;transition:all .15s}
.drop-zone:hover,.drop-zone.dragover{border-color:#58a6ff;background:rgba(88,166,255,.05)}
.drop-zone-text{color:#8b949e;margin-bottom:.5rem}
.drop-zone-hint{font-size:.8rem;color:#484f58}

/* === CONTEXT MENU === */
.ctx-menu{position:fixed;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:.5rem 0;min-width:180px;box-shadow:0 8px 24px rgba(0,0,0,.4);z-index:1001;display:none}
.ctx-menu.active{display:block}
.ctx-item{display:block;width:100%;padding:.5rem 1rem;color:#c9d1d9;cursor:pointer;font-size:.875rem;text-align:left;background:none;border:none}
.ctx-item:hover{background:#21262d}
.ctx-div{height:1px;background:#21262d;margin:.5rem 0}

/* === SOURCE CARDS === */
.source-card{background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:1rem;margin-bottom:1rem}
.source-head{display:flex;align-items:center;gap:.75rem;margin-bottom:.75rem}
.source-name{font-weight:600;color:#e6edf3}
.source-meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.5rem;font-size:.8rem}
.source-label{color:#8b949e;font-size:.7rem;text-transform:uppercase}
.source-val{color:#c9d1d9;font-family:monospace}

/* === ICONS === */
.icon{display:inline-flex;align-items:center;justify-content:center;width:1em;height:1em;vertical-align:middle}
.icon svg{width:100%;height:100%}
.icon-sm{width:.875em;height:.875em}
.icon-lg{width:1.25em;height:1.25em}
.icon-xl{width:1.5em;height:1.5em}

/* === UTILITIES === */
.hidden{display:none!important}
.mono{font-family:'Consolas','Monaco',monospace}
.flex{display:flex}
.flex-wrap{flex-wrap:wrap}
.items-center{align-items:center}
.justify-between{justify-content:space-between}
.gap-2{gap:.5rem}
.gap-4{gap:1rem}
.mb-4{margin-bottom:1rem}
.mt-4{margin-top:1rem}

/* === SCROLLBAR === */
::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-track{background:#0d1117}
::-webkit-scrollbar-thumb{background:#30363d;border-radius:4px}
::-webkit-scrollbar-thumb:hover{background:#484f58}

/* === PRINT === */
@media print{
  .class-banner{position:static}
  .sidebar{display:none}
  .main{margin-left:0}
  .btn{display:none}
  body{background:#fff;color:#000}
  .card,.entity,.stat{border-color:#ccc}
}
]]></xsl:text>
</style>
</head>
<body>

<!-- Classification Banner Top -->
<div class="class-banner" id="class-top">
  <xsl:attribute name="style">background-color:<xsl:value-of select="$classification-color"/></xsl:attribute>
  <xsl:value-of select="$classification"/>
</div>

<!-- Main App Container -->
<div class="app">

  <!-- Sidebar Navigation -->
  <nav class="sidebar">
    <div class="sidebar-logo">⦿ NetIntel</div>
    <ul class="nav">
      <li><a href="#" class="active" data-nav="dashboard">◫ Dashboard</a></li>
      <li><a href="#" data-nav="entities">▤ All Entities</a></li>
      <li><a href="#" data-nav="cleartext">⚠ Cleartext</a></li>
      <li><a href="#" data-nav="sources">◰ Sources</a></li>
    </ul>
    <div class="nav-section">Tools</div>
    <ul class="nav">
      <li><a href="#" data-action="import">↑ Import Data</a></li>
      <li><a href="#" data-action="export">↓ Export</a></li>
      <li><a href="#" data-action="vuln-db">⬡ Vuln Database</a></li>
    </ul>
  </nav>

  <!-- Main Content Area -->
  <main class="main">
    
    <!-- Header Bar -->
    <header class="header">
      <div class="header-left">
        <div class="search">
          <input type="text" id="search" placeholder="Search hosts, ports, services..."/>
        </div>
      </div>
      <div class="header-right">
        <span style="font-size:.8rem;color:#8b949e;">Scan: <xsl:value-of select="/nmaprun/@startstr"/></span>
        <button class="btn btn-secondary btn-sm" data-action="import">Import</button>
        <button class="btn btn-primary btn-sm" data-action="export">Export</button>
      </div>
    </header>

    <!-- Content Sections -->
    <div class="content">
      
      <!-- Dashboard Section -->
      <xsl:call-template name="dashboard-section"/>
      
      <!-- Entities Section -->
      <xsl:call-template name="entities-section"/>
      
      <!-- Cleartext Section -->
      <xsl:call-template name="cleartext-section"/>
      
      <!-- Sources Section -->
      <xsl:call-template name="sources-section"/>
      
    </div>
  </main>
</div>

<!-- Classification Banner Bottom -->
<div class="class-banner" id="class-bottom">
  <xsl:attribute name="style">background-color:<xsl:value-of select="$classification-color"/></xsl:attribute>
  <xsl:value-of select="$classification"/>
</div>

<!-- Modals -->
<xsl:call-template name="modals"/>

<!-- Context Menu -->
<div class="ctx-menu" id="ctx-menu">
  <button class="ctx-item" data-tag="crown">★ Crown Jewel</button>
  <button class="ctx-item" data-tag="choke">◎ Choke Point</button>
  <button class="ctx-item" data-tag="key">⬡ Key Terrain</button>
  <div class="ctx-div"></div>
  <button class="ctx-item" data-tag="clear">✕ Clear Tags</button>
</div>

<!-- Embedded Scan Data as JSON -->
<xsl:call-template name="embedded-data"/>

<!-- Inline JavaScript -->
<xsl:call-template name="inline-scripts"/>

</body>
</html>
</xsl:template>

<!-- ============================================
     DASHBOARD SECTION
     ============================================ -->
<xsl:template name="dashboard-section">
  <xsl:variable name="total" select="/nmaprun/runstats/hosts/@total"/>
  <xsl:variable name="up" select="/nmaprun/runstats/hosts/@up"/>
  <xsl:variable name="down" select="/nmaprun/runstats/hosts/@down"/>
  <xsl:variable name="open-ports" select="count(/nmaprun/host/ports/port[state/@state='open'])"/>
  
  <section class="section active" data-section="dashboard">
    <div class="section-header">
      <h2 class="section-title">Executive Summary</h2>
    </div>
    
    <!-- Stats Grid -->
    <div class="stats">
      <div class="stat success">
        <div class="stat-label">Hosts Online</div>
        <div class="stat-value"><xsl:value-of select="$up"/></div>
        <div class="stat-detail">of <xsl:value-of select="$total"/> scanned</div>
      </div>
      <div class="stat info">
        <div class="stat-label">Open Ports</div>
        <div class="stat-value"><xsl:value-of select="$open-ports"/></div>
        <div class="stat-detail">across all hosts</div>
      </div>
      <div class="stat warning">
        <div class="stat-label">Cleartext Services</div>
        <div class="stat-value" id="cleartext-count">--</div>
        <div class="stat-detail">security concern</div>
      </div>
      <div class="stat danger">
        <div class="stat-label">Risk Score</div>
        <div class="stat-value" id="risk-score">--</div>
        <div class="stat-detail">average (0-100)</div>
      </div>
    </div>
    
    <!-- Cleartext Warning Panel (hidden by default, shown by JS) -->
    <div class="cleartext-panel hidden" id="cleartext-panel">
      <div class="cleartext-head">⚠ Cleartext Protocols Detected</div>
      <div id="cleartext-list"></div>
    </div>
    
    <!-- Top Risks -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">Top Risks</span>
        <a href="#" class="btn btn-ghost btn-sm" data-nav="entities">View All →</a>
      </div>
      <ul class="risk-list" id="top-risks">
        <li class="risk-item" style="color:#8b949e;">Calculating risks...</li>
      </ul>
    </div>
    
    <!-- Two Column Layout -->
    <div class="flex gap-4" style="flex-wrap:wrap;margin-top:1rem;">
      <!-- OS Distribution -->
      <div class="card" style="flex:1;min-width:280px;">
        <div class="card-header">
          <span class="card-title">OS Distribution</span>
        </div>
        <div class="card-body" id="os-dist"></div>
      </div>
      
      <!-- Key Terrain -->
      <div class="card" style="flex:1;min-width:280px;">
        <div class="card-header">
          <span class="card-title">Key Terrain</span>
          <span class="badge badge-info" id="terrain-count">0 tagged</span>
        </div>
        <div class="card-body" id="terrain-list">
          <p style="color:#8b949e;font-size:.85rem;">Right-click hosts to tag as key terrain</p>
        </div>
      </div>
    </div>
  </section>
</xsl:template>

<!-- ============================================
     ENTITIES SECTION
     ============================================ -->
<xsl:template name="entities-section">
  <section class="section" data-section="entities">
    <div class="section-header">
      <h2 class="section-title">All Entities</h2>
      <div class="flex gap-2">
        <select id="entity-group" class="btn btn-secondary btn-sm" style="appearance:auto;padding-right:2rem;">
          <option value="none">No Grouping</option>
          <option value="os">Group by OS</option>
          <option value="subnet">Group by Subnet</option>
          <option value="service">Group by Service</option>
          <option value="risk">Group by Risk Level</option>
        </select>
        <select id="entity-filter" class="btn btn-secondary btn-sm" style="appearance:auto;padding-right:2rem;">
          <option value="all">All Hosts</option>
          <option value="up">Online Only</option>
          <option value="cleartext">Has Cleartext</option>
          <option value="risk">High Risk</option>
          <option value="tagged">Key Terrain</option>
        </select>
      </div>
    </div>
    
    <div class="entity-grid" id="entity-grid">
      <xsl:for-each select="/nmaprun/host[status/@state='up']">
        <xsl:call-template name="entity-card"/>
      </xsl:for-each>
    </div>
  </section>
</xsl:template>

<!-- Entity Card Template -->
<xsl:template name="entity-card">
  <xsl:variable name="ip" select="address[@addrtype='ipv4']/@addr | address[@addrtype='ipv6']/@addr"/>
  <xsl:variable name="mac" select="address[@addrtype='mac']/@addr"/>
  <xsl:variable name="mac-vendor" select="address[@addrtype='mac']/@vendor"/>
  <xsl:variable name="hostname" select="hostnames/hostname/@name"/>
  <xsl:variable name="os" select="os/osmatch[1]"/>
  <xsl:variable name="open-ports" select="ports/port[state/@state='open']"/>
  <xsl:variable name="filtered-ports" select="ports/port[state/@state='filtered']"/>
  
  <div class="entity" data-ip="{$ip}">
    <div class="entity-head">
      <div class="entity-icon" data-os-icon="">▣</div>
      <div class="entity-info">
        <div class="entity-ip"><xsl:value-of select="$ip"/></div>
        <xsl:if test="$hostname">
          <div class="entity-host"><xsl:value-of select="$hostname"/></div>
        </xsl:if>
        <div class="entity-tags"></div>
      </div>
    </div>
    <div class="entity-body">
      <div class="entity-stats">
        <div class="entity-stat">
          <b><xsl:value-of select="count($open-ports)"/></b>
          <span>Open</span>
        </div>
        <div class="entity-stat">
          <b><xsl:value-of select="count($filtered-ports)"/></b>
          <span>Filtered</span>
        </div>
        <div class="entity-stat">
          <b data-risk="">--</b>
          <span>Risk</span>
        </div>
      </div>
      
      <div class="ports">
        <xsl:for-each select="$open-ports">
          <span class="port open" data-port="{@portid}" data-svc="{service/@name}">
            <xsl:value-of select="@portid"/>/<xsl:value-of select="@protocol"/>
          </span>
        </xsl:for-each>
      </div>
      
      <!-- Fingerprint Signals -->
      <xsl:if test="$os or $mac">
        <div class="signals">
          <div class="signals-title">Identification Signals</div>
          <xsl:if test="$os">
            <div class="signal">
              <span class="signal-src">OS</span>
              <span class="signal-val"><xsl:value-of select="$os/@name"/></span>
              <span class="signal-conf"><xsl:value-of select="$os/@accuracy"/>%</span>
            </div>
          </xsl:if>
          <xsl:if test="$mac">
            <div class="signal">
              <span class="signal-src">MAC</span>
              <span class="signal-val"><xsl:value-of select="$mac"/><xsl:if test="$mac-vendor"> (<xsl:value-of select="$mac-vendor"/>)</xsl:if></span>
            </div>
          </xsl:if>
          <xsl:for-each select="$open-ports[service/@product][position() &lt;= 2]">
            <div class="signal">
              <span class="signal-src">:<xsl:value-of select="@portid"/></span>
              <span class="signal-val"><xsl:value-of select="service/@product"/><xsl:if test="service/@version"><xsl:text> </xsl:text><xsl:value-of select="service/@version"/></xsl:if></span>
            </div>
          </xsl:for-each>
        </div>
      </xsl:if>
    </div>
    <div class="entity-foot">
      <span>1 source</span>
      <button class="btn btn-ghost btn-sm">Details</button>
    </div>
  </div>
</xsl:template>

<!-- ============================================
     CLEARTEXT SECTION
     ============================================ -->
<xsl:template name="cleartext-section">
  <section class="section" data-section="cleartext">
    <div class="section-header">
      <h2 class="section-title">Cleartext Protocol Analysis</h2>
    </div>
    <div class="card">
      <div class="card-body" id="cleartext-detail">
        <p style="color:#8b949e;">Analyzing cleartext protocols...</p>
      </div>
    </div>
  </section>
</xsl:template>

<!-- ============================================
     SOURCES SECTION
     ============================================ -->
<xsl:template name="sources-section">
  <section class="section" data-section="sources">
    <div class="section-header">
      <h2 class="section-title">Data Sources</h2>
      <button class="btn btn-primary btn-sm" data-action="import">+ Add Source</button>
    </div>
    
    <div class="source-card">
      <div class="source-head">
        <span style="font-size:1.25rem;">⦿</span>
        <span class="source-name">Nmap Scan (Primary)</span>
      </div>
      <div class="source-meta">
        <div>
          <div class="source-label">Tool</div>
          <div class="source-val">nmap <xsl:value-of select="/nmaprun/@version"/></div>
        </div>
        <div>
          <div class="source-label">Started</div>
          <div class="source-val"><xsl:value-of select="/nmaprun/@startstr"/></div>
        </div>
        <div>
          <div class="source-label">Finished</div>
          <div class="source-val"><xsl:value-of select="/nmaprun/runstats/finished/@timestr"/></div>
        </div>
        <div>
          <div class="source-label">Hosts</div>
          <div class="source-val"><xsl:value-of select="/nmaprun/runstats/hosts/@up"/> up / <xsl:value-of select="/nmaprun/runstats/hosts/@total"/> total</div>
        </div>
        <div style="grid-column: 1 / -1;">
          <div class="source-label">Arguments</div>
          <div class="source-val" style="word-break:break-all;"><xsl:value-of select="/nmaprun/@args"/></div>
        </div>
      </div>
    </div>
    
    <div id="additional-sources"></div>
  </section>
</xsl:template>

<!-- ============================================
     MODALS
     ============================================ -->
<xsl:template name="modals">
  <!-- Import Modal -->
  <div class="modal-overlay" id="import-modal">
    <div class="modal">
      <div class="modal-head">
        <span class="modal-title">Import Additional Data</span>
        <button class="modal-close" data-close-modal="">×</button>
      </div>
      <div class="modal-body">
        <div class="drop-zone" id="drop-zone">
          <div style="font-size:2rem;margin-bottom:1rem;">↑</div>
          <div class="drop-zone-text">Drop file here or click to browse</div>
          <div class="drop-zone-hint">Supports: Nmap XML</div>
          <input type="file" id="file-input" accept=".xml" style="display:none;"/>
        </div>
      </div>
      <div class="modal-foot">
        <button class="btn btn-secondary" data-close-modal="">Cancel</button>
      </div>
    </div>
  </div>
  
  <!-- Export Modal -->
  <div class="modal-overlay" id="export-modal">
    <div class="modal">
      <div class="modal-head">
        <span class="modal-title">Export Data</span>
        <button class="modal-close" data-close-modal="">×</button>
      </div>
      <div class="modal-body">
        <div class="flex flex-wrap gap-2">
          <button class="btn btn-secondary" data-export="csv">Export CSV</button>
          <button class="btn btn-secondary" data-export="json">Export JSON</button>
          <button class="btn btn-secondary" data-export="html">Export Report</button>
          <button class="btn btn-primary" data-export="cpe">Export CPEs</button>
        </div>
        <div class="mt-4">
          <label style="display:flex;align-items:center;gap:.5rem;font-size:.875rem;">
            <input type="checkbox" id="export-tags"/> Include tags and annotations
          </label>
        </div>
      </div>
      <div class="modal-foot">
        <button class="btn btn-secondary" data-close-modal="">Close</button>
      </div>
    </div>
  </div>
  
  <!-- Vuln DB Modal -->
  <div class="modal-overlay" id="vuln-modal">
    <div class="modal">
      <div class="modal-head">
        <span class="modal-title">Vulnerability Database</span>
        <button class="modal-close" data-close-modal="">×</button>
      </div>
      <div class="modal-body">
        <p style="color:#8b949e;margin-bottom:1rem;font-size:.875rem;">
          Load a CPE-to-CVE mapping file to enrich scan data with vulnerability information.
        </p>
        <div class="drop-zone" id="vuln-drop-zone">
          <div style="font-size:2rem;margin-bottom:1rem;">⬡</div>
          <div class="drop-zone-text">Drop vuln-db.json here</div>
          <div class="drop-zone-hint">CPE to CVE mapping file</div>
          <input type="file" id="vuln-input" accept=".json" style="display:none;"/>
        </div>
        <div class="mt-4" id="vuln-status">
          <p style="color:#8b949e;font-size:.8rem;">No vulnerability database loaded</p>
        </div>
      </div>
      <div class="modal-foot">
        <button class="btn btn-secondary" data-close-modal="">Close</button>
      </div>
    </div>
  </div>
</xsl:template>

<!-- ============================================
     EMBEDDED DATA (JSON)
     ============================================ -->
<xsl:template name="embedded-data">
  <script type="application/json" id="scan-data">
{
  "scanInfo": {
    "scanner": "<xsl:value-of select="/nmaprun/@scanner"/>",
    "version": "<xsl:value-of select="/nmaprun/@version"/>",
    "args": "<xsl:value-of select="translate(/nmaprun/@args, '&quot;', &quot;'&quot;)"/>",
    "start": "<xsl:value-of select="/nmaprun/@start"/>",
    "startstr": "<xsl:value-of select="/nmaprun/@startstr"/>",
    "endstr": "<xsl:value-of select="/nmaprun/runstats/finished/@timestr"/>"
  },
  "stats": {
    "total": <xsl:value-of select="/nmaprun/runstats/hosts/@total"/>,
    "up": <xsl:value-of select="/nmaprun/runstats/hosts/@up"/>,
    "down": <xsl:value-of select="/nmaprun/runstats/hosts/@down"/>
  },
  "hosts": [<xsl:for-each select="/nmaprun/host">
    {
      "ip": "<xsl:value-of select="address[@addrtype='ipv4']/@addr"/><xsl:value-of select="address[@addrtype='ipv6']/@addr"/>",
      "mac": "<xsl:value-of select="address[@addrtype='mac']/@addr"/>",
      "macVendor": "<xsl:value-of select="address[@addrtype='mac']/@vendor"/>",
      "hostname": "<xsl:value-of select="hostnames/hostname/@name"/>",
      "status": "<xsl:value-of select="status/@state"/>",
      "os": [<xsl:for-each select="os/osmatch">{"name":"<xsl:value-of select="translate(@name, '&quot;', &quot;'&quot;)"/>","accuracy":<xsl:value-of select="@accuracy"/>}<xsl:if test="position()!=last()">,</xsl:if></xsl:for-each>],
      "ports": [<xsl:for-each select="ports/port">{"port":<xsl:value-of select="@portid"/>,"proto":"<xsl:value-of select="@protocol"/>","state":"<xsl:value-of select="state/@state"/>","svc":"<xsl:value-of select="service/@name"/>","product":"<xsl:value-of select="translate(service/@product, '&quot;', &quot;'&quot;)"/>","version":"<xsl:value-of select="service/@version"/>","cpe":"<xsl:value-of select="service/cpe"/>"}<xsl:if test="position()!=last()">,</xsl:if></xsl:for-each>],
      "trace": [<xsl:for-each select="trace/hop">{"ttl":<xsl:value-of select="@ttl"/>,"ip":"<xsl:value-of select="@ipaddr"/>"}<xsl:if test="position()!=last()">,</xsl:if></xsl:for-each>]
    }<xsl:if test="position()!=last()">,</xsl:if></xsl:for-each>
  ]
}
  </script>
</xsl:template>

<!-- ============================================
     INLINE JAVASCRIPT
     ============================================ -->
<xsl:template name="inline-scripts">
<script>
<xsl:text disable-output-escaping="yes"><![CDATA[
// === CONSTANTS ===
const CLEARTEXT = {21:'FTP',23:'Telnet',25:'SMTP',80:'HTTP',110:'POP3',143:'IMAP',161:'SNMP',389:'LDAP',513:'rlogin',514:'RSH',1433:'MSSQL',3306:'MySQL',5432:'PostgreSQL',8080:'HTTP-Alt'};
const RISK_WEIGHTS = {21:7,22:3,23:10,25:4,53:3,80:2,110:6,111:5,135:6,139:7,143:6,161:7,389:6,443:1,445:8,512:9,513:9,514:9,1433:8,1521:8,3306:7,3389:7,5432:6,5900:7,6379:7,27017:8};
const OS_PATTERNS = {win:/windows|microsoft/i,lin:/linux|ubuntu|debian|centos|redhat/i,net:/cisco|juniper|fortinet/i};
const MAX_IMPORT_SIZE = 10 * 1024 * 1024; // 10MB max file size

// === HEROICONS (inline SVG) ===
const ICONS = {
  server: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M21.75 17.25v-.228a4.5 4.5 0 0 0-.12-1.03l-2.268-9.64a3.375 3.375 0 0 0-3.285-2.602H7.923a3.375 3.375 0 0 0-3.285 2.602l-2.268 9.64a4.5 4.5 0 0 0-.12 1.03v.228m19.5 0a3 3 0 0 1-3 3H5.25a3 3 0 0 1-3-3m19.5 0a3 3 0 0 0-3-3H5.25a3 3 0 0 0-3 3m16.5 0h.008v.008h-.008v-.008Zm-3 0h.008v.008h-.008v-.008Z" /></svg>',
  computer: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M9 17.25v1.007a3 3 0 0 1-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0 1 15 18.257V17.25m6-12V15a2.25 2.25 0 0 1-2.25 2.25H5.25A2.25 2.25 0 0 1 3 15V5.25m18 0A2.25 2.25 0 0 0 18.75 3H5.25A2.25 2.25 0 0 0 3 5.25m18 0V12a2.25 2.25 0 0 1-2.25 2.25H5.25A2.25 2.25 0 0 1 3 12V5.25" /></svg>',
  windows: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor"><path d="M3 5.5l7.5-1v7H3v-6zm0 13l7.5 1v-7H3v6zm8.5 1.1l9.5 1.4v-8.5h-9.5v7.1zm0-14.2v7.1h9.5V4l-9.5 1.4z"/></svg>',
  linux: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/></svg>',
  wifi: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M8.288 15.038a5.25 5.25 0 0 1 7.424 0M5.106 11.856c3.807-3.808 9.98-3.808 13.788 0M1.924 8.674c5.565-5.565 14.587-5.565 20.152 0M12.53 18.22l-.53.53-.53-.53a.75.75 0 0 1 1.06 0Z" /></svg>',
  database: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M20.25 6.375c0 2.278-3.694 4.125-8.25 4.125S3.75 8.653 3.75 6.375m16.5 0c0-2.278-3.694-4.125-8.25-4.125S3.75 4.097 3.75 6.375m16.5 0v11.25c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125V6.375m16.5 0v3.75m-16.5-3.75v3.75m16.5 0v3.75C20.25 16.153 16.556 18 12 18s-8.25-1.847-8.25-4.125v-3.75m16.5 0c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125" /></svg>',
  globe: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M12 21a9.004 9.004 0 0 0 8.716-6.747M12 21a9.004 9.004 0 0 1-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 0 1 7.843 4.582M12 3a8.997 8.997 0 0 0-7.843 4.582m15.686 0A11.953 11.953 0 0 1 12 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0 1 21 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0 1 12 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 0 1 3 12c0-1.605.42-3.113 1.157-4.418" /></svg>',
  shield: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75 11.25 15 15 9.75m-3-7.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z" /></svg>',
  warning: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" /></svg>',
  check: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="m4.5 12.75 6 6 9-13.5" /></svg>',
  xmark: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18 18 6M6 6l12 12" /></svg>',
  chart: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 0 1 3 19.875v-6.75ZM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 0 1-1.125-1.125V8.625ZM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 0 1-1.125-1.125V4.125Z" /></svg>',
  folder: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M2.25 12.75V12A2.25 2.25 0 0 1 4.5 9.75h15A2.25 2.25 0 0 1 21.75 12v.75m-8.69-6.44-2.12-2.12a1.5 1.5 0 0 0-1.061-.44H4.5A2.25 2.25 0 0 0 2.25 6v12a2.25 2.25 0 0 0 2.25 2.25h15A2.25 2.25 0 0 0 21.75 18V9a2.25 2.25 0 0 0-2.25-2.25h-5.379a1.5 1.5 0 0 1-1.06-.44Z" /></svg>',
  upload: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 0 0 5.25 21h13.5A2.25 2.25 0 0 0 21 18.75V16.5m-13.5-9L12 3m0 0 4.5 4.5M12 3v13.5" /></svg>',
  download: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 0 0 5.25 21h13.5A2.25 2.25 0 0 0 21 18.75V16.5M16.5 12 12 16.5m0 0L7.5 12m4.5 4.5V3" /></svg>',
  bug: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M12 12.75c1.148 0 2.278.08 3.383.237 1.037.146 1.866.966 1.866 2.013 0 3.728-2.35 6.75-5.25 6.75S6.75 18.728 6.75 15c0-1.046.83-1.867 1.866-2.013A24.204 24.204 0 0 1 12 12.75Zm0 0c2.883 0 5.647.508 8.207 1.44a23.91 23.91 0 0 1-1.152 6.06M12 12.75c-2.883 0-5.647.508-8.208 1.44.125 2.104.52 4.136 1.153 6.06M12 12.75a2.25 2.25 0 0 0 2.248-2.354M12 12.75a2.25 2.25 0 0 1-2.248-2.354M12 8.25c.995 0 1.971-.08 2.922-.236.403-.066.74-.358.795-.762a3.778 3.778 0 0 0-.399-2.25M12 8.25c-.995 0-1.97-.08-2.922-.236-.402-.066-.74-.358-.795-.762a3.734 3.734 0 0 1 .4-2.253M12 8.25a2.25 2.25 0 0 0-2.248 2.146M12 8.25a2.25 2.25 0 0 1 2.248 2.146M8.683 5a6.032 6.032 0 0 1-1.155-1.002c.07-.63.27-1.222.574-1.747m.581 2.749A3.75 3.75 0 0 1 15.318 5m0 0c.427-.283.815-.62 1.155-.999a4.471 4.471 0 0 0-.575-1.752M4.921 6a24.048 24.048 0 0 0-.392 3.314c1.668.546 3.416.914 5.223 1.082M19.08 6c.205 1.08.337 2.187.392 3.314a23.882 23.882 0 0 1-5.223 1.082" /></svg>',
  star: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M11.48 3.499a.562.562 0 0 1 1.04 0l2.125 5.111a.563.563 0 0 0 .475.345l5.518.442c.499.04.701.663.321.988l-4.204 3.602a.563.563 0 0 0-.182.557l1.285 5.385a.562.562 0 0 1-.84.61l-4.725-2.885a.562.562 0 0 0-.586 0L6.982 20.54a.562.562 0 0 1-.84-.61l1.285-5.386a.562.562 0 0 0-.182-.557l-4.204-3.602a.562.562 0 0 1 .321-.988l5.518-.442a.563.563 0 0 0 .475-.345L11.48 3.5Z" /></svg>',
  key: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M15.75 5.25a3 3 0 0 1 3 3m3 0a6 6 0 0 1-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1 1 21.75 8.25Z" /></svg>',
  target: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M12 12.75c1.148 0 2.278.08 3.383.237 1.037.146 1.866.966 1.866 2.013 0 3.728-2.35 6.75-5.25 6.75S6.75 18.728 6.75 15c0-1.046.83-1.867 1.866-2.013A24.204 24.204 0 0 1 12 12.75Z" /></svg>',
  network: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M13.19 8.688a4.5 4.5 0 0 1 1.242 7.244l-4.5 4.5a4.5 4.5 0 0 1-6.364-6.364l1.757-1.757m13.35-.622 1.757-1.757a4.5 4.5 0 0 0-6.364-6.364l-4.5 4.5a4.5 4.5 0 0 0 1.242 7.244" /></svg>',
  chevronDown: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="m19.5 8.25-7.5 7.5-7.5-7.5" /></svg>',
  magnify: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="m21 21-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 5.196a7.5 7.5 0 0 0 10.607 10.607Z" /></svg>'
};

// Helper to render icon
function icon(name, cls = '') {
  return `<span class="icon ${cls}">${ICONS[name] || ''}</span>`;
}

// Generate unique storage key based on scan info
function getStorageKey() {
  if (!state.data || !state.data.scanInfo) return 'netintel-default';
  const info = state.data.scanInfo;
  const identifier = `${info.start || ''}-${info.args || ''}`;
  let hash = 0;
  for (let i = 0; i < identifier.length; i++) {
    hash = ((hash << 5) - hash) + identifier.charCodeAt(i);
    hash |= 0;
  }
  return 'netintel-' + Math.abs(hash).toString(36);
}

// === STATE ===
let state = {data:null, tags:{}, vulnDb:null};

// === INIT ===
document.addEventListener('DOMContentLoaded', () => {
  loadState(); // Also loads scan data
  initIcons();
  initNav();
  initModals();
  initContextMenu();
  initDropZones();
  initFilters();
  render();
  console.log('[NetIntel] Initialized with', state.data?.hosts?.length || 0, 'hosts');
});

// Replace Unicode symbols with SVG icons
function initIcons() {
  const NAV_ICONS = {
    'dashboard': 'chart',
    'entities': 'server',
    'cleartext': 'warning',
    'sources': 'folder',
    'import': 'upload',
    'export': 'download',
    'vuln-db': 'bug'
  };

  // Update nav items
  document.querySelectorAll('[data-nav], [data-action]').forEach(el => {
    const key = el.dataset.nav || el.dataset.action;
    const iconName = NAV_ICONS[key];
    if (iconName && ICONS[iconName]) {
      const text = el.textContent.replace(/^[^\w\s]+\s*/, '');
      el.innerHTML = `${icon(iconName, 'icon-lg')} ${text}`;
    }
  });

  // Update sidebar logo
  const logo = document.querySelector('.sidebar-logo');
  if (logo) {
    logo.innerHTML = `${icon('shield', 'icon-xl')} NetIntel`;
  }
}

function loadState() {
  try {
    // First load scan data to generate storage key
    const scanDataEl = document.getElementById('scan-data');
    if (scanDataEl) {
      state.data = JSON.parse(scanDataEl.textContent);
    }
    const key = getStorageKey();
    const s = localStorage.getItem(key);
    if (s) {
      const p = JSON.parse(s);
      state.tags = p.tags || {};
      state.vulnDb = p.vulnDb;
    }
    console.log('[NetIntel] State loaded from:', key);
  } catch(e) {
    console.error('[NetIntel] Error loading state:', e);
    state.tags = {};
    state.vulnDb = null;
  }
}

function saveState() {
  try {
    const key = getStorageKey();
    localStorage.setItem(key, JSON.stringify({tags:state.tags,vulnDb:state.vulnDb}));
  } catch(e) {
    console.error('[NetIntel] Error saving state:', e);
  }
}

// === NAVIGATION ===
function initNav() {
  document.querySelectorAll('[data-nav]').forEach(el => {
    el.addEventListener('click', e => { e.preventDefault(); navigateTo(el.dataset.nav); });
  });
  document.querySelectorAll('[data-action]').forEach(el => {
    el.addEventListener('click', e => { e.preventDefault(); handleAction(el.dataset.action); });
  });
}

function navigateTo(section) {
  document.querySelectorAll('[data-nav]').forEach(a => a.classList.toggle('active', a.dataset.nav === section));
  document.querySelectorAll('[data-section]').forEach(s => s.classList.toggle('active', s.dataset.section === section));
  if (section === 'cleartext') renderCleartext();
}

function handleAction(action) {
  if (action === 'import') document.getElementById('import-modal').classList.add('active');
  else if (action === 'export') document.getElementById('export-modal').classList.add('active');
  else if (action === 'vuln-db') document.getElementById('vuln-modal').classList.add('active');
}

// === MODALS ===
function initModals() {
  document.querySelectorAll('[data-close-modal]').forEach(el => {
    el.addEventListener('click', () => document.querySelectorAll('.modal-overlay').forEach(m => m.classList.remove('active')));
  });
  document.querySelectorAll('.modal-overlay').forEach(m => {
    m.addEventListener('click', e => { if (e.target === m) m.classList.remove('active'); });
  });
  document.querySelectorAll('[data-export]').forEach(el => {
    el.addEventListener('click', () => exportData(el.dataset.export));
  });
}

// === CONTEXT MENU ===
function initContextMenu() {
  const menu = document.getElementById('ctx-menu');
  let targetIp = null;
  
  document.addEventListener('contextmenu', e => {
    const entity = e.target.closest('[data-ip]');
    if (entity) {
      e.preventDefault();
      targetIp = entity.dataset.ip;
      menu.style.left = e.pageX + 'px';
      menu.style.top = e.pageY + 'px';
      menu.classList.add('active');
    }
  });
  
  document.addEventListener('click', () => menu.classList.remove('active'));
  
  menu.querySelectorAll('[data-tag]').forEach(btn => {
    btn.addEventListener('click', () => {
      if (!targetIp) return;
      const tag = btn.dataset.tag;
      if (tag === 'clear') delete state.tags[targetIp];
      else {
        if (!state.tags[targetIp]) state.tags[targetIp] = [];
        if (!state.tags[targetIp].includes(tag)) state.tags[targetIp].push(tag);
      }
      saveState();
      updateEntityTags();
      updateKeyTerrain();
    });
  });
}

// === DROP ZONES ===
function initDropZones() {
  // Import drop zone
  const dz = document.getElementById('drop-zone');
  const fi = document.getElementById('file-input');
  if (dz && fi) {
    dz.addEventListener('click', () => fi.click());
    dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('dragover'); });
    dz.addEventListener('dragleave', () => dz.classList.remove('dragover'));
    dz.addEventListener('drop', e => { e.preventDefault(); dz.classList.remove('dragover'); importFile(e.dataTransfer.files[0]); });
    fi.addEventListener('change', () => { if (fi.files[0]) importFile(fi.files[0]); });
  }

  // Vulnerability database drop zone
  const vulnDz = document.getElementById('vuln-drop-zone');
  const vulnFi = document.getElementById('vuln-input');
  if (vulnDz && vulnFi) {
    vulnDz.addEventListener('click', () => vulnFi.click());
    vulnDz.addEventListener('dragover', e => { e.preventDefault(); vulnDz.classList.add('dragover'); });
    vulnDz.addEventListener('dragleave', () => vulnDz.classList.remove('dragover'));
    vulnDz.addEventListener('drop', e => { e.preventDefault(); vulnDz.classList.remove('dragover'); importVulnDb(e.dataTransfer.files[0]); });
    vulnFi.addEventListener('change', () => { if (vulnFi.files[0]) importVulnDb(vulnFi.files[0]); });
  }
}

function importVulnDb(file) {
  if (!file) return;

  if (file.size > MAX_IMPORT_SIZE) {
    alert(`File too large (${(file.size / 1024 / 1024).toFixed(1)}MB). Maximum size is 10MB.`);
    return;
  }

  const reader = new FileReader();
  reader.onerror = () => {
    console.error('[NetIntel] Error reading vuln db:', reader.error);
    alert('Error reading file.');
  };
  reader.onload = e => {
    try {
      const db = JSON.parse(e.target.result);
      state.vulnDb = db;
      saveState();

      const cpeCount = Object.keys(db).length;
      const cveCount = Object.values(db).reduce((sum, cves) => sum + cves.length, 0);

      document.getElementById('vuln-status').innerHTML =
        `<p style="color:#3fb950;">✓ Database loaded: ${cpeCount} CPEs, ${cveCount} CVEs</p>`;

      console.log('[NetIntel] Loaded vuln db with', cpeCount, 'CPEs');
    } catch (err) {
      console.error('[NetIntel] Vuln db parse error:', err);
      alert('Invalid JSON file: ' + err.message);
    }
  };
  reader.readAsText(file);
}

// === FILTERS AND GROUPING ===
const GROUP_CONFIG = {
  os: {
    label: 'Operating System',
    getKey: host => {
      const osName = host.os && host.os[0] ? host.os[0].name : '';
      if (OS_PATTERNS.win.test(osName)) return 'windows';
      if (OS_PATTERNS.lin.test(osName)) return 'linux';
      if (OS_PATTERNS.net.test(osName)) return 'network';
      return 'unknown';
    },
    getLabel: key => ({ windows: 'Windows', linux: 'Linux', network: 'Network Devices', unknown: 'Unknown OS' }[key] || key),
    getIcon: key => ({ windows: ['os-win', 'windows'], linux: ['os-lin', 'linux'], network: ['os-net', 'wifi'], unknown: ['os-unk', 'server'] }[key] || ['os-unk', 'server'])
  },
  subnet: {
    label: 'Subnet',
    getKey: host => {
      const parts = host.ip.split('.');
      return parts.length === 4 ? `${parts[0]}.${parts[1]}.${parts[2]}.0/24` : 'other';
    },
    getLabel: key => key,
    getIcon: () => ['subnet', 'network']
  },
  service: {
    label: 'Primary Service',
    getKey: host => {
      const dominated = findDominantService(host);
      return dominated || 'other';
    },
    getLabel: key => SERVICE_LABELS[key] || key,
    getIcon: key => ({ web: ['svc', 'globe'], database: ['svc', 'database'], mail: ['svc', 'folder'], file: ['svc', 'folder'], remote: ['svc', 'computer'], directory: ['svc', 'key'], other: ['svc', 'server'] }[key] || ['svc', 'server'])
  },
  risk: {
    label: 'Risk Level',
    getKey: host => {
      const score = calculateRisk(host);
      if (score >= 70) return 'critical';
      if (score >= 50) return 'high';
      if (score >= 25) return 'medium';
      return 'low';
    },
    getLabel: key => ({ critical: 'Critical Risk (70+)', high: 'High Risk (50-69)', medium: 'Medium Risk (25-49)', low: 'Low Risk (0-24)' }[key]),
    getIcon: key => ({ critical: ['risk-crit', 'warning'], high: ['risk-high', 'warning'], medium: ['risk-med', 'shield'], low: ['risk-low', 'check'] }[key])
  }
};

const SERVICE_LABELS = {
  web: 'Web Servers',
  database: 'Databases',
  mail: 'Mail Servers',
  file: 'File Sharing',
  remote: 'Remote Access',
  directory: 'Directory Services',
  other: 'Other Services'
};

const SERVICE_PORTS = {
  web: [80, 443, 8080, 8443, 8000, 3000],
  database: [3306, 5432, 1433, 1521, 27017, 6379, 9200],
  mail: [25, 110, 143, 465, 587, 993, 995],
  file: [21, 22, 139, 445, 873, 2049],
  remote: [22, 23, 3389, 5900, 5901],
  directory: [389, 636, 88, 464]
};

function findDominantService(host) {
  const openPorts = host.ports.filter(p => p.state === 'open').map(p => p.port);
  let maxMatch = 0;
  let dominant = 'other';

  Object.entries(SERVICE_PORTS).forEach(([svc, ports]) => {
    const matches = openPorts.filter(p => ports.includes(p)).length;
    if (matches > maxMatch) {
      maxMatch = matches;
      dominant = svc;
    }
  });

  return dominant;
}

function calculateRisk(host) {
  const open = host.ports.filter(p => p.state === 'open');
  let risk = 0;
  open.forEach(p => {
    if (RISK_WEIGHTS[p.port]) risk += RISK_WEIGHTS[p.port];
    if (CLEARTEXT[p.port]) risk += 3;
  });
  return Math.min(risk, 100);
}

function initFilters() {
  const filterEl = document.getElementById('entity-filter');
  const groupEl = document.getElementById('entity-group');

  if (filterEl) {
    filterEl.addEventListener('change', () => applyFilterAndGroup());
  }
  if (groupEl) {
    groupEl.addEventListener('change', () => applyFilterAndGroup());
  }
}

function applyFilterAndGroup() {
  const filterEl = document.getElementById('entity-filter');
  const groupEl = document.getElementById('entity-group');
  const filter = filterEl ? filterEl.value : 'all';
  const groupBy = groupEl ? groupEl.value : 'none';

  // Get filtered hosts
  const filteredHosts = state.data.hosts.filter(host => {
    if (host.status !== 'up') return false;

    const open = host.ports.filter(p => p.state === 'open');
    const hasCleartext = open.some(p => CLEARTEXT[p.port]);
    const risk = calculateRisk(host);
    const isTagged = state.tags[host.ip] && state.tags[host.ip].length > 0;

    switch (filter) {
      case 'up': return true;
      case 'cleartext': return hasCleartext;
      case 'risk': return risk >= 50;
      case 'tagged': return isTagged;
      default: return true;
    }
  });

  if (groupBy === 'none') {
    renderFlatView(filteredHosts);
  } else {
    renderGroupedView(filteredHosts, groupBy);
  }
}

function renderFlatView(hosts) {
  const grid = document.getElementById('entity-grid');
  if (!grid) return;

  grid.innerHTML = '';
  grid.className = 'entity-grid';

  hosts.forEach(host => {
    const card = createEntityCard(host);
    grid.appendChild(card);
  });

  updateEntityCards();
}

function renderGroupedView(hosts, groupBy) {
  const grid = document.getElementById('entity-grid');
  if (!grid) return;

  const config = GROUP_CONFIG[groupBy];
  if (!config) return;

  // Group hosts
  const groups = {};
  hosts.forEach(host => {
    const key = config.getKey(host);
    if (!groups[key]) groups[key] = [];
    groups[key].push(host);
  });

  // Sort groups by count (descending)
  const sortedKeys = Object.keys(groups).sort((a, b) => groups[b].length - groups[a].length);

  grid.innerHTML = '';
  grid.className = 'entity-groups';

  sortedKeys.forEach(key => {
    const groupHosts = groups[key];
    const [iconClass, iconName] = config.getIcon(key);

    const groupEl = document.createElement('div');
    groupEl.className = 'entity-group';
    groupEl.innerHTML = `
      <div class="group-header" data-group="${key}">
        <div class="group-title">
          <div class="group-icon ${iconClass}">${icon(iconName, 'icon-lg')}</div>
          <span>${config.getLabel(key)}</span>
        </div>
        <div class="group-meta">
          <span>${groupHosts.length} host${groupHosts.length !== 1 ? 's' : ''}</span>
          <span class="group-toggle">${icon('chevronDown')}</span>
        </div>
      </div>
      <div class="group-body" data-group-body="${key}">
        <div class="entity-grid"></div>
      </div>
    `;

    const innerGrid = groupEl.querySelector('.entity-grid');
    groupHosts.forEach(host => {
      const card = createEntityCard(host);
      innerGrid.appendChild(card);
    });

    // Toggle collapse
    const header = groupEl.querySelector('.group-header');
    const body = groupEl.querySelector('.group-body');
    header.addEventListener('click', () => {
      header.classList.toggle('collapsed');
      body.classList.toggle('collapsed');
    });

    grid.appendChild(groupEl);
  });

  updateEntityCards();
}

function applyFilter(filter) {
  applyFilterAndGroup();
}

// === RENDERING ===
function render() {
  renderStats();
  updateEntityCards();
  updateOsDist();
  updateKeyTerrain();
  renderSources();
  renderVulnDbStatus();
}

function renderVulnDbStatus() {
  const el = document.getElementById('vuln-status');
  if (!el) return;

  if (state.vulnDb) {
    const cpeCount = Object.keys(state.vulnDb).length;
    const cveCount = Object.values(state.vulnDb).reduce((sum, cves) => sum + cves.length, 0);
    el.innerHTML = `<p style="color:#3fb950;">✓ Database loaded: ${cpeCount} CPEs, ${cveCount} CVEs</p>`;
  }
}

function renderStats() {
  let clearCount = 0, totalRisk = 0, riskCount = 0;
  const risks = [];
  
  state.data.hosts.filter(h => h.status === 'up').forEach(host => {
    const open = host.ports.filter(p => p.state === 'open');
    open.forEach(p => { if (CLEARTEXT[p.port]) clearCount++; });
    
    let risk = 0;
    const reasons = [];
    open.forEach(p => {
      if (RISK_WEIGHTS[p.port]) {
        risk += RISK_WEIGHTS[p.port];
        reasons.push({port:p.port, w:RISK_WEIGHTS[p.port]});
      }
      if (CLEARTEXT[p.port]) risk += 3;
    });
    risk = Math.min(risk, 100);
    if (risk > 0) {
      totalRisk += risk;
      riskCount++;
      risks.push({host, risk, reasons: reasons.sort((a,b) => b.w - a.w)});
    }
  });
  
  document.getElementById('cleartext-count').textContent = clearCount;
  document.getElementById('risk-score').textContent = riskCount ? Math.round(totalRisk / riskCount) : 0;
  
  // Cleartext panel
  if (clearCount > 0) {
    const panel = document.getElementById('cleartext-panel');
    panel.classList.remove('hidden');
    const list = document.getElementById('cleartext-list');
    const items = [];
    state.data.hosts.filter(h => h.status === 'up').forEach(host => {
      host.ports.filter(p => p.state === 'open' && CLEARTEXT[p.port]).forEach(p => {
        items.push({ip: host.ip, port: p.port, name: CLEARTEXT[p.port]});
      });
    });
    list.innerHTML = items.slice(0,5).map(i =>
      `<div class="cleartext-item"><span class="mono">${i.ip}</span><span>${i.port} - ${i.name}</span><span class="badge badge-cleartext">cleartext</span></div>`
    ).join('') + (items.length > 5 ? `<div style="color:#8b949e;font-size:.8rem;padding:.5rem;">...and ${items.length-5} more</div>` : '');
  }
  
  // Top risks
  const topRisks = risks.sort((a,b) => b.risk - a.risk).slice(0,5);
  const riskList = document.getElementById('top-risks');
  riskList.innerHTML = topRisks.length ? topRisks.map(r => {
    const level = r.risk >= 70 ? 'critical' : r.risk >= 50 ? 'high' : r.risk >= 25 ? 'medium' : 'low';
    return `<li class="risk-item"><div class="risk-score ${level}">${r.risk}</div><div class="risk-info"><div class="risk-title">${r.host.ip}${r.host.hostname ? ' ('+r.host.hostname+')' : ''}</div><div class="risk-desc">${r.reasons[0] ? 'Port '+r.reasons[0].port : 'Multiple factors'}</div></div></li>`;
  }).join('') : '<li class="risk-item" style="color:#8b949e;">No significant risks detected</li>';
}

function updateEntityCards() {
  document.querySelectorAll('.entity[data-ip]').forEach(card => {
    const ip = card.dataset.ip;
    const host = state.data.hosts.find(h => h.ip === ip);
    if (!host) return;
    
    // Risk score
    const open = host.ports.filter(p => p.state === 'open');
    let risk = 0;
    open.forEach(p => {
      if (RISK_WEIGHTS[p.port]) risk += RISK_WEIGHTS[p.port];
      if (CLEARTEXT[p.port]) risk += 3;
    });
    risk = Math.min(risk, 100);
    const riskEl = card.querySelector('[data-risk]');
    if (riskEl) riskEl.textContent = risk;
    
    // Cleartext ports
    card.querySelectorAll('.port[data-port]').forEach(p => {
      if (CLEARTEXT[parseInt(p.dataset.port)]) {
        p.classList.remove('open');
        p.classList.add('clear');
      }
    });
    
    // OS icon
    const os = host.os && host.os[0] ? host.os[0].name : '';
    const icon = card.querySelector('[data-os-icon]');
    if (icon) {
      if (OS_PATTERNS.win.test(os)) { icon.classList.add('win'); icon.textContent = '⊞'; }
      else if (OS_PATTERNS.lin.test(os)) { icon.classList.add('lin'); icon.textContent = '◆'; }
      else if (OS_PATTERNS.net.test(os)) { icon.classList.add('net'); icon.textContent = '◎'; }
    }
    
    // Tags
    updateEntityTags();
  });
}

function updateEntityTags() {
  const tagLabels = {crown: '★ Crown Jewel', choke: '◎ Choke Point', key: '⬡ Key Terrain'};
  document.querySelectorAll('.entity[data-ip]').forEach(card => {
    const ip = card.dataset.ip;
    const tags = state.tags[ip] || [];
    const tagsEl = card.querySelector('.entity-tags');
    if (tagsEl) {
      tagsEl.innerHTML = tags.map(t => `<span class="tag tag-${t}">${tagLabels[t] || t}</span>`).join('');
    }
    card.classList.toggle('tagged', tags.length > 0);
  });
}

function updateOsDist() {
  const dist = {};
  state.data.hosts.filter(h => h.status === 'up').forEach(host => {
    let type = 'unknown';
    const os = host.os && host.os[0] ? host.os[0].name : '';
    if (OS_PATTERNS.win.test(os)) type = 'windows';
    else if (OS_PATTERNS.lin.test(os)) type = 'linux';
    else if (OS_PATTERNS.net.test(os)) type = 'network';
    dist[type] = (dist[type] || 0) + 1;
  });
  
  const el = document.getElementById('os-dist');
  el.innerHTML = Object.entries(dist).map(([k,v]) =>
    `<div class="flex items-center justify-between mb-4"><span style="text-transform:capitalize;">${k}</span><span class="badge badge-info">${v}</span></div>`
  ).join('') || '<p style="color:#8b949e;">No OS data available</p>';
}

function updateKeyTerrain() {
  const tagged = Object.entries(state.tags).filter(([_,t]) => t.length > 0);
  document.getElementById('terrain-count').textContent = tagged.length + ' tagged';
  const el = document.getElementById('terrain-list');
  el.innerHTML = tagged.length ? tagged.slice(0,5).map(([ip,tags]) =>
    `<div class="flex items-center justify-between mb-4"><span class="mono">${ip}</span><div>${tags.map(t => `<span class="tag tag-${t}">${t}</span>`).join('')}</div></div>`
  ).join('') : '<p style="color:#8b949e;font-size:.85rem;">Right-click hosts to tag as key terrain</p>';
}

function renderSources() {
  const el = document.getElementById('additional-sources');
  if (!el || !state.data.sources || state.data.sources.length === 0) return;

  el.innerHTML = state.data.sources.map(src => `
    <div class="source-card">
      <div class="source-head">
        <span style="font-size:1.25rem;">↑</span>
        <span class="source-name">${src.name}</span>
      </div>
      <div class="source-meta">
        <div>
          <div class="source-label">Hosts</div>
          <div class="source-val">${src.hosts}</div>
        </div>
        <div>
          <div class="source-label">Imported</div>
          <div class="source-val">${new Date(src.timestamp).toLocaleString()}</div>
        </div>
      </div>
    </div>
  `).join('');
}

function renderCleartext() {
  const items = [];
  state.data.hosts.filter(h => h.status === 'up').forEach(host => {
    host.ports.filter(p => p.state === 'open' && CLEARTEXT[p.port]).forEach(p => {
      items.push({ip: host.ip, hostname: host.hostname, port: p.port, proto: p.proto, name: CLEARTEXT[p.port], svc: p.svc});
    });
  });
  
  const el = document.getElementById('cleartext-detail');
  if (items.length === 0) {
    el.innerHTML = '<p style="color:#3fb950;">✓ No cleartext protocols detected</p>';
    return;
  }
  
  // Group by service
  const byService = {};
  items.forEach(i => {
    if (!byService[i.name]) byService[i.name] = [];
    byService[i.name].push(i);
  });
  
  el.innerHTML = `<p class="mb-4" style="color:#f85149;"><strong>${items.length}</strong> cleartext services across <strong>${new Set(items.map(i => i.ip)).size}</strong> hosts</p>` +
    Object.entries(byService).map(([svc, list]) => `
      <div class="card mb-4">
        <div class="card-header"><span class="badge badge-cleartext">${svc}</span> <span style="margin-left:.5rem;color:#8b949e;">${list.length} instance${list.length !== 1 ? 's' : ''}</span></div>
        <div class="tbl-wrap"><table class="tbl"><thead><tr><th>Host</th><th>Port</th></tr></thead><tbody>
          ${list.map(i => `<tr><td class="mono">${i.ip}${i.hostname ? ' <span style="color:#8b949e;">('+i.hostname+')</span>' : ''}</td><td class="mono">${i.port}/${i.proto}</td></tr>`).join('')}
        </tbody></table></div>
      </div>
    `).join('');
}

// === IMPORT/EXPORT ===
function importFile(file) {
  if (!file) return;

  // File size check (10MB limit)
  if (file.size > MAX_IMPORT_SIZE) {
    alert(`File too large (${(file.size / 1024 / 1024).toFixed(1)}MB). Maximum size is 10MB.`);
    return;
  }

  const reader = new FileReader();
  reader.onerror = () => {
    console.error('[NetIntel] Error reading file:', reader.error);
    alert('Error reading file. Please try again.');
  };
  reader.onload = e => {
    try {
      const parser = new DOMParser();
      const doc = parser.parseFromString(e.target.result, 'text/xml');
      const parseError = doc.querySelector('parsererror');
      if (parseError) {
        alert('Invalid XML file: ' + parseError.textContent.slice(0, 100));
        return;
      }
      const nmaprun = doc.querySelector('nmaprun');
      if (!nmaprun) {
        alert('Not a valid Nmap XML file (missing nmaprun element)');
        return;
      }

      // Parse and merge the new scan data
      const newHosts = parseNmapXml(doc);
      const sourceName = `Imported: ${file.name}`;
      mergeHosts(newHosts, sourceName);

      document.querySelectorAll('.modal-overlay').forEach(m => m.classList.remove('active'));
      console.log('[NetIntel] Imported', newHosts.length, 'hosts from', file.name);
    } catch (err) {
      console.error('[NetIntel] Import error:', err);
      alert('Error parsing file: ' + err.message);
    }
  };
  reader.readAsText(file);
}

// Parse Nmap XML document into host objects
function parseNmapXml(doc) {
  const hosts = [];
  doc.querySelectorAll('host').forEach(hostEl => {
    const ipv4 = hostEl.querySelector('address[addrtype="ipv4"]');
    const ipv6 = hostEl.querySelector('address[addrtype="ipv6"]');
    const mac = hostEl.querySelector('address[addrtype="mac"]');
    const hostname = hostEl.querySelector('hostnames hostname');
    const status = hostEl.querySelector('status');
    const osMatches = hostEl.querySelectorAll('os osmatch');

    const host = {
      ip: (ipv4 ? ipv4.getAttribute('addr') : '') || (ipv6 ? ipv6.getAttribute('addr') : ''),
      mac: mac ? mac.getAttribute('addr') : '',
      macVendor: mac ? mac.getAttribute('vendor') : '',
      hostname: hostname ? hostname.getAttribute('name') : '',
      status: status ? status.getAttribute('state') : 'unknown',
      os: [],
      ports: [],
      trace: []
    };

    // OS detection
    osMatches.forEach(om => {
      host.os.push({
        name: om.getAttribute('name') || '',
        accuracy: parseInt(om.getAttribute('accuracy')) || 0
      });
    });

    // Ports
    hostEl.querySelectorAll('ports port').forEach(portEl => {
      const stateEl = portEl.querySelector('state');
      const svcEl = portEl.querySelector('service');
      const cpeEl = portEl.querySelector('cpe');
      host.ports.push({
        port: parseInt(portEl.getAttribute('portid')) || 0,
        proto: portEl.getAttribute('protocol') || 'tcp',
        state: stateEl ? stateEl.getAttribute('state') : 'unknown',
        svc: svcEl ? svcEl.getAttribute('name') : '',
        product: svcEl ? svcEl.getAttribute('product') : '',
        version: svcEl ? svcEl.getAttribute('version') : '',
        cpe: cpeEl ? cpeEl.textContent : ''
      });
    });

    // Traceroute
    hostEl.querySelectorAll('trace hop').forEach(hop => {
      host.trace.push({
        ttl: parseInt(hop.getAttribute('ttl')) || 0,
        ip: hop.getAttribute('ipaddr') || ''
      });
    });

    if (host.ip) hosts.push(host);
  });
  return hosts;
}

// Merge imported hosts into existing data
function mergeHosts(newHosts, sourceName) {
  let added = 0, updated = 0;

  newHosts.forEach(newHost => {
    const existing = state.data.hosts.find(h => h.ip === newHost.ip);
    if (existing) {
      // Merge ports (add new ports, don't duplicate)
      newHost.ports.forEach(newPort => {
        const existingPort = existing.ports.find(p => p.port === newPort.port && p.proto === newPort.proto);
        if (!existingPort) {
          existing.ports.push(newPort);
        } else if (newPort.product && !existingPort.product) {
          // Update if new scan has more detail
          Object.assign(existingPort, newPort);
        }
      });

      // Update OS if new scan has higher confidence
      if (newHost.os.length > 0) {
        const newBestOs = newHost.os[0];
        const existingBestOs = existing.os[0];
        if (!existingBestOs || newBestOs.accuracy > existingBestOs.accuracy) {
          existing.os = newHost.os;
        }
      }

      // Update status to 'up' if new scan shows it's up
      if (newHost.status === 'up') existing.status = 'up';

      // Merge traceroute if not present
      if (newHost.trace.length > 0 && existing.trace.length === 0) {
        existing.trace = newHost.trace;
      }

      updated++;
    } else {
      // New host - add to collection
      state.data.hosts.push(newHost);
      added++;
    }
  });

  // Update stats
  state.data.stats.total = state.data.hosts.length;
  state.data.stats.up = state.data.hosts.filter(h => h.status === 'up').length;
  state.data.stats.down = state.data.stats.total - state.data.stats.up;

  // Track source
  if (!state.data.sources) state.data.sources = [];
  state.data.sources.push({
    name: sourceName,
    hosts: newHosts.length,
    timestamp: new Date().toISOString()
  });

  // Re-render UI
  rebuildEntityGrid();
  render();

  alert(`Import complete!\nAdded: ${added} new hosts\nUpdated: ${updated} existing hosts`);
}

// Rebuild entity grid after import (since XSL only runs once)
function rebuildEntityGrid() {
  const grid = document.getElementById('entity-grid');
  if (!grid) return;

  // Clear existing cards
  grid.innerHTML = '';

  // Rebuild cards for all hosts that are up
  state.data.hosts.filter(h => h.status === 'up').forEach(host => {
    const card = createEntityCard(host);
    grid.appendChild(card);
  });
}

// === CVE MATCHING ===
function getHostCVEs(host) {
  if (!state.vulnDb) return [];

  const cves = [];
  const seen = new Set();

  host.ports.filter(p => p.state === 'open' && p.cpe).forEach(port => {
    const cpe = port.cpe;
    // Try exact match first
    if (state.vulnDb[cpe]) {
      state.vulnDb[cpe].forEach(vuln => {
        if (!seen.has(vuln.cve)) {
          seen.add(vuln.cve);
          cves.push({ ...vuln, port: port.port, cpe });
        }
      });
    }
    // Try prefix match (for version-less CPEs)
    const cpeBase = cpe.split(':').slice(0, 5).join(':');
    Object.keys(state.vulnDb).forEach(dbCpe => {
      if (dbCpe.startsWith(cpeBase) && dbCpe !== cpe) {
        state.vulnDb[dbCpe].forEach(vuln => {
          if (!seen.has(vuln.cve)) {
            seen.add(vuln.cve);
            cves.push({ ...vuln, port: port.port, cpe: dbCpe });
          }
        });
      }
    });
  });

  // Sort by CVSS score descending
  return cves.sort((a, b) => (b.cvss || 0) - (a.cvss || 0));
}

function getCvssClass(cvss) {
  if (cvss >= 9.0) return 'critical';
  if (cvss >= 7.0) return 'high';
  if (cvss >= 4.0) return 'medium';
  return 'low';
}

// Create entity card element dynamically
function createEntityCard(host) {
  const open = host.ports.filter(p => p.state === 'open');
  const filtered = host.ports.filter(p => p.state === 'filtered');
  const os = host.os && host.os[0] ? host.os[0] : null;
  const mac = host.mac;
  const cves = getHostCVEs(host);

  const card = document.createElement('div');
  card.className = 'entity';
  card.dataset.ip = host.ip;

  const vulnsHtml = cves.length > 0 ? `
    <div class="vulns">
      <div class="vulns-title">\u26a0 ${cves.length} CVE${cves.length !== 1 ? 's' : ''} Found</div>
      ${cves.slice(0, 3).map(v => `
        <div class="vuln">
          <span class="vuln-id">${v.cve}</span>
          <span class="vuln-score ${getCvssClass(v.cvss)}">${v.cvss || '?'}</span>
          <span class="vuln-desc">${v.desc || ''}</span>
        </div>
      `).join('')}
      ${cves.length > 3 ? `<div class="vulns-more">...and ${cves.length - 3} more</div>` : ''}
    </div>
  ` : '';

  card.innerHTML = `
    <div class="entity-head">
      <div class="entity-icon" data-os-icon="">\u25a3</div>
      <div class="entity-info">
        <div class="entity-ip">${host.ip}</div>
        ${host.hostname ? `<div class="entity-host">${host.hostname}</div>` : ''}
        <div class="entity-tags"></div>
      </div>
      ${cves.length > 0 ? `<span class="badge badge-critical">${cves.length} CVE${cves.length !== 1 ? 's' : ''}</span>` : ''}
    </div>
    <div class="entity-body">
      <div class="entity-stats">
        <div class="entity-stat"><b>${open.length}</b><span>Open</span></div>
        <div class="entity-stat"><b>${filtered.length}</b><span>Filtered</span></div>
        <div class="entity-stat"><b data-risk="">--</b><span>Risk</span></div>
      </div>
      <div class="ports">
        ${open.map(p => `<span class="port open" data-port="${p.port}" data-svc="${p.svc}">${p.port}/${p.proto}</span>`).join('')}
      </div>
      ${os || mac ? `
      <div class="signals">
        <div class="signals-title">Identification Signals</div>
        ${os ? `<div class="signal"><span class="signal-src">OS</span><span class="signal-val">${os.name}</span><span class="signal-conf">${os.accuracy}%</span></div>` : ''}
        ${mac ? `<div class="signal"><span class="signal-src">MAC</span><span class="signal-val">${mac}${host.macVendor ? ' (' + host.macVendor + ')' : ''}</span></div>` : ''}
        ${open.filter(p => p.product).slice(0, 2).map(p => `<div class="signal"><span class="signal-src">:${p.port}</span><span class="signal-val">${p.product}${p.version ? ' ' + p.version : ''}</span></div>`).join('')}
      </div>` : ''}
      ${vulnsHtml}
    </div>
    <div class="entity-foot">
      <span>${(state.data.sources ? state.data.sources.length : 1)} source${state.data.sources && state.data.sources.length !== 1 ? 's' : ''}</span>
      <button class="btn btn-ghost btn-sm">Details</button>
    </div>
  `;

  return card;
}

function exportData(format) {
  let content, filename, type;
  const includeTags = document.getElementById('export-tags')?.checked;
  
  if (format === 'json') {
    const data = {...state.data, tags: includeTags ? state.tags : {}};
    content = JSON.stringify(data, null, 2);
    filename = 'netintel-export.json';
    type = 'application/json';
  } else if (format === 'csv') {
    const rows = [['IP','Hostname','OS','Open Ports','Risk','Tags']];
    state.data.hosts.filter(h => h.status === 'up').forEach(h => {
      const os = h.os && h.os[0] ? h.os[0].name : '';
      const ports = h.ports.filter(p => p.state === 'open').map(p => p.port).join(';');
      let risk = 0;
      h.ports.filter(p => p.state === 'open').forEach(p => { if (RISK_WEIGHTS[p.port]) risk += RISK_WEIGHTS[p.port]; });
      const tags = includeTags && state.tags[h.ip] ? state.tags[h.ip].join(';') : '';
      rows.push([h.ip, h.hostname, os, ports, Math.min(risk,100), tags]);
    });
    content = rows.map(r => r.map(c => `"${c}"`).join(',')).join('\n');
    filename = 'netintel-export.csv';
    type = 'text/csv';
  } else if (format === 'cpe') {
    const cpes = new Set();
    state.data.hosts.forEach(h => h.ports.forEach(p => { if (p.cpe) cpes.add(p.cpe); }));
    content = JSON.stringify(Array.from(cpes), null, 2);
    filename = 'cpe-list.json';
    type = 'application/json';
  } else if (format === 'html') {
    content = document.documentElement.outerHTML;
    filename = 'netintel-report.html';
    type = 'text/html';
  }
  
  if (content) {
    const blob = new Blob([content], {type});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
  }
}

// === SEARCH ===
document.getElementById('search')?.addEventListener('input', e => {
  const q = e.target.value.toLowerCase();
  const filterEl = document.getElementById('entity-filter');
  const filter = filterEl ? filterEl.value : 'all';

  document.querySelectorAll('.entity[data-ip]').forEach(card => {
    const ip = card.dataset.ip;
    const text = card.textContent.toLowerCase();
    const matchesSearch = !q || ip.includes(q) || text.includes(q);

    // Also respect current filter
    if (matchesSearch && filter !== 'all') {
      const host = state.data.hosts.find(h => h.ip === ip);
      if (host) {
        const open = host.ports.filter(p => p.state === 'open');
        const hasCleartext = open.some(p => CLEARTEXT[p.port]);
        let risk = 0;
        open.forEach(p => {
          if (RISK_WEIGHTS[p.port]) risk += RISK_WEIGHTS[p.port];
          if (CLEARTEXT[p.port]) risk += 3;
        });
        risk = Math.min(risk, 100);
        const isTagged = state.tags[ip] && state.tags[ip].length > 0;

        let passesFilter = true;
        switch (filter) {
          case 'up': passesFilter = host.status === 'up'; break;
          case 'cleartext': passesFilter = hasCleartext; break;
          case 'risk': passesFilter = risk >= 50; break;
          case 'tagged': passesFilter = isTagged; break;
        }
        card.style.display = passesFilter ? '' : 'none';
        return;
      }
    }

    card.style.display = matchesSearch ? '' : 'none';
  });
});
]]></xsl:text>
</script>
</xsl:template>

</xsl:stylesheet>
