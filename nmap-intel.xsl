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
const STORAGE_KEY = 'netintel';

// === STATE ===
let state = {data:null, tags:{}, vulnDb:null};

// === INIT ===
document.addEventListener('DOMContentLoaded', () => {
  loadState();
  state.data = JSON.parse(document.getElementById('scan-data').textContent);
  initNav();
  initModals();
  initContextMenu();
  initDropZones();
  render();
});

function loadState() {
  try {
    const s = localStorage.getItem(STORAGE_KEY);
    if (s) { const p = JSON.parse(s); state.tags = p.tags || {}; state.vulnDb = p.vulnDb; }
  } catch(e) {}
}

function saveState() {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify({tags:state.tags,vulnDb:state.vulnDb})); } catch(e) {}
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
  const dz = document.getElementById('drop-zone');
  const fi = document.getElementById('file-input');
  if (dz && fi) {
    dz.addEventListener('click', () => fi.click());
    dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('dragover'); });
    dz.addEventListener('dragleave', () => dz.classList.remove('dragover'));
    dz.addEventListener('drop', e => { e.preventDefault(); dz.classList.remove('dragover'); importFile(e.dataTransfer.files[0]); });
    fi.addEventListener('change', () => { if (fi.files[0]) importFile(fi.files[0]); });
  }
}

// === RENDERING ===
function render() {
  renderStats();
  updateEntityCards();
  updateOsDist();
  updateKeyTerrain();
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
  document.querySelectorAll('.entity[data-ip]').forEach(card => {
    const ip = card.dataset.ip;
    const tags = state.tags[ip] || [];
    const tagsEl = card.querySelector('.entity-tags');
    if (tagsEl) {
      tagsEl.innerHTML = tags.map(t => `<span class="tag tag-${t}">${t === 'crown' ? '★ Crown Jewel' : t === 'choke' ? '◎ Choke Point' : '⬡ Key Terrain'}</span>`).join('');
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
  const reader = new FileReader();
  reader.onload = e => {
    const parser = new DOMParser();
    const doc = parser.parseFromString(e.target.result, 'text/xml');
    if (doc.querySelector('nmaprun')) {
      // Parse and merge (simplified)
      alert('Import successful! (Full merge logic TODO)');
      document.querySelectorAll('.modal-overlay').forEach(m => m.classList.remove('active'));
    } else {
      alert('Invalid nmap XML file');
    }
  };
  reader.readAsText(file);
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
  document.querySelectorAll('.entity[data-ip]').forEach(card => {
    const ip = card.dataset.ip;
    const text = card.textContent.toLowerCase();
    card.style.display = !q || ip.includes(q) || text.includes(q) ? '' : 'none';
  });
});
]]></xsl:text>
</script>
</xsl:template>

</xsl:stylesheet>
