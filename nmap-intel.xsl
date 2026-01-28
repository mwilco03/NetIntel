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
.search-count{display:inline-block;margin-left:.5rem;padding:.2rem .5rem;font-size:.75rem;color:#8b949e;background:#161b22;border-radius:4px}

/* === VIEW TOGGLE === */
.view-toggle{display:flex;background:#161b22;border-radius:6px;padding:2px;gap:2px}
.view-toggle .btn{background:transparent;border:none;opacity:.7}
.view-toggle .btn.active{background:#30363d;opacity:1}
.view-toggle .btn:hover{opacity:1}

/* === AGGREGATION VIEWS === */
.agg-view{padding:1rem 0}
.agg-header{display:flex;align-items:baseline;gap:1rem;margin-bottom:1rem}
.agg-header h3{margin:0;font-size:1.1rem;font-weight:600;color:#c9d1d9}
.agg-subtitle{font-size:.8rem;color:#8b949e}
.agg-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:.75rem}
.agg-card{background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:1rem;cursor:pointer;transition:all .15s}
.agg-card:hover{border-color:#58a6ff;background:#161b22}
.agg-card-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:.5rem}
.agg-card-port{font-size:1.25rem;font-weight:600;color:#58a6ff}
.agg-card-count{font-size:.8rem;padding:.2rem .5rem;background:#238636;color:#fff;border-radius:10px}
.agg-card-name{font-size:.875rem;color:#c9d1d9;margin-bottom:.25rem}
.agg-card-hosts{font-size:.75rem;color:#8b949e;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.agg-card.critical{border-color:rgba(248,81,73,.5)}
.agg-card.warning{border-color:rgba(210,153,34,.5)}
.agg-card.cleartext{border-color:rgba(255,123,0,.5)}

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
/* Criticality - Gold/Orange tones */
.tag-ckt{background:rgba(255,140,0,.25);color:#ff8c00;border:1px solid #ff8c00;font-weight:600}
.tag-mission-critical{background:rgba(255,69,0,.2);color:#ff6347;border:1px solid #ff6347}
.tag-mission-essential{background:rgba(255,165,0,.2);color:#ffa500;border:1px solid #ffa500}
.tag-business-critical{background:rgba(210,153,34,.2);color:#d29922;border:1px solid #d29922}
/* Tactical - Red/Purple tones */
.tag-crown{background:rgba(210,153,34,.2);color:#d29922;border:1px solid #d29922}
.tag-choke{background:rgba(248,81,73,.2);color:#f85149;border:1px solid #f85149}
.tag-key{background:rgba(163,113,247,.2);color:#a371f7;border:1px solid #a371f7}
.tag-pivot{background:rgba(219,112,147,.2);color:#db7093;border:1px solid #db7093}
.tag-attack-surface{background:rgba(255,99,71,.2);color:#ff6347;border:1px solid #ff6347}
.tag-egress{background:rgba(255,69,0,.2);color:#ff4500;border:1px solid #ff4500}
/* Environment - Blue/Green/Gray tones */
.tag-production{background:rgba(35,134,54,.2);color:#238636;border:1px solid #238636}
.tag-staging{background:rgba(88,166,255,.2);color:#58a6ff;border:1px solid #58a6ff}
.tag-development{background:rgba(163,113,247,.15);color:#a371f7;border:1px solid rgba(163,113,247,.5)}
.tag-test{background:rgba(139,148,158,.15);color:#8b949e;border:1px solid rgba(139,148,158,.4)}
.tag-deprecated{background:rgba(110,84,76,.2);color:#bc8f8f;border:1px solid #bc8f8f;text-decoration:line-through}
/* Priority */
.tag-p1{background:rgba(248,81,73,.3);color:#f85149;border:1px solid #f85149;font-weight:600}
.tag-p2{background:rgba(210,153,34,.25);color:#d29922;border:1px solid #d29922}
.tag-p3{background:rgba(88,166,255,.15);color:#58a6ff;border:1px solid rgba(88,166,255,.4)}
.tag-monitor{background:rgba(139,148,158,.1);color:#8b949e;border:1px solid rgba(139,148,158,.3)}
/* Metadata */
.tag-owner{background:rgba(88,166,255,.15);color:#58a6ff;border:1px solid rgba(88,166,255,.3);max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tag-notes{background:rgba(139,148,158,.15);color:#8b949e;border:1px solid rgba(139,148,158,.3);cursor:help}
/* Label checkbox styling for modal */
.label-group{display:flex;flex-wrap:wrap;gap:.5rem}
.label-check{display:flex;align-items:center;gap:.35rem;cursor:pointer;font-size:.8rem;padding:.25rem .5rem;border-radius:4px;background:#161b22;border:1px solid #21262d}
.label-check:hover{border-color:#30363d}
.label-check input{margin:0}

/* === ENTITY CARDS === */
.entity-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:1rem}
.entity{background:#0d1117;border:1px solid #21262d;border-radius:8px;overflow:hidden;transition:border-color .15s}
.entity:hover{border-color:#30363d}
.entity.tagged{border-color:#a371f7}
.entity.selected{border-color:#58a6ff;box-shadow:0 0 0 2px rgba(88,166,255,.3);animation:pulse-border .5s ease-out}
@keyframes pulse-border{0%{box-shadow:0 0 0 4px rgba(88,166,255,.5)}100%{box-shadow:0 0 0 2px rgba(88,166,255,.3)}}
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

/* === ADMIN PORTS === */
.admin-ports{margin-top:.75rem;padding-top:.75rem;border-top:1px solid #21262d}
.admin-title{font-size:.75rem;font-weight:600;color:#d29922;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.5rem;display:flex;align-items:center;gap:.5rem}
.admin-title svg{width:14px;height:14px}
.admin-port{display:flex;align-items:center;gap:.5rem;padding:.35rem .5rem;background:rgba(210,153,34,.08);border:1px solid rgba(210,153,34,.2);border-radius:4px;font-size:.7rem;margin-bottom:.25rem}
.admin-port-num{font-family:monospace;font-weight:600;color:#e6edf3;min-width:45px}
.admin-port-name{color:#d29922;font-weight:500;flex:1}
.admin-port-sev{padding:.1rem .35rem;border-radius:3px;font-weight:600;font-size:.65rem;text-transform:uppercase}
.admin-port-sev.sev-critical{background:rgba(248,81,73,.3);color:#f85149}
.admin-port-sev.sev-high{background:rgba(210,153,34,.3);color:#d29922}
.admin-port-sev.sev-medium{background:rgba(88,166,255,.3);color:#58a6ff}
.admin-port-sev.sev-low{background:rgba(35,134,54,.3);color:#3fb950}
.admin-port-cat{color:#8b949e;font-size:.65rem}
.admin-more{font-size:.7rem;color:#8b949e;padding:.25rem}

/* === NSE SCRIPT FINDINGS === */
.nse-findings{margin-top:.75rem;padding-top:.75rem;border-top:1px solid #21262d}
.nse-title{font-size:.75rem;font-weight:600;color:#58a6ff;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.5rem;display:flex;align-items:center;gap:.5rem}
.nse-title svg{width:14px;height:14px}
.nse-finding{display:flex;align-items:center;gap:.5rem;padding:.3rem .5rem;background:rgba(88,166,255,.08);border:1px solid rgba(88,166,255,.15);border-radius:4px;font-size:.7rem;margin-bottom:.25rem}
.nse-port{font-family:monospace;color:#8b949e;min-width:40px}
.nse-type{color:#58a6ff;font-weight:500;min-width:50px}
.nse-detail{color:#c9d1d9;flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.nse-more{font-size:.7rem;color:#8b949e;padding:.25rem}
.nse-vulns{margin-top:.75rem;padding-top:.75rem;border-top:1px solid #21262d}
.nse-vuln-title{font-size:.75rem;font-weight:600;color:#f85149;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.5rem;display:flex;align-items:center;gap:.5rem}
.nse-vuln-title svg{width:14px;height:14px}
.nse-vuln{display:flex;align-items:center;gap:.5rem;padding:.3rem .5rem;background:rgba(248,81,73,.1);border:1px solid rgba(248,81,73,.2);border-radius:4px;font-size:.7rem;margin-bottom:.25rem}
.nse-vuln-script{font-family:monospace;color:#f85149;font-weight:500}
.nse-vuln-port{color:#8b949e}

/* === DIFF VIEW === */
.diff-item{display:flex;align-items:center;gap:1rem;padding:.75rem;border-bottom:1px solid #21262d;font-size:.875rem}
.diff-item:last-child{border-bottom:none}
.diff-item:hover{background:#161b22}
.diff-ip{font-family:monospace;font-weight:600;min-width:120px}
.diff-hostname{color:#8b949e;flex:1}
.diff-badge{padding:.2rem .5rem;border-radius:4px;font-size:.75rem;font-weight:500}
.diff-badge.new{background:rgba(35,134,54,.2);color:#3fb950}
.diff-badge.removed{background:rgba(248,81,73,.2);color:#f85149}
.diff-badge.changed{background:rgba(210,153,34,.2);color:#d29922}
.diff-changes{margin-top:.5rem;padding:.5rem;background:#161b22;border-radius:4px;font-size:.8rem}
.diff-change{display:flex;align-items:center;gap:.5rem;padding:.25rem 0}
.diff-change.added{color:#3fb950}
.diff-change.removed{color:#f85149}
.diff-change .port{margin:0}

/* === TOPOLOGY VIEW === */
.topo-container{background:#0d1117;border:1px solid #21262d;border-radius:8px;min-height:500px;position:relative;overflow:hidden}
.topo-canvas{width:100%;height:500px}
.topo-node{position:absolute;background:#161b22;border:2px solid #30363d;border-radius:8px;padding:.5rem .75rem;font-size:.75rem;cursor:pointer;transition:all .15s;z-index:1}
.topo-node:hover{border-color:#58a6ff;z-index:10}
.topo-node.scanner{border-color:#238636;background:rgba(35,134,54,.1)}
.topo-node.target{border-color:#58a6ff}
.topo-node.hop{border-color:#8b949e;background:#21262d}
.topo-node-ip{font-family:monospace;font-weight:600;color:#e6edf3}
.topo-node-label{color:#8b949e;font-size:.7rem}
.topo-edge{position:absolute;background:#30363d;height:2px;transform-origin:left center;z-index:0}
.topo-edge.active{background:#58a6ff}
.topo-legend{display:flex;gap:1.5rem;padding:1rem;border-top:1px solid #21262d;font-size:.8rem}
.topo-legend-item{display:flex;align-items:center;gap:.5rem}
.topo-legend-dot{width:12px;height:12px;border-radius:4px;border:2px solid}
.topo-controls{padding:1rem;border-bottom:1px solid #21262d;display:flex;gap:1rem;align-items:center}

/* === TIMELINE VIEW === */
.timeline-container{position:relative}
.timeline-track{display:flex;gap:1rem;overflow-x:auto;padding:1rem 0}
.timeline-scan{flex:0 0 200px;background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:1rem;cursor:pointer;transition:all .15s}
.timeline-scan:hover{border-color:#58a6ff}
.timeline-scan.active{border-color:#58a6ff;background:#161b22}
.timeline-scan-date{font-weight:600;color:#e6edf3;margin-bottom:.25rem}
.timeline-scan-time{font-size:.8rem;color:#8b949e;margin-bottom:.5rem}
.timeline-scan-stats{display:flex;gap:.5rem;font-size:.75rem}
.timeline-scan-stat{padding:.2rem .4rem;background:#21262d;border-radius:3px}
.timeline-chart{height:200px;background:#0d1117;border:1px solid #21262d;border-radius:8px;margin-top:1rem;padding:1rem;position:relative}
.timeline-bar{position:absolute;bottom:2rem;background:#58a6ff;border-radius:2px 2px 0 0;min-width:20px;transition:height .3s}
.timeline-bar.hosts{background:#238636}
.timeline-bar.ports{background:#58a6ff}
.timeline-bar.risks{background:#f85149}

/* === FINGERPRINT === */
.fp-section{margin-bottom:1rem}
.fp-title{font-size:.8rem;font-weight:600;color:#8b949e;text-transform:uppercase;margin-bottom:.5rem}
.fp-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:.5rem}
.fp-item{background:#161b22;padding:.5rem .75rem;border-radius:4px;font-size:.8rem}
.fp-key{color:#8b949e;margin-right:.5rem}
.fp-val{color:#e6edf3;font-family:monospace}

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
.ctx-menu{position:fixed;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:.5rem 0;min-width:200px;box-shadow:0 8px 24px rgba(0,0,0,.4);z-index:1001;display:none}
.ctx-menu.active{display:block}
.ctx-label{padding:.25rem 1rem;font-size:.7rem;color:#8b949e;text-transform:uppercase;letter-spacing:.05em}
.ctx-item{display:block;width:100%;padding:.5rem 1rem;color:#c9d1d9;cursor:pointer;font-size:.875rem;text-align:left;background:none;border:none}
.ctx-item:hover{background:#21262d}
.ctx-item.ctx-danger{color:#f85149}
.ctx-item.ctx-danger:hover{background:rgba(248,81,73,.1)}
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
    <div class="sidebar-logo">[N] NetIntel</div>
    <ul class="nav">
      <li><a href="#" class="active" data-nav="dashboard"># Dashboard</a></li>
      <li><a href="#" data-nav="entities">= All Entities</a></li>
      <li><a href="#" data-nav="topology">o Topology</a></li>
      <li><a href="#" data-nav="timeline">~ Timeline</a></li>
      <li><a href="#" data-nav="cleartext">! Cleartext</a></li>
      <li><a href="#" data-nav="diff">&lt;&gt; Scan Diff</a></li>
      <li><a href="#" data-nav="sources">[] Sources</a></li>
    </ul>
    <div class="nav-section">Tools</div>
    <ul class="nav">
      <li><a href="#" data-action="import">^ Import Data</a></li>
      <li><a href="#" data-action="export">v Export</a></li>
      <li><a href="#" data-action="vuln-db">* Vuln Database</a></li>
    </ul>
  </nav>

  <!-- Main Content Area -->
  <main class="main">
    
    <!-- Header Bar -->
    <header class="header">
      <div class="header-left">
        <div class="search">
          <input type="text" id="search" placeholder="Search: port:22 service:ssh os:windows tag:ckt cve:CVE-* risk:>50"/>
        </div>
      </div>
      <div class="header-right">
        <span style="font-size:.8rem;color:#8b949e;">Scan: <xsl:value-of select="/nmaprun/@startstr"/></span>
        <button class="btn btn-ghost btn-sm" data-action="share" title="Copy shareable link">[+] Share</button>
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

      <!-- Topology Section -->
      <xsl:call-template name="topology-section"/>

      <!-- Timeline Section -->
      <xsl:call-template name="timeline-section"/>

      <!-- Cleartext Section -->
      <xsl:call-template name="cleartext-section"/>

      <!-- Diff Section -->
      <xsl:call-template name="diff-section"/>

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
  <div class="ctx-label">Criticality</div>
  <button class="ctx-item" data-tag="ckt">◆ CKT</button>
  <button class="ctx-item" data-tag="mission-critical">▲ Mission Critical</button>
  <div class="ctx-div"></div>
  <div class="ctx-label">Tactical</div>
  <button class="ctx-item" data-tag="crown">* Crown Jewel</button>
  <button class="ctx-item" data-tag="choke">o Choke Point</button>
  <button class="ctx-item" data-tag="pivot">&lt;&gt; Pivot Point</button>
  <div class="ctx-div"></div>
  <button class="ctx-item" data-action="annotate">✎ Full Annotation...</button>
  <div class="ctx-div"></div>
  <button class="ctx-item ctx-danger" data-tag="clear">✕ Clear All</button>
</div>

<!-- Annotation Modal -->
<div class="modal" id="annotate-modal">
  <div class="modal-content" style="max-width:560px">
    <div class="modal-head">
      <h3>Asset Annotation</h3>
      <button class="modal-close">×</button>
    </div>
    <div class="modal-body">
      <div id="annotate-info" style="margin-bottom:1rem;padding:.75rem;background:#161b22;border-radius:6px;font-family:monospace;font-size:.85rem"></div>

      <div class="form-group" style="margin-bottom:1rem">
        <label style="display:block;font-size:.8rem;color:#8b949e;margin-bottom:.25rem">Owner / Responsible Party</label>
        <input type="text" id="annotate-owner" class="input" placeholder="e.g., J. Smith, SOC Team, Network Ops" style="width:100%"/>
      </div>

      <div class="form-group" style="margin-bottom:1rem">
        <label style="display:block;font-size:.8rem;color:#8b949e;margin-bottom:.25rem">Notes</label>
        <textarea id="annotate-notes" class="input" rows="3" placeholder="Function, dependencies, maintenance windows..." style="width:100%;resize:vertical"></textarea>
      </div>

      <div class="form-group" style="margin-bottom:.75rem">
        <label style="display:block;font-size:.75rem;color:#d29922;margin-bottom:.5rem;text-transform:uppercase;letter-spacing:.05em">Criticality</label>
        <div id="annotate-labels-crit" class="label-group">
          <label class="label-check"><input type="checkbox" value="ckt"/> CKT (Cyber Key Terrain)</label>
          <label class="label-check"><input type="checkbox" value="mission-critical"/> Mission Critical</label>
          <label class="label-check"><input type="checkbox" value="mission-essential"/> Mission Essential</label>
          <label class="label-check"><input type="checkbox" value="business-critical"/> Business Critical</label>
        </div>
      </div>

      <div class="form-group" style="margin-bottom:.75rem">
        <label style="display:block;font-size:.75rem;color:#f85149;margin-bottom:.5rem;text-transform:uppercase;letter-spacing:.05em">Tactical</label>
        <div id="annotate-labels-tact" class="label-group">
          <label class="label-check"><input type="checkbox" value="crown"/> Crown Jewel</label>
          <label class="label-check"><input type="checkbox" value="choke"/> Choke Point</label>
          <label class="label-check"><input type="checkbox" value="key"/> Key Terrain</label>
          <label class="label-check"><input type="checkbox" value="pivot"/> Pivot Point</label>
          <label class="label-check"><input type="checkbox" value="attack-surface"/> Attack Surface</label>
          <label class="label-check"><input type="checkbox" value="egress"/> Egress Point</label>
        </div>
      </div>

      <div class="form-group" style="margin-bottom:.75rem">
        <label style="display:block;font-size:.75rem;color:#58a6ff;margin-bottom:.5rem;text-transform:uppercase;letter-spacing:.05em">Environment</label>
        <div id="annotate-labels-env" class="label-group">
          <label class="label-check"><input type="checkbox" value="production"/> Production</label>
          <label class="label-check"><input type="checkbox" value="staging"/> Staging</label>
          <label class="label-check"><input type="checkbox" value="development"/> Development</label>
          <label class="label-check"><input type="checkbox" value="test"/> Test</label>
          <label class="label-check"><input type="checkbox" value="deprecated"/> Deprecated</label>
        </div>
      </div>

      <div class="form-group">
        <label style="display:block;font-size:.75rem;color:#a371f7;margin-bottom:.5rem;text-transform:uppercase;letter-spacing:.05em">Priority</label>
        <div id="annotate-labels-pri" class="label-group">
          <label class="label-check"><input type="checkbox" value="p1"/> P1 - Immediate</label>
          <label class="label-check"><input type="checkbox" value="p2"/> P2 - Urgent</label>
          <label class="label-check"><input type="checkbox" value="p3"/> P3 - Normal</label>
          <label class="label-check"><input type="checkbox" value="monitor"/> Monitor</label>
        </div>
      </div>
    </div>
    <div class="modal-foot">
      <button class="btn btn-secondary modal-close">Cancel</button>
      <button class="btn btn-primary" id="annotate-save">Save</button>
    </div>
  </div>
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
      <div class="cleartext-head">[!] Cleartext Protocols Detected</div>
      <div id="cleartext-list"></div>
    </div>
    
    <!-- Top Risks -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">Top Risks</span>
        <a href="#" class="btn btn-ghost btn-sm" data-nav="entities">View All &gt;&gt;</a>
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
        <div class="view-toggle">
          <button class="btn btn-secondary btn-sm active" data-view="cards">= Cards</button>
          <button class="btn btn-secondary btn-sm" data-view="ports"># Ports</button>
          <button class="btn btn-secondary btn-sm" data-view="services">@ Services</button>
        </div>
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
          <option value="ckt">CKT / Mission Critical</option>
          <option value="tagged">All Tagged</option>
          <option value="admin">Admin Ports</option>
          <option value="cleartext">Has Cleartext</option>
          <option value="risk">High Risk (50+)</option>
          <option value="production">Production</option>
        </select>
      </div>
    </div>

    <!-- Card View (default) -->
    <div class="entity-grid" id="entity-grid">
      <xsl:for-each select="/nmaprun/host[status/@state='up']">
        <xsl:call-template name="entity-card"/>
      </xsl:for-each>
    </div>

    <!-- Aggregation Views (hidden by default) -->
    <div class="agg-view" id="port-agg-view" style="display:none;">
      <div class="agg-header">
        <h3>Port Distribution</h3>
        <span class="agg-subtitle">Click a port to filter hosts</span>
      </div>
      <div class="agg-grid" id="port-agg-grid"></div>
    </div>

    <div class="agg-view" id="service-agg-view" style="display:none;">
      <div class="agg-header">
        <h3>Service Distribution</h3>
        <span class="agg-subtitle">Click a service to filter hosts</span>
      </div>
      <div class="agg-grid" id="service-agg-grid"></div>
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
      <div class="entity-icon" data-os-icon="">[=]</div>
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
     TOPOLOGY SECTION
     ============================================ -->
<xsl:template name="topology-section">
  <section class="section" data-section="topology">
    <div class="section-header">
      <h2 class="section-title">Network Topology</h2>
      <div class="flex gap-2">
        <select id="topo-layout" class="btn btn-secondary btn-sm" style="appearance:auto;">
          <option value="hierarchical">Hierarchical</option>
          <option value="radial">Radial</option>
        </select>
        <button class="btn btn-secondary btn-sm" id="topo-refresh">Refresh</button>
      </div>
    </div>

    <div class="card">
      <div class="topo-controls">
        <span style="color:#8b949e;font-size:.8rem;">Showing traceroute paths from scan data</span>
      </div>
      <div class="topo-container" id="topo-container">
        <div class="topo-canvas" id="topo-canvas"></div>
      </div>
      <div class="topo-legend">
        <div class="topo-legend-item">
          <div class="topo-legend-dot" style="border-color:#238636;background:rgba(35,134,54,.2)"></div>
          <span>Scanner</span>
        </div>
        <div class="topo-legend-item">
          <div class="topo-legend-dot" style="border-color:#58a6ff;background:rgba(88,166,255,.2)"></div>
          <span>Target</span>
        </div>
        <div class="topo-legend-item">
          <div class="topo-legend-dot" style="border-color:#8b949e;background:#21262d"></div>
          <span>Hop</span>
        </div>
      </div>
    </div>

    <div class="card mt-4">
      <div class="card-header">
        <span class="card-title">Traceroute Details</span>
      </div>
      <div class="card-body" id="topo-details">
        <p style="color:#8b949e;">Select a host to see traceroute details</p>
      </div>
    </div>
  </section>
</xsl:template>

<!-- ============================================
     TIMELINE SECTION
     ============================================ -->
<xsl:template name="timeline-section">
  <section class="section" data-section="timeline">
    <div class="section-header">
      <h2 class="section-title">Scan Timeline</h2>
      <button class="btn btn-primary btn-sm" id="timeline-add">+ Add Scan</button>
    </div>

    <div class="card">
      <div class="card-body">
        <p style="color:#8b949e;margin-bottom:1rem;">Track changes across multiple scans over time.</p>
        <div class="timeline-container">
          <div class="timeline-track" id="timeline-track">
            <!-- Current scan -->
            <div class="timeline-scan active" data-scan="current">
              <div class="timeline-scan-date"><xsl:value-of select="substring(/nmaprun/@startstr, 1, 10)"/></div>
              <div class="timeline-scan-time"><xsl:value-of select="substring(/nmaprun/@startstr, 12)"/></div>
              <div class="timeline-scan-stats">
                <span class="timeline-scan-stat"><xsl:value-of select="/nmaprun/runstats/hosts/@up"/> hosts</span>
                <span class="timeline-scan-stat"><xsl:value-of select="count(/nmaprun/host/ports/port[state/@state='open'])"/> ports</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="card mt-4">
      <div class="card-header">
        <span class="card-title">Trend Analysis</span>
      </div>
      <div class="card-body">
        <div class="timeline-chart" id="timeline-chart">
          <p style="color:#8b949e;text-align:center;padding-top:4rem;">Add more scans to see trends</p>
        </div>
      </div>
    </div>

    <div class="card mt-4">
      <div class="card-header">
        <span class="card-title">Change Log</span>
      </div>
      <div class="card-body" id="timeline-changes">
        <p style="color:#8b949e;">No changes recorded yet</p>
      </div>
    </div>
  </section>
</xsl:template>

<!-- ============================================
     DIFF SECTION
     ============================================ -->
<xsl:template name="diff-section">
  <section class="section" data-section="diff">
    <div class="section-header">
      <h2 class="section-title">Scan Comparison</h2>
    </div>

    <div class="card" id="diff-upload-card">
      <div class="card-body">
        <p style="color:#8b949e;margin-bottom:1rem;">Load a comparison scan to see what changed between scans.</p>
        <div class="drop-zone" id="diff-drop-zone">
          <div style="font-size:2rem;margin-bottom:1rem;">&lt;&gt;</div>
          <div class="drop-zone-text">Drop comparison scan here</div>
          <div class="drop-zone-hint">Nmap XML format</div>
          <input type="file" id="diff-file-input" accept=".xml" style="display:none;"/>
        </div>
      </div>
    </div>

    <div id="diff-results" class="hidden">
      <div class="stats" id="diff-stats"></div>

      <div class="card">
        <div class="card-header">
          <span class="card-title">New Hosts</span>
          <span class="badge badge-low" id="diff-new-count">0</span>
        </div>
        <div class="card-body" id="diff-new-hosts">
          <p style="color:#8b949e;">No new hosts</p>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <span class="card-title">Removed Hosts</span>
          <span class="badge badge-critical" id="diff-removed-count">0</span>
        </div>
        <div class="card-body" id="diff-removed-hosts">
          <p style="color:#8b949e;">No removed hosts</p>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <span class="card-title">Changed Hosts</span>
          <span class="badge badge-high" id="diff-changed-count">0</span>
        </div>
        <div class="card-body" id="diff-changed-hosts">
          <p style="color:#8b949e;">No changes detected</p>
        </div>
      </div>
    </div>
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
        <p style="font-size:.8rem;color:#8b949e;margin-bottom:.75rem">Scan Data</p>
        <div class="flex flex-wrap gap-2">
          <button class="btn btn-secondary" data-export="csv">Export CSV</button>
          <button class="btn btn-secondary" data-export="json">Export JSON</button>
          <button class="btn btn-secondary" data-export="html">Export Report</button>
          <button class="btn btn-secondary" data-export="cpe">Export CPEs</button>
        </div>
        <div class="mt-4" style="margin-bottom:.75rem">
          <label style="display:flex;align-items:center;gap:.5rem;font-size:.875rem;">
            <input type="checkbox" id="export-tags" checked="checked"/> Include tags and annotations in CSV/JSON
          </label>
        </div>
        <p style="font-size:.8rem;color:#8b949e;margin-bottom:.75rem;margin-top:1rem;padding-top:1rem;border-top:1px solid #21262d">Asset Tags Only</p>
        <div class="flex flex-wrap gap-2">
          <button class="btn btn-primary" data-export="tags">Export Tags (JSON)</button>
        </div>
        <p style="font-size:.75rem;color:#8b949e;margin-top:.5rem">Tags are keyed by MAC address for portability across scans</p>
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
          <div style="font-size:2rem;margin-bottom:1rem;">[*]</div>
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
      "osFingerprint": "<xsl:value-of select="os/osfingerprint/@fingerprint"/>",
      "ports": [<xsl:for-each select="ports/port">{"port":<xsl:value-of select="@portid"/>,"proto":"<xsl:value-of select="@protocol"/>","state":"<xsl:value-of select="state/@state"/>","svc":"<xsl:value-of select="service/@name"/>","product":"<xsl:value-of select="translate(service/@product, '&quot;', &quot;'&quot;)"/>","version":"<xsl:value-of select="service/@version"/>","cpe":"<xsl:value-of select="service/cpe"/>","fp":"<xsl:value-of select="service/@servicefp"/>","scripts":[<xsl:for-each select="script">{"id":"<xsl:value-of select="@id"/>","output":"<xsl:value-of select="translate(translate(@output, '&quot;', &quot;'&quot;), '&#10;&#13;', '  ')"/>"}<xsl:if test="position()!=last()">,</xsl:if></xsl:for-each>]}<xsl:if test="position()!=last()">,</xsl:if></xsl:for-each>],
      "hostscripts": [<xsl:for-each select="hostscript/script">{"id":"<xsl:value-of select="@id"/>","output":"<xsl:value-of select="translate(translate(@output, '&quot;', &quot;'&quot;), '&#10;&#13;', '  ')"/>"}<xsl:if test="position()!=last()">,</xsl:if></xsl:for-each>],
      "trace": [<xsl:for-each select="trace/hop">{"ttl":<xsl:value-of select="@ttl"/>,"ip":"<xsl:value-of select="@ipaddr"/>","rtt":"<xsl:value-of select="@rtt"/>","host":"<xsl:value-of select="@host"/>"}<xsl:if test="position()!=last()">,</xsl:if></xsl:for-each>]
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
const RISK_WEIGHTS = {21:7,22:3,23:10,25:4,53:3,80:2,110:6,111:5,135:6,139:7,143:6,161:7,389:6,443:1,445:8,512:9,513:9,514:9,1433:8,1521:8,3306:7,3389:7,5432:6,5900:7,6379:9,27017:8,2375:10,2376:8,4243:10,6443:10,10250:10,10255:6,2379:10,8500:8,9200:8,5985:8,5986:8,623:10,1099:8,10000:7,9000:8,8291:8,50000:8,11211:8};

// Admin/Management ports by category - high risk if exposed
const ADMIN_PORTS = {
  // Container/Orchestration
  2375: {name:'Docker API',cat:'container',sev:'critical',desc:'Unauthenticated Docker - full host compromise'},
  2376: {name:'Docker TLS',cat:'container',sev:'high',desc:'Docker with TLS - verify auth'},
  4243: {name:'Docker API',cat:'container',sev:'critical',desc:'Legacy Docker API - full host compromise'},
  2377: {name:'Docker Swarm',cat:'container',sev:'high',desc:'Swarm cluster management'},
  6443: {name:'Kubernetes API',cat:'container',sev:'critical',desc:'K8s API - cluster admin'},
  10250: {name:'Kubelet',cat:'container',sev:'critical',desc:'Kubelet API - node compromise'},
  10255: {name:'Kubelet RO',cat:'container',sev:'medium',desc:'Kubelet read-only'},
  8443: {name:'K8s Dashboard',cat:'container',sev:'high',desc:'K8s dashboard'},
  2379: {name:'etcd',cat:'container',sev:'critical',desc:'etcd - K8s secrets exposure'},
  2380: {name:'etcd peer',cat:'container',sev:'high',desc:'etcd peer port'},
  9000: {name:'Portainer',cat:'container',sev:'high',desc:'Docker/K8s mgmt UI'},
  5000: {name:'Registry',cat:'container',sev:'medium',desc:'Docker registry'},
  // Network Infrastructure
  4786: {name:'Smart Install',cat:'network',sev:'critical',desc:'Cisco Smart Install - RCE'},
  8291: {name:'Winbox',cat:'network',sev:'high',desc:'MikroTik router admin'},
  161: {name:'SNMP',cat:'network',sev:'high',desc:'SNMP - default community strings'},
  162: {name:'SNMP Trap',cat:'network',sev:'medium',desc:'SNMP trap receiver'},
  830: {name:'NETCONF',cat:'network',sev:'high',desc:'NETCONF SSH - network config'},
  6030: {name:'Arista eAPI',cat:'network',sev:'high',desc:'Arista eAPI'},
  // Out-of-Band Management
  623: {name:'IPMI',cat:'oob',sev:'critical',desc:'IPMI/BMC - hardware control'},
  5900: {name:'VNC',cat:'oob',sev:'high',desc:'VNC - often weak/no auth'},
  5901: {name:'VNC:1',cat:'oob',sev:'high',desc:'VNC display :1'},
  443: {name:'iLO/iDRAC',cat:'oob',sev:'high',desc:'Check for BMC on :443'},
  17988: {name:'iLO',cat:'oob',sev:'high',desc:'HP iLO alt port'},
  17990: {name:'iLO',cat:'oob',sev:'high',desc:'HP iLO virtual media'},
  // Windows Admin
  5985: {name:'WinRM HTTP',cat:'windows',sev:'high',desc:'Windows Remote Mgmt'},
  5986: {name:'WinRM HTTPS',cat:'windows',sev:'high',desc:'WinRM over TLS'},
  3389: {name:'RDP',cat:'windows',sev:'medium',desc:'Remote Desktop'},
  445: {name:'SMB',cat:'windows',sev:'high',desc:'SMB - check for vulns'},
  135: {name:'RPC',cat:'windows',sev:'medium',desc:'MS-RPC endpoint mapper'},
  // DevOps/CI-CD/Orchestration
  50000: {name:'Jenkins Agent',cat:'devops',sev:'high',desc:'Jenkins agent - code exec'},
  8080: {name:'Jenkins/Tomcat',cat:'devops',sev:'medium',desc:'Common admin UI port'},
  8081: {name:'Nexus/Artifactory',cat:'devops',sev:'medium',desc:'Artifact repository'},
  9090: {name:'Prometheus',cat:'devops',sev:'medium',desc:'Prometheus metrics'},
  3000: {name:'Grafana',cat:'devops',sev:'medium',desc:'Grafana dashboard'},
  8500: {name:'Consul',cat:'devops',sev:'high',desc:'Consul HTTP API'},
  8200: {name:'Vault',cat:'devops',sev:'critical',desc:'HashiCorp Vault'},
  8140: {name:'Puppet',cat:'devops',sev:'high',desc:'Puppet master'},
  4505: {name:'SaltStack Pub',cat:'devops',sev:'critical',desc:'Salt master publish'},
  4506: {name:'SaltStack Req',cat:'devops',sev:'critical',desc:'Salt master request'},
  443: {name:'Ansible Tower',cat:'devops',sev:'high',desc:'Check for AWX/Tower'},
  8065: {name:'Mattermost',cat:'devops',sev:'medium',desc:'Mattermost chat'},
  8111: {name:'TeamCity',cat:'devops',sev:'high',desc:'TeamCity CI server'},
  8929: {name:'GitLab SSH',cat:'devops',sev:'medium',desc:'GitLab SSH'},
  9418: {name:'Git',cat:'devops',sev:'medium',desc:'Git protocol'},
  8082: {name:'ArgoCD',cat:'devops',sev:'high',desc:'ArgoCD server'},
  7472: {name:'Terraform Ent',cat:'devops',sev:'high',desc:'Terraform Enterprise'},
  10350: {name:'Tilt',cat:'devops',sev:'medium',desc:'Tilt dev server'},
  6660: {name:'Rundeck',cat:'devops',sev:'high',desc:'Rundeck automation'},
  // Databases
  6379: {name:'Redis',cat:'database',sev:'high',desc:'Redis - no auth default'},
  27017: {name:'MongoDB',cat:'database',sev:'high',desc:'MongoDB - check auth'},
  9200: {name:'Elasticsearch',cat:'database',sev:'high',desc:'ES HTTP API'},
  9300: {name:'ES Transport',cat:'database',sev:'high',desc:'ES cluster'},
  11211: {name:'Memcached',cat:'database',sev:'high',desc:'Memcached - no auth'},
  5601: {name:'Kibana',cat:'database',sev:'medium',desc:'Kibana UI'},
  // Remote Access
  1099: {name:'Java RMI',cat:'remote',sev:'high',desc:'RMI - deser attacks'},
  9001: {name:'Supervisor',cat:'remote',sev:'medium',desc:'Supervisord XML-RPC'},
  10000: {name:'Webmin',cat:'remote',sev:'high',desc:'Webmin panel'},
  // Suspicious
  4444: {name:'Metasploit',cat:'suspicious',sev:'critical',desc:'MSF handler - active attack?'},
  1337: {name:'Elite',cat:'suspicious',sev:'high',desc:'Common backdoor port'},
  31337: {name:'Back Orifice',cat:'suspicious',sev:'critical',desc:'Classic backdoor'}
};

const OS_PATTERNS = {win:/windows|microsoft/i,lin:/linux|ubuntu|debian|centos|redhat/i,net:/cisco|juniper|fortinet/i};
const MAX_IMPORT_SIZE = 10 * 1024 * 1024; // 10MB max file size

// === ASSET IDENTIFICATION ===
// Use MAC as primary key (stable), fall back to IP if no MAC
function getAssetKey(host) {
  if (host.mac) return 'mac:' + host.mac.toUpperCase();
  return 'ip:' + host.ip;
}

function getAssetKeyByIp(ip) {
  if (!state.data?.hosts) return 'ip:' + ip;
  const host = state.data.hosts.find(h => h.ip === ip);
  return host ? getAssetKey(host) : 'ip:' + ip;
}

function getHostByAssetKey(key) {
  if (!state.data?.hosts) return null;
  if (key.startsWith('mac:')) {
    const mac = key.slice(4);
    return state.data.hosts.find(h => h.mac && h.mac.toUpperCase() === mac);
  }
  const ip = key.slice(3);
  return state.data.hosts.find(h => h.ip === ip);
}

// Get tags for a host (handles both old IP-based and new MAC-based)
function getAssetTags(host) {
  const key = getAssetKey(host);
  const tags = state.tags[key];
  // Migration: also check old IP-based tags
  if (!tags && state.tags[host.ip]) {
    return state.tags[host.ip];
  }
  return tags || { labels: [], owner: '', notes: '' };
}

// Set tags for a host using stable key
function setAssetTags(host, tags) {
  const key = getAssetKey(host);
  // Store current IP for reference/lookup
  state.tags[key] = { ...tags, lastIp: host.ip, lastSeen: new Date().toISOString() };
  // Remove old IP-based entry if migrating
  if (state.tags[host.ip] && key !== 'ip:' + host.ip) {
    delete state.tags[host.ip];
  }
  saveState();
}

// Migrate old tags format (IP -> MAC-based with structure)
function migrateTags() {
  if (!state.data?.hosts) return;
  const oldTags = { ...state.tags };
  let migrated = 0;

  Object.entries(oldTags).forEach(([key, value]) => {
    // Skip if already in new format (has 'mac:' or 'ip:' prefix)
    if (key.startsWith('mac:') || key.startsWith('ip:')) return;

    // Old format: key is IP, value is array of labels
    if (Array.isArray(value)) {
      const host = state.data.hosts.find(h => h.ip === key);
      if (host) {
        const newKey = getAssetKey(host);
        state.tags[newKey] = {
          labels: value,
          owner: '',
          notes: '',
          lastIp: key,
          lastSeen: new Date().toISOString()
        };
        delete state.tags[key];
        migrated++;
      }
    }
  });

  if (migrated > 0) {
    console.log('[NetIntel] Migrated', migrated, 'tags to MAC-based format');
    saveState();
  }
}

// === NSE SCRIPT PARSING ===
// Key scripts that provide valuable intel
const NSE_PARSERS = {
  'ssl-cert': (output) => {
    const info = {};
    const subjectMatch = output.match(/Subject: (.+?)(?:$|  )/);
    const issuerMatch = output.match(/Issuer: (.+?)(?:$|  )/);
    const validMatch = output.match(/Not valid after:\s*(\d{4}-\d{2}-\d{2})/);
    if (subjectMatch) info.subject = subjectMatch[1].trim();
    if (issuerMatch) info.issuer = issuerMatch[1].trim();
    if (validMatch) info.expires = validMatch[1];
    return { type: 'cert', icon: 'shield', ...info };
  },
  'http-title': (output) => {
    const title = output.replace(/^Title:\s*/, '').trim();
    return { type: 'http', icon: 'globe', title };
  },
  'http-server-header': (output) => {
    return { type: 'http', icon: 'server', server: output.trim() };
  },
  'smb-os-discovery': (output) => {
    const info = {};
    const osMatch = output.match(/OS: ([^\n]+)/);
    const compMatch = output.match(/Computer name: ([^\n]+)/);
    const domainMatch = output.match(/Domain name: ([^\n]+)/);
    if (osMatch) info.os = osMatch[1].trim();
    if (compMatch) info.computer = compMatch[1].trim();
    if (domainMatch) info.domain = domainMatch[1].trim();
    return { type: 'smb', icon: 'windows', ...info };
  },
  'ssh-hostkey': (output) => {
    const keys = [];
    const keyMatches = output.matchAll(/(\d+) ([\w-]+) ([^\s]+)/g);
    for (const m of keyMatches) {
      keys.push({ bits: m[1], algo: m[2], fingerprint: m[3].slice(0, 16) + '...' });
    }
    return { type: 'ssh', icon: 'key', keys: keys.slice(0, 3) };
  },
  'ftp-anon': (output) => {
    const anon = output.toLowerCase().includes('anonymous ftp login allowed');
    return { type: 'ftp', icon: 'warning', anonymous: anon, sev: anon ? 'high' : 'info' };
  },
  'ms-sql-info': (output) => {
    const info = {};
    const versionMatch = output.match(/Version:([^\n]+)/i);
    const instanceMatch = output.match(/Instance name:([^\n]+)/i);
    if (versionMatch) info.version = versionMatch[1].trim();
    if (instanceMatch) info.instance = instanceMatch[1].trim();
    return { type: 'mssql', icon: 'database', ...info };
  },
  'mysql-info': (output) => {
    const info = {};
    const versionMatch = output.match(/Version: ([^\n]+)/);
    if (versionMatch) info.version = versionMatch[1].trim();
    return { type: 'mysql', icon: 'database', ...info };
  }
};

// Scripts that indicate vulnerabilities
const VULN_SCRIPTS = ['smb-vuln-', 'ssl-heartbleed', 'ssl-poodle', 'ssl-ccs-injection', 'vulners', 'vulscan'];

// Get parsed NSE findings for a host
function getHostNseFindings(host) {
  const findings = [];
  const vulns = [];

  // Parse port scripts
  (host.ports || []).forEach(port => {
    (port.scripts || []).forEach(script => {
      // Check for vulnerability scripts
      if (VULN_SCRIPTS.some(v => script.id.startsWith(v) || script.id.includes(v))) {
        vulns.push({ port: port.port, script: script.id, output: script.output });
      }
      // Parse known scripts
      else if (NSE_PARSERS[script.id]) {
        const parsed = NSE_PARSERS[script.id](script.output);
        findings.push({ port: port.port, script: script.id, ...parsed });
      }
    });
  });

  // Parse host-level scripts
  (host.hostscripts || []).forEach(script => {
    if (VULN_SCRIPTS.some(v => script.id.startsWith(v) || script.id.includes(v))) {
      vulns.push({ port: null, script: script.id, output: script.output });
    }
    else if (NSE_PARSERS[script.id]) {
      const parsed = NSE_PARSERS[script.id](script.output);
      findings.push({ port: null, script: script.id, ...parsed });
    }
  });

  return { findings, vulns };
}

// Get all scripts for a host (raw, for details view)
function getHostAllScripts(host) {
  const scripts = [];
  (host.ports || []).forEach(port => {
    (port.scripts || []).forEach(script => {
      scripts.push({ port: port.port, ...script });
    });
  });
  (host.hostscripts || []).forEach(script => {
    scripts.push({ port: null, ...script });
  });
  return scripts;
}

// === SEARCH INDEXES ===
// Reverse indexes for fast lookups - built on data load
const searchIndex = {
  byPort: {},      // port -> [ip, ip, ...]
  byService: {},   // service -> [ip, ip, ...]
  byProduct: {},   // product -> [ip, ip, ...]
  byOs: {},        // os keyword -> [ip, ip, ...]
  byTag: {},       // tag -> [ip, ip, ...]
  byCve: {}        // cve -> [ip, ip, ...]
};

function buildSearchIndex() {
  // Reset indexes
  Object.keys(searchIndex).forEach(k => searchIndex[k] = {});

  if (!state.data?.hosts) return;

  state.data.hosts.filter(h => h.status === 'up').forEach(host => {
    const ip = host.ip;

    // Index by port
    host.ports.filter(p => p.state === 'open').forEach(port => {
      const portKey = String(port.port);
      if (!searchIndex.byPort[portKey]) searchIndex.byPort[portKey] = [];
      searchIndex.byPort[portKey].push(ip);

      // Index by service
      if (port.svc) {
        const svc = port.svc.toLowerCase();
        if (!searchIndex.byService[svc]) searchIndex.byService[svc] = [];
        if (!searchIndex.byService[svc].includes(ip)) searchIndex.byService[svc].push(ip);
      }

      // Index by product
      if (port.product) {
        const prod = port.product.toLowerCase();
        if (!searchIndex.byProduct[prod]) searchIndex.byProduct[prod] = [];
        if (!searchIndex.byProduct[prod].includes(ip)) searchIndex.byProduct[prod].push(ip);
      }
    });

    // Index by OS
    if (host.os && host.os[0] && host.os[0].name) {
      const osName = host.os[0].name.toLowerCase();
      const osWords = osName.split(/\s+/);
      osWords.forEach(word => {
        if (word.length > 2) {
          if (!searchIndex.byOs[word]) searchIndex.byOs[word] = [];
          if (!searchIndex.byOs[word].includes(ip)) searchIndex.byOs[word].push(ip);
        }
      });
    }

    // Index by tags
    const tagData = getAssetTags(host);
    const labels = Array.isArray(tagData) ? tagData : (tagData.labels || []);
    labels.forEach(tag => {
      if (!searchIndex.byTag[tag]) searchIndex.byTag[tag] = [];
      searchIndex.byTag[tag].push(ip);
    });

    // Index by CVE (if vuln db loaded)
    const cves = getHostCVEs(host);
    cves.forEach(cve => {
      const cveId = cve.cve.toLowerCase();
      if (!searchIndex.byCve[cveId]) searchIndex.byCve[cveId] = [];
      searchIndex.byCve[cveId].push(ip);
    });
  });

  console.log('[NetIntel] Search index built:',
    Object.keys(searchIndex.byPort).length, 'ports,',
    Object.keys(searchIndex.byService).length, 'services,',
    Object.keys(searchIndex.byTag).length, 'tags');
}

// === SEARCH QUERY PARSER ===
// Supports: port:22, service:ssh, os:windows, tag:ckt, cve:CVE-2021-*, owner:john, ip:192.168.*
function parseSearchQuery(query) {
  const terms = [];
  const fieldPattern = /(\w+):("[^"]+"|[\S]+)/g;
  let match;
  let remaining = query;

  while ((match = fieldPattern.exec(query)) !== null) {
    const field = match[1].toLowerCase();
    let value = match[2].replace(/^"|"$/g, '').toLowerCase();
    const isWildcard = value.includes('*');
    terms.push({ field, value, isWildcard });
    remaining = remaining.replace(match[0], '');
  }

  // Remaining text is freeform search
  const freeform = remaining.trim().toLowerCase();
  if (freeform) {
    terms.push({ field: 'text', value: freeform, isWildcard: freeform.includes('*') });
  }

  return terms;
}

function matchesSearchTerms(host, terms) {
  if (terms.length === 0) return true;

  return terms.every(term => {
    const { field, value, isWildcard } = term;
    const pattern = isWildcard ? new RegExp('^' + value.replace(/\*/g, '.*') + '$', 'i') : null;
    const matches = (str) => isWildcard ? pattern.test(str) : str.toLowerCase().includes(value);

    switch (field) {
      case 'port':
        return host.ports.some(p => p.state === 'open' && matches(String(p.port)));

      case 'service':
      case 'svc':
        return host.ports.some(p => p.state === 'open' && p.svc && matches(p.svc));

      case 'product':
        return host.ports.some(p => p.product && matches(p.product));

      case 'os':
        return host.os && host.os[0] && matches(host.os[0].name);

      case 'ip':
        return matches(host.ip);

      case 'host':
      case 'hostname':
        return host.hostname && matches(host.hostname);

      case 'mac':
        return host.mac && matches(host.mac);

      case 'tag':
      case 'label':
        const tagData = getAssetTags(host);
        const labels = Array.isArray(tagData) ? tagData : (tagData.labels || []);
        return labels.some(l => matches(l));

      case 'owner':
        const ownerData = getAssetTags(host);
        return ownerData.owner && matches(ownerData.owner);

      case 'cve':
        const cves = getHostCVEs(host);
        return cves.some(c => matches(c.cve));

      case 'admin':
        if (value === 'true' || value === 'yes' || value === '*') {
          return host.ports.some(p => p.state === 'open' && ADMIN_PORTS[p.port]);
        }
        return host.ports.some(p => p.state === 'open' && ADMIN_PORTS[p.port] &&
          (matches(ADMIN_PORTS[p.port].name) || matches(ADMIN_PORTS[p.port].cat)));

      case 'risk':
        const risk = calculateRisk(host);
        if (value.startsWith('>')) return risk > parseInt(value.slice(1));
        if (value.startsWith('<')) return risk < parseInt(value.slice(1));
        return risk >= parseInt(value);

      case 'text':
      default:
        // Freeform: search IP, hostname, ports, services, OS
        const searchText = [
          host.ip,
          host.hostname || '',
          host.ports.filter(p => p.state === 'open').map(p => `${p.port} ${p.svc || ''} ${p.product || ''}`).join(' '),
          host.os && host.os[0] ? host.os[0].name : ''
        ].join(' ').toLowerCase();
        return matches(searchText);
    }
  });
}

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
  search: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="m21 21-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 5.196a7.5 7.5 0 0 0 10.607 10.607Z" /></svg>',
  target: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M12 12.75c1.148 0 2.278.08 3.383.237 1.037.146 1.866.966 1.866 2.013 0 3.728-2.35 6.75-5.25 6.75S6.75 18.728 6.75 15c0-1.046.83-1.867 1.866-2.013A24.204 24.204 0 0 1 12 12.75Z" /></svg>',
  network: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M13.19 8.688a4.5 4.5 0 0 1 1.242 7.244l-4.5 4.5a4.5 4.5 0 0 1-6.364-6.364l1.757-1.757m13.35-.622 1.757-1.757a4.5 4.5 0 0 0-6.364-6.364l-4.5 4.5a4.5 4.5 0 0 0 1.242 7.244" /></svg>',
  chevronDown: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="m19.5 8.25-7.5 7.5-7.5-7.5" /></svg>',
  magnify: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="m21 21-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 5.196a7.5 7.5 0 0 0 10.607 10.607Z" /></svg>'
};

// Helper to render icon
function icon(name, cls = '') {
  return `<span class="icon ${cls}">${ICONS[name] || ''}</span>`;
}

// =============================================================================
// REACTIVE STORE - Lightweight state management (~50 lines)
// =============================================================================
function createStore(initialState = {}) {
  const listeners = new Map();
  let state = { ...initialState };

  return {
    // Get current state or specific key
    get(key) {
      return key ? state[key] : { ...state };
    },

    // Set state and notify listeners
    set(key, value) {
      const oldValue = state[key];
      if (oldValue === value) return;

      state[key] = value;

      // Notify key-specific listeners
      if (listeners.has(key)) {
        listeners.get(key).forEach(fn => fn(value, oldValue));
      }
      // Notify wildcard listeners
      if (listeners.has('*')) {
        listeners.get('*').forEach(fn => fn(state, key));
      }
    },

    // Batch update multiple keys
    update(updates) {
      Object.entries(updates).forEach(([key, value]) => {
        this.set(key, value);
      });
    },

    // Subscribe to state changes
    subscribe(key, callback) {
      if (!listeners.has(key)) {
        listeners.set(key, new Set());
      }
      listeners.get(key).add(callback);

      // Return unsubscribe function
      return () => listeners.get(key).delete(callback);
    },

    // Get full state for persistence
    toJSON() {
      return { ...state };
    }
  };
}

// =============================================================================
// ROUTER - Hash-based SPA routing (~60 lines)
// =============================================================================
function createRouter() {
  const routes = new Map();
  let currentRoute = null;

  // Parse hash into route object
  function parseHash(hash) {
    const clean = (hash || '').replace(/^#\/?/, '');
    const [path, query] = clean.split('?');
    const segments = path.split('/').filter(Boolean);

    return {
      path: '/' + segments.join('/'),
      segments,
      section: segments[0] || 'dashboard',
      param: segments[1] || null,
      query: Object.fromEntries(new URLSearchParams(query || ''))
    };
  }

  // Match route against registered patterns
  function matchRoute(route) {
    for (const [pattern, handler] of routes) {
      const patternParts = pattern.split('/').filter(Boolean);
      const routeParts = route.segments;

      if (patternParts.length !== routeParts.length) continue;

      const params = {};
      let match = true;

      for (let i = 0; i < patternParts.length; i++) {
        if (patternParts[i].startsWith(':')) {
          params[patternParts[i].slice(1)] = routeParts[i];
        } else if (patternParts[i] !== routeParts[i]) {
          match = false;
          break;
        }
      }

      if (match) return { handler, params };
    }
    return null;
  }

  // Handle route change
  function handleRoute() {
    const route = parseHash(location.hash);
    const matched = matchRoute(route);

    currentRoute = route;

    if (matched) {
      matched.handler({ ...route, params: matched.params });
    } else {
      // Default: navigate to section
      navigateToSection(route.section, route.param);
    }
  }

  return {
    // Register a route handler
    on(pattern, handler) {
      routes.set(pattern, handler);
      return this;
    },

    // Navigate to a path
    go(path, replace = false) {
      const newHash = '#' + path.replace(/^\//, '');
      if (replace) {
        history.replaceState(null, '', newHash);
      } else {
        history.pushState(null, '', newHash);
      }
      handleRoute();
    },

    // Get current route
    current() {
      return currentRoute;
    },

    // Initialize router
    init() {
      window.addEventListener('hashchange', handleRoute);
      window.addEventListener('popstate', handleRoute);
      // Handle initial route
      if (location.hash) {
        handleRoute();
      }
      return this;
    }
  };
}

// =============================================================================
// APP STATE & ROUTER INSTANCES
// =============================================================================
const store = createStore({
  data: null,
  tags: {},
  vulnDb: null,
  currentSection: 'dashboard',
  selectedHost: null,
  filter: 'all',
  groupBy: 'none',
  subnetMask: 24
});

const router = createRouter();

// Legacy state reference (for gradual migration)
let state = {
  get data() { return store.get('data'); },
  set data(v) { store.set('data', v); },
  get tags() { return store.get('tags'); },
  set tags(v) { store.set('tags', v); },
  get vulnDb() { return store.get('vulnDb'); },
  set vulnDb(v) { store.set('vulnDb', v); }
};

// Subnet mask from store
let subnetMask = 24;
store.subscribe('subnetMask', (v) => { subnetMask = v; });

// === INIT ===
document.addEventListener('DOMContentLoaded', () => {
  loadState(); // Also loads scan data
  migrateTags(); // Convert old IP-based tags to MAC-based
  initIcons();
  initNav();
  initModals();
  initContextMenu();
  initDropZones();
  initFilters();
  initRouter();
  render();
  console.log('[NetIntel] Initialized with', state.data?.hosts?.length || 0, 'hosts');
});

// Initialize router with routes
function initRouter() {
  router
    // Section routes
    .on('dashboard', () => navigateToSection('dashboard'))
    .on('entities', ({ query }) => {
      navigateToSection('entities');
      // Apply filter state from URL query params
      if (query) {
        applyUrlFilterState(query);
      }
    })
    .on('entities/:ip', ({ params, query }) => {
      navigateToSection('entities');
      if (query) applyUrlFilterState(query);
      selectHost(params.ip);
    })
    .on('topology', () => navigateToSection('topology'))
    .on('topology/:ip', ({ params }) => {
      navigateToSection('topology');
      showNodeDetails({ id: params.ip, type: 'target', host: state.data.hosts.find(h => h.ip === params.ip) });
    })
    .on('timeline', () => navigateToSection('timeline'))
    .on('cleartext', () => navigateToSection('cleartext'))
    .on('diff', () => navigateToSection('diff'))
    .on('sources', () => navigateToSection('sources'))
    .init();

  // If no hash, don't navigate (stay on dashboard)
  if (!location.hash) {
    history.replaceState(null, '', '#/dashboard');
  }
}

// Navigate to section (called by router)
function navigateToSection(section, param = null) {
  store.set('currentSection', section);
  store.set('selectedHost', param);

  // Update nav UI
  document.querySelectorAll('[data-nav]').forEach(a => {
    a.classList.toggle('active', a.dataset.nav === section);
  });

  // Update section visibility
  document.querySelectorAll('[data-section]').forEach(s => {
    s.classList.toggle('active', s.dataset.section === section);
  });

  // Section-specific initialization
  if (section === 'cleartext') renderCleartext();
  if (section === 'topology') { initTopology(); renderTopology(); }
  if (section === 'timeline') { initTimeline(); renderTimeline(); }
}

// Select and highlight a specific host
function selectHost(ip) {
  const host = state.data.hosts.find(h => h.ip === ip);
  if (!host) return;

  store.set('selectedHost', ip);

  // Scroll to and highlight the entity card
  const card = document.querySelector(`.entity[data-ip="${ip}"]`);
  if (card) {
    card.scrollIntoView({ behavior: 'smooth', block: 'center' });
    card.classList.add('selected');
    setTimeout(() => card.classList.remove('selected'), 2000);
  }
}

// Replace Unicode symbols with SVG icons
function initIcons() {
  const NAV_ICONS = {
    'dashboard': 'chart',
    'entities': 'server',
    'topology': 'network',
    'timeline': 'chart',
    'cleartext': 'warning',
    'diff': 'magnify',
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
    el.addEventListener('click', e => { e.preventDefault(); router.go(el.dataset.nav); });
  });
  document.querySelectorAll('[data-action]').forEach(el => {
    el.addEventListener('click', e => { e.preventDefault(); handleAction(el.dataset.action); });
  });
}

function handleAction(action) {
  if (action === 'import') document.getElementById('import-modal').classList.add('active');
  else if (action === 'export') document.getElementById('export-modal').classList.add('active');
  else if (action === 'vuln-db') document.getElementById('vuln-modal').classList.add('active');
  else if (action === 'share') {
    const url = getShareableUrl();
    navigator.clipboard.writeText(url).then(() => {
      showToast('Link copied to clipboard');
    }).catch(() => {
      // Fallback for older browsers
      prompt('Copy this link:', url);
    });
  }
}

// Toast notifications
function showToast(message, duration = 3000) {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.style.cssText = 'position:fixed;bottom:20px;right:20px;z-index:9999';
    document.body.appendChild(container);
  }
  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.textContent = message;
  toast.style.cssText = 'background:#238636;color:#fff;padding:.75rem 1.25rem;border-radius:6px;margin-top:.5rem;animation:fadeIn .2s;font-size:.875rem';
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity .2s';
    setTimeout(() => toast.remove(), 200);
  }, duration);
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
  let targetHost = null;

  document.addEventListener('contextmenu', e => {
    const entity = e.target.closest('[data-ip]');
    if (entity) {
      e.preventDefault();
      targetIp = entity.dataset.ip;
      targetHost = state.data?.hosts?.find(h => h.ip === targetIp);
      menu.style.left = e.pageX + 'px';
      menu.style.top = e.pageY + 'px';
      menu.classList.add('active');
    }
  });

  document.addEventListener('click', () => menu.classList.remove('active'));

  // Handle label quick-tags
  menu.querySelectorAll('[data-tag]').forEach(btn => {
    btn.addEventListener('click', () => {
      if (!targetHost) return;
      const tag = btn.dataset.tag;
      const key = getAssetKey(targetHost);

      if (tag === 'clear') {
        delete state.tags[key];
        // Also delete old IP-based entry if exists
        if (state.tags[targetIp]) delete state.tags[targetIp];
      } else {
        let current = state.tags[key] || { labels: [], owner: '', notes: '' };
        // Handle old format migration
        if (Array.isArray(current)) current = { labels: current, owner: '', notes: '' };
        if (!current.labels) current.labels = [];
        if (!current.labels.includes(tag)) current.labels.push(tag);
        current.lastIp = targetIp;
        current.lastSeen = new Date().toISOString();
        state.tags[key] = current;
      }
      saveState();
      updateEntityTags();
      updateKeyTerrain();
    });
  });

  // Handle annotate action
  menu.querySelector('[data-action="annotate"]')?.addEventListener('click', () => {
    if (!targetHost) return;
    openAnnotationModal(targetHost);
  });
}

// === ANNOTATION MODAL ===
function openAnnotationModal(host) {
  const modal = document.getElementById('annotate-modal');
  if (!modal) return;

  const key = getAssetKey(host);
  const current = getAssetTags(host);
  const labels = Array.isArray(current) ? current : (current.labels || []);
  const owner = current.owner || '';
  const notes = current.notes || '';

  // Populate info
  const infoEl = document.getElementById('annotate-info');
  infoEl.innerHTML = `
    <div><strong>IP:</strong> ${host.ip}</div>
    ${host.hostname ? `<div><strong>Hostname:</strong> ${host.hostname}</div>` : ''}
    ${host.mac ? `<div><strong>MAC:</strong> ${host.mac}${host.macVendor ? ' (' + host.macVendor + ')' : ''}</div>` : ''}
    <div style="margin-top:.5rem;font-size:.75rem;color:#8b949e"><strong>Asset Key:</strong> ${key}</div>
  `;

  // Populate fields
  document.getElementById('annotate-owner').value = owner;
  document.getElementById('annotate-notes').value = notes;

  // Populate label checkboxes (all groups)
  modal.querySelectorAll('.label-group input[type="checkbox"]').forEach(cb => {
    cb.checked = labels.includes(cb.value);
  });

  // Setup save handler (remove old handlers first)
  const saveBtn = document.getElementById('annotate-save');
  const newSaveBtn = saveBtn.cloneNode(true);
  saveBtn.parentNode.replaceChild(newSaveBtn, saveBtn);

  newSaveBtn.addEventListener('click', () => {
    const newLabels = Array.from(modal.querySelectorAll('.label-group input:checked')).map(cb => cb.value);
    const newOwner = document.getElementById('annotate-owner').value.trim();
    const newNotes = document.getElementById('annotate-notes').value.trim();

    setAssetTags(host, {
      labels: newLabels,
      owner: newOwner,
      notes: newNotes
    });

    updateEntityTags();
    updateKeyTerrain();
    modal.classList.remove('active');
  });

  modal.classList.add('active');
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

  // Diff comparison drop zone
  const diffDz = document.getElementById('diff-drop-zone');
  const diffFi = document.getElementById('diff-file-input');
  if (diffDz && diffFi) {
    diffDz.addEventListener('click', () => diffFi.click());
    diffDz.addEventListener('dragover', e => { e.preventDefault(); diffDz.classList.add('dragover'); });
    diffDz.addEventListener('dragleave', () => diffDz.classList.remove('dragover'));
    diffDz.addEventListener('drop', e => { e.preventDefault(); diffDz.classList.remove('dragover'); loadComparisonScan(e.dataTransfer.files[0]); });
    diffFi.addEventListener('change', () => { if (diffFi.files[0]) loadComparisonScan(diffFi.files[0]); });
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

// === SCAN DIFF ===
function loadComparisonScan(file) {
  if (!file) return;

  if (file.size > MAX_IMPORT_SIZE) {
    alert(`File too large. Maximum size is 10MB.`);
    return;
  }

  const reader = new FileReader();
  reader.onerror = () => alert('Error reading file.');
  reader.onload = e => {
    try {
      const parser = new DOMParser();
      const doc = parser.parseFromString(e.target.result, 'text/xml');
      if (!doc.querySelector('nmaprun')) {
        alert('Not a valid Nmap XML file');
        return;
      }

      const comparisonHosts = parseNmapXml(doc);
      const diff = computeDiff(state.data.hosts, comparisonHosts);
      renderDiff(diff, file.name);

      console.log('[NetIntel] Diff computed:', diff.summary);
    } catch (err) {
      console.error('[NetIntel] Diff error:', err);
      alert('Error parsing file: ' + err.message);
    }
  };
  reader.readAsText(file);
}

function computeDiff(baseHosts, comparisonHosts) {
  const baseMap = new Map(baseHosts.map(h => [h.ip, h]));
  const compMap = new Map(comparisonHosts.map(h => [h.ip, h]));

  const diff = {
    newHosts: [],      // In comparison but not in base
    removedHosts: [],  // In base but not in comparison
    changedHosts: [],  // In both but with differences
    unchangedCount: 0,
    summary: {}
  };

  // Find new and changed hosts
  comparisonHosts.forEach(compHost => {
    const baseHost = baseMap.get(compHost.ip);
    if (!baseHost) {
      diff.newHosts.push(compHost);
    } else {
      const changes = compareHosts(baseHost, compHost);
      if (changes.length > 0) {
        diff.changedHosts.push({ host: compHost, baseHost, changes });
      } else {
        diff.unchangedCount++;
      }
    }
  });

  // Find removed hosts
  baseHosts.forEach(baseHost => {
    if (!compMap.has(baseHost.ip)) {
      diff.removedHosts.push(baseHost);
    }
  });

  diff.summary = {
    new: diff.newHosts.length,
    removed: diff.removedHosts.length,
    changed: diff.changedHosts.length,
    unchanged: diff.unchangedCount
  };

  return diff;
}

function compareHosts(baseHost, compHost) {
  const changes = [];

  // Compare ports
  const basePorts = new Set(baseHost.ports.filter(p => p.state === 'open').map(p => `${p.port}/${p.proto}`));
  const compPorts = new Set(compHost.ports.filter(p => p.state === 'open').map(p => `${p.port}/${p.proto}`));

  // New ports
  compPorts.forEach(p => {
    if (!basePorts.has(p)) {
      changes.push({ type: 'port_added', port: p });
    }
  });

  // Closed ports
  basePorts.forEach(p => {
    if (!compPorts.has(p)) {
      changes.push({ type: 'port_removed', port: p });
    }
  });

  // OS changes
  const baseOs = baseHost.os && baseHost.os[0] ? baseHost.os[0].name : '';
  const compOs = compHost.os && compHost.os[0] ? compHost.os[0].name : '';
  if (baseOs !== compOs && (baseOs || compOs)) {
    changes.push({ type: 'os_changed', from: baseOs, to: compOs });
  }

  // Status changes
  if (baseHost.status !== compHost.status) {
    changes.push({ type: 'status_changed', from: baseHost.status, to: compHost.status });
  }

  return changes;
}

function renderDiff(diff, filename) {
  // Hide upload card, show results
  document.getElementById('diff-upload-card').classList.add('hidden');
  document.getElementById('diff-results').classList.remove('hidden');

  // Update stats
  const statsEl = document.getElementById('diff-stats');
  statsEl.innerHTML = `
    <div class="stat success">
      <div class="stat-label">New Hosts</div>
      <div class="stat-value">${diff.summary.new}</div>
      <div class="stat-detail">appeared in ${filename}</div>
    </div>
    <div class="stat danger">
      <div class="stat-label">Removed Hosts</div>
      <div class="stat-value">${diff.summary.removed}</div>
      <div class="stat-detail">no longer present</div>
    </div>
    <div class="stat warning">
      <div class="stat-label">Changed Hosts</div>
      <div class="stat-value">${diff.summary.changed}</div>
      <div class="stat-detail">port or service changes</div>
    </div>
    <div class="stat info">
      <div class="stat-label">Unchanged</div>
      <div class="stat-value">${diff.summary.unchanged}</div>
      <div class="stat-detail">no differences</div>
    </div>
  `;

  // Update counts
  document.getElementById('diff-new-count').textContent = diff.summary.new;
  document.getElementById('diff-removed-count').textContent = diff.summary.removed;
  document.getElementById('diff-changed-count').textContent = diff.summary.changed;

  // Render new hosts
  const newHostsEl = document.getElementById('diff-new-hosts');
  newHostsEl.innerHTML = diff.newHosts.length ? diff.newHosts.map(h => `
    <div class="diff-item">
      <span class="diff-ip">${h.ip}</span>
      <span class="diff-hostname">${h.hostname || ''}</span>
      <span class="diff-badge new">NEW</span>
      <div class="ports">${h.ports.filter(p => p.state === 'open').slice(0, 5).map(p =>
        `<span class="port open">${p.port}/${p.proto}</span>`
      ).join('')}</div>
    </div>
  `).join('') : '<p style="color:#8b949e;">No new hosts detected</p>';

  // Render removed hosts
  const removedHostsEl = document.getElementById('diff-removed-hosts');
  removedHostsEl.innerHTML = diff.removedHosts.length ? diff.removedHosts.map(h => `
    <div class="diff-item">
      <span class="diff-ip">${h.ip}</span>
      <span class="diff-hostname">${h.hostname || ''}</span>
      <span class="diff-badge removed">REMOVED</span>
    </div>
  `).join('') : '<p style="color:#8b949e;">No hosts removed</p>';

  // Render changed hosts
  const changedHostsEl = document.getElementById('diff-changed-hosts');
  changedHostsEl.innerHTML = diff.changedHosts.length ? diff.changedHosts.map(({ host, changes }) => `
    <div class="diff-item" style="flex-direction:column;align-items:stretch;">
      <div style="display:flex;align-items:center;gap:1rem;">
        <span class="diff-ip">${host.ip}</span>
        <span class="diff-hostname">${host.hostname || ''}</span>
        <span class="diff-badge changed">${changes.length} change${changes.length !== 1 ? 's' : ''}</span>
      </div>
      <div class="diff-changes">
        ${changes.map(c => {
          if (c.type === 'port_added') return `<div class="diff-change added">${icon('check')} Port ${c.port} opened</div>`;
          if (c.type === 'port_removed') return `<div class="diff-change removed">${icon('xmark')} Port ${c.port} closed</div>`;
          if (c.type === 'os_changed') return `<div class="diff-change">OS: ${c.from || 'unknown'} -> ${c.to || 'unknown'}</div>`;
          if (c.type === 'status_changed') return `<div class="diff-change">Status: ${c.from} -> ${c.to}</div>`;
          return '';
        }).join('')}
      </div>
    </div>
  `).join('') : '<p style="color:#8b949e;">No changes detected</p>';
}

// === SUBNET UTILITIES ===
// Configurable subnet mask (default /24)
let subnetMask = 24;

// Calculate subnet info for a given mask
function getSubnetInfo(mask) {
  const hostBits = 32 - mask;
  return {
    mask,
    cidr: `/${mask}`,
    hosts: Math.pow(2, hostBits) - 2,
    networks: Math.pow(2, mask - 16) // networks in a /16
  };
}

// Get subnet key for an IP at given CIDR
function getSubnetKey(ip, cidr = subnetMask) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return 'other';

  const ipNum = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
  const maskBits = (0xFFFFFFFF << (32 - cidr)) >>> 0;
  const networkNum = (ipNum & maskBits) >>> 0;

  const netParts = [
    (networkNum >>> 24) & 0xFF,
    (networkNum >>> 16) & 0xFF,
    (networkNum >>> 8) & 0xFF,
    networkNum & 0xFF
  ];

  return `${netParts.join('.')}/${cidr}`;
}

// Available CIDR options for grouping
const CIDR_OPTIONS = [8, 16, 20, 24, 28];

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
    getKey: host => getSubnetKey(host.ip, subnetMask),
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
    filterEl.addEventListener('change', () => {
      applyFilterAndGroup();
      syncFilterToUrl();
    });
  }
  if (groupEl) {
    groupEl.addEventListener('change', () => {
      applyFilterAndGroup();
      syncFilterToUrl();
    });
  }

  // View toggle (Cards / Ports / Services)
  document.querySelectorAll('[data-view]').forEach(btn => {
    btn.addEventListener('click', () => {
      const view = btn.dataset.view;
      document.querySelectorAll('[data-view]').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      switchEntityView(view);
      syncFilterToUrl();
    });
  });
}

// Switch between Cards, Ports, and Services views
function switchEntityView(view) {
  const cardView = document.getElementById('entity-grid');
  const portView = document.getElementById('port-agg-view');
  const serviceView = document.getElementById('service-agg-view');

  cardView.style.display = view === 'cards' ? '' : 'none';
  portView.style.display = view === 'ports' ? '' : 'none';
  serviceView.style.display = view === 'services' ? '' : 'none';

  if (view === 'ports') renderPortAggregation();
  if (view === 'services') renderServiceAggregation();
}

// Render port aggregation view
function renderPortAggregation() {
  const grid = document.getElementById('port-agg-grid');
  if (!grid || !state.data?.hosts) return;

  // Aggregate ports across all hosts
  const portMap = {};
  state.data.hosts.filter(h => h.status === 'up').forEach(host => {
    host.ports.filter(p => p.state === 'open').forEach(p => {
      if (!portMap[p.port]) {
        portMap[p.port] = {
          port: p.port,
          service: p.svc || 'unknown',
          product: p.product || '',
          hosts: [],
          isAdmin: !!ADMIN_PORTS[p.port],
          isCleartext: !!CLEARTEXT[p.port]
        };
      }
      portMap[p.port].hosts.push(host.ip);
    });
  });

  // Sort by host count (descending)
  const sorted = Object.values(portMap).sort((a, b) => b.hosts.length - a.hosts.length);

  grid.innerHTML = sorted.map(p => {
    const adminInfo = ADMIN_PORTS[p.port];
    const cleartextInfo = CLEARTEXT[p.port];
    const severity = adminInfo?.sev === 'critical' ? 'critical' : (adminInfo ? 'warning' : (cleartextInfo ? 'cleartext' : ''));
    const hostPreview = p.hosts.slice(0, 3).join(', ') + (p.hosts.length > 3 ? ` +${p.hosts.length - 3} more` : '');

    return `
      <div class="agg-card ${severity}" data-port="${p.port}" title="${adminInfo?.desc || cleartextInfo || ''}">
        <div class="agg-card-header">
          <span class="agg-card-port">${p.port}</span>
          <span class="agg-card-count">${p.hosts.length} host${p.hosts.length !== 1 ? 's' : ''}</span>
        </div>
        <div class="agg-card-name">${p.service}${p.product ? ' - ' + p.product : ''}</div>
        <div class="agg-card-hosts">${hostPreview}</div>
      </div>
    `;
  }).join('');

  // Click to filter
  grid.querySelectorAll('.agg-card').forEach(card => {
    card.addEventListener('click', () => {
      const port = card.dataset.port;
      document.getElementById('search').value = 'port:' + port;
      document.getElementById('search').dispatchEvent(new Event('input'));
      document.querySelector('[data-view="cards"]').click();
    });
  });
}

// Render service aggregation view
function renderServiceAggregation() {
  const grid = document.getElementById('service-agg-grid');
  if (!grid || !state.data?.hosts) return;

  // Aggregate services across all hosts
  const svcMap = {};
  state.data.hosts.filter(h => h.status === 'up').forEach(host => {
    host.ports.filter(p => p.state === 'open' && p.svc).forEach(p => {
      const key = p.svc.toLowerCase();
      if (!svcMap[key]) {
        svcMap[key] = {
          service: p.svc,
          ports: new Set(),
          hosts: new Set(),
          products: new Set()
        };
      }
      svcMap[key].ports.add(p.port);
      svcMap[key].hosts.add(host.ip);
      if (p.product) svcMap[key].products.add(p.product);
    });
  });

  // Convert Sets and sort by host count
  const sorted = Object.values(svcMap)
    .map(s => ({
      ...s,
      ports: Array.from(s.ports),
      hosts: Array.from(s.hosts),
      products: Array.from(s.products)
    }))
    .sort((a, b) => b.hosts.length - a.hosts.length);

  grid.innerHTML = sorted.map(s => {
    const hostPreview = s.hosts.slice(0, 3).join(', ') + (s.hosts.length > 3 ? ` +${s.hosts.length - 3} more` : '');
    const portList = s.ports.slice(0, 5).join(', ') + (s.ports.length > 5 ? '...' : '');
    const isCritical = s.ports.some(p => ADMIN_PORTS[p]?.sev === 'critical');
    const hasAdmin = s.ports.some(p => ADMIN_PORTS[p]);
    const hasCleartext = s.ports.some(p => CLEARTEXT[p]);
    const severity = isCritical ? 'critical' : (hasAdmin ? 'warning' : (hasCleartext ? 'cleartext' : ''));

    return `
      <div class="agg-card ${severity}" data-service="${s.service}">
        <div class="agg-card-header">
          <span class="agg-card-port">${s.service}</span>
          <span class="agg-card-count">${s.hosts.length} host${s.hosts.length !== 1 ? 's' : ''}</span>
        </div>
        <div class="agg-card-name">Ports: ${portList}</div>
        <div class="agg-card-hosts">${hostPreview}</div>
      </div>
    `;
  }).join('');

  // Click to filter
  grid.querySelectorAll('.agg-card').forEach(card => {
    card.addEventListener('click', () => {
      const svc = card.dataset.service;
      document.getElementById('search').value = 'service:' + svc;
      document.getElementById('search').dispatchEvent(new Event('input'));
      document.querySelector('[data-view="cards"]').click();
    });
  });
}

// Apply filter state from URL query parameters
function applyUrlFilterState(query) {
  const filterEl = document.getElementById('entity-filter');
  const groupEl = document.getElementById('entity-group');
  const searchEl = document.getElementById('search');

  if (query.filter && filterEl) {
    filterEl.value = query.filter;
  }
  if (query.group && groupEl) {
    groupEl.value = query.group;
  }
  if (query.q && searchEl) {
    searchEl.value = query.q;
    // Trigger search
    searchEl.dispatchEvent(new Event('input'));
  }
  if (query.view && ['cards', 'ports', 'services'].includes(query.view)) {
    document.querySelector(`[data-view="${query.view}"]`)?.click();
  }

  // Apply after setting values
  setTimeout(() => applyFilterAndGroup(), 0);
}

// Sync current filter/search state to URL
function syncFilterToUrl() {
  const filterEl = document.getElementById('entity-filter');
  const groupEl = document.getElementById('entity-group');
  const searchEl = document.getElementById('search');
  const activeView = document.querySelector('[data-view].active')?.dataset.view;

  const filter = filterEl?.value || 'all';
  const group = groupEl?.value || 'none';
  const q = searchEl?.value || '';

  const params = new URLSearchParams();
  if (filter !== 'all') params.set('filter', filter);
  if (group !== 'none') params.set('group', group);
  if (q.trim()) params.set('q', q);
  if (activeView && activeView !== 'cards') params.set('view', activeView);

  const queryString = params.toString();
  const newHash = '#/entities' + (queryString ? '?' + queryString : '');

  // Only update if we're on entities page and URL differs
  if (location.hash.startsWith('#/entities') && location.hash !== newHash) {
    history.replaceState(null, '', newHash);
  }
}

// Get shareable URL for current filter state
function getShareableUrl() {
  const base = location.origin + location.pathname;
  syncFilterToUrl();
  return base + location.hash;
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
    const hasAdmin = open.some(p => ADMIN_PORTS[p.port]);
    const risk = calculateRisk(host);
    const tagData = getAssetTags(host);
    const labels = Array.isArray(tagData) ? tagData : (tagData.labels || []);
    const isTagged = labels.length > 0 || tagData.owner || tagData.notes;
    const isCkt = labels.some(l => ['ckt', 'mission-critical', 'mission-essential', 'crown'].includes(l));
    const isProd = labels.includes('production');

    switch (filter) {
      case 'up': return true;
      case 'ckt': return isCkt;
      case 'tagged': return isTagged;
      case 'admin': return hasAdmin;
      case 'cleartext': return hasCleartext;
      case 'risk': return risk >= 50;
      case 'production': return isProd;
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
  buildSearchIndex();
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
  if (!state.data?.hosts) return;

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
      if (OS_PATTERNS.win.test(os)) { icon.classList.add('win'); icon.textContent = '[W]'; }
      else if (OS_PATTERNS.lin.test(os)) { icon.classList.add('lin'); icon.textContent = '[L]'; }
      else if (OS_PATTERNS.net.test(os)) { icon.classList.add('net'); icon.textContent = '[N]'; }
    }
    
    // Tags
    updateEntityTags();
  });
}

function updateEntityTags() {
  const tagLabels = {
    // Criticality
    'ckt': '[!] CKT', 'mission-critical': '[!!] Mission Critical', 'mission-essential': '[!] Mission Essential', 'business-critical': '[*] Business Critical',
    // Tactical
    'crown': '[*] Crown Jewel', 'choke': '[o] Choke Point', 'key': '[K] Key Terrain', 'pivot': '[&lt;&gt;] Pivot', 'attack-surface': '[!] Attack Surface', 'egress': '[-&gt;] Egress',
    // Environment
    'production': '[P] Prod', 'staging': '[S] Stage', 'development': '[D] Dev', 'test': '[T] Test', 'deprecated': '[X] Deprecated',
    // Priority
    'p1': 'P1', 'p2': 'P2', 'p3': 'P3', 'monitor': '[M] Monitor'
  };
  document.querySelectorAll('.entity[data-ip]').forEach(card => {
    const ip = card.dataset.ip;
    const host = state.data?.hosts?.find(h => h.ip === ip);
    if (!host) return;

    const tagData = getAssetTags(host);
    const labels = Array.isArray(tagData) ? tagData : (tagData.labels || []);
    const owner = tagData.owner || '';
    const notes = tagData.notes || '';
    const hasAnnotation = owner || notes;

    const tagsEl = card.querySelector('.entity-tags');
    if (tagsEl) {
      let html = labels.map(t => `<span class="tag tag-${t}">${tagLabels[t] || t}</span>`).join('');
      if (owner) html += `<span class="tag tag-owner" title="Owner: ${owner}">👤 ${owner}</span>`;
      if (notes) html += `<span class="tag tag-notes" title="${notes}">📝</span>`;
      tagsEl.innerHTML = html;
    }
    card.classList.toggle('tagged', labels.length > 0 || hasAnnotation);
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
  // Get all tagged assets with their current IP
  const tagged = Object.entries(state.tags)
    .filter(([key, data]) => {
      if (Array.isArray(data)) return data.length > 0;
      return (data.labels?.length > 0) || data.owner || data.notes;
    })
    .map(([key, data]) => {
      const host = getHostByAssetKey(key);
      const ip = host?.ip || data.lastIp || key.replace(/^(mac:|ip:)/, '');
      const labels = Array.isArray(data) ? data : (data.labels || []);
      const owner = data.owner || '';
      return { key, ip, labels, owner, host };
    });

  document.getElementById('terrain-count').textContent = tagged.length + ' tagged';
  const el = document.getElementById('terrain-list');

  el.innerHTML = tagged.length ? tagged.slice(0, 5).map(t => `
    <div class="flex items-center justify-between mb-4" style="gap:.5rem">
      <span class="mono" style="flex-shrink:0">${t.ip}</span>
      <div style="flex:1;display:flex;flex-wrap:wrap;gap:.25rem;justify-content:flex-end">
        ${t.labels.map(l => `<span class="tag tag-${l}">${l}</span>`).join('')}
        ${t.owner ? `<span class="tag tag-owner" title="Owner">👤</span>` : ''}
      </div>
    </div>
  `).join('') : '<p style="color:#8b949e;font-size:.85rem;">Right-click hosts to tag or annotate</p>';
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

// Detect admin/management ports on host
function getHostAdminPorts(host) {
  const found = [];
  host.ports.filter(p => p.state === 'open').forEach(port => {
    const info = ADMIN_PORTS[port.port];
    if (info) {
      found.push({ port: port.port, ...info, service: port.service || '' });
    }
  });
  // Sort by severity: critical > high > medium > low
  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  return found.sort((a, b) => (sevOrder[a.sev] || 3) - (sevOrder[b.sev] || 3));
}

// Create entity card element dynamically
function createEntityCard(host) {
  const open = host.ports.filter(p => p.state === 'open');
  const filtered = host.ports.filter(p => p.state === 'filtered');
  const os = host.os && host.os[0] ? host.os[0] : null;
  const mac = host.mac;
  const cves = getHostCVEs(host);
  const adminPorts = getHostAdminPorts(host);
  const { findings: nseFindings, vulns: nseVulns } = getHostNseFindings(host);

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

  const adminHtml = adminPorts.length > 0 ? `
    <div class="admin-ports">
      <div class="admin-title">${icon('warning')} Admin Ports Exposed</div>
      ${adminPorts.slice(0, 4).map(a => `
        <div class="admin-port">
          <span class="admin-port-num">${a.port}</span>
          <span class="admin-port-name">${a.name}</span>
          <span class="admin-port-sev sev-${a.sev}">${a.sev}</span>
          <span class="admin-port-cat">${a.cat}</span>
        </div>
      `).join('')}
      ${adminPorts.length > 4 ? `<div class="admin-more">...and ${adminPorts.length - 4} more</div>` : ''}
    </div>
  ` : '';

  // Count critical/high admin ports for badge
  const criticalAdmin = adminPorts.filter(a => a.sev === 'critical' || a.sev === 'high').length;

  // NSE script findings HTML
  const nseHtml = nseFindings.length > 0 ? `
    <div class="nse-findings">
      <div class="nse-title">${icon('search')} Script Findings</div>
      ${nseFindings.slice(0, 4).map(f => `
        <div class="nse-finding">
          <span class="nse-port">${f.port ? ':' + f.port : 'host'}</span>
          <span class="nse-type">${f.type}</span>
          <span class="nse-detail">${
            f.title || f.subject || f.os || f.server || f.version ||
            (f.keys ? f.keys.map(k => k.algo).join(', ') : '') ||
            (f.anonymous ? 'Anonymous FTP!' : '') || f.script
          }</span>
        </div>
      `).join('')}
      ${nseFindings.length > 4 ? `<div class="nse-more">...and ${nseFindings.length - 4} more</div>` : ''}
    </div>
  ` : '';

  // NSE vulnerability findings
  const nseVulnHtml = nseVulns.length > 0 ? `
    <div class="nse-vulns">
      <div class="nse-vuln-title">${icon('warning')} Script Vulnerabilities</div>
      ${nseVulns.slice(0, 3).map(v => `
        <div class="nse-vuln">
          <span class="nse-vuln-script">${v.script}</span>
          ${v.port ? `<span class="nse-vuln-port">:${v.port}</span>` : ''}
        </div>
      `).join('')}
      ${nseVulns.length > 3 ? `<div class="nse-more">...and ${nseVulns.length - 3} more</div>` : ''}
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
      ${nseVulns.length > 0 ? `<span class="badge badge-critical" title="NSE vulns detected">${icon('shield')}</span>` : ''}
      ${criticalAdmin > 0 ? `<span class="badge badge-warning" title="Admin ports exposed">${icon('warning')}</span>` : ''}
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
      ${nseHtml}
      ${adminHtml}
      ${nseVulnHtml}
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

  // Helper to get tag info for a host in export-friendly format
  function getExportTags(host) {
    const tagData = getAssetTags(host);
    if (Array.isArray(tagData)) return { labels: tagData.join(';'), owner: '', notes: '' };
    return {
      labels: (tagData.labels || []).join(';'),
      owner: tagData.owner || '',
      notes: tagData.notes || ''
    };
  }

  if (format === 'json') {
    const data = {...state.data, tags: includeTags ? state.tags : {}};
    content = JSON.stringify(data, null, 2);
    filename = 'netintel-export.json';
    type = 'application/json';
  } else if (format === 'csv') {
    const rows = [['IP','Hostname','MAC','OS','Open Ports','Risk','Labels','Owner','Notes']];
    state.data.hosts.filter(h => h.status === 'up').forEach(h => {
      const os = h.os && h.os[0] ? h.os[0].name : '';
      const ports = h.ports.filter(p => p.state === 'open').map(p => p.port).join(';');
      let risk = 0;
      h.ports.filter(p => p.state === 'open').forEach(p => { if (RISK_WEIGHTS[p.port]) risk += RISK_WEIGHTS[p.port]; });
      const tags = includeTags ? getExportTags(h) : { labels: '', owner: '', notes: '' };
      rows.push([h.ip, h.hostname || '', h.mac || '', os, ports, Math.min(risk,100), tags.labels, tags.owner, tags.notes]);
    });
    content = rows.map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
    filename = 'netintel-export.csv';
    type = 'text/csv';
  } else if (format === 'cpe') {
    const cpes = new Set();
    state.data.hosts.forEach(h => h.ports.forEach(p => { if (p.cpe) cpes.add(p.cpe); }));
    content = JSON.stringify(Array.from(cpes), null, 2);
    filename = 'cpe-list.json';
    type = 'application/json';
  } else if (format === 'tags') {
    // Export just the tags/annotations for reimport
    const tagExport = {};
    Object.entries(state.tags).forEach(([key, data]) => {
      const host = getHostByAssetKey(key);
      const entry = {
        key,
        ip: host?.ip || data.lastIp || '',
        mac: host?.mac || (key.startsWith('mac:') ? key.slice(4) : ''),
        hostname: host?.hostname || '',
        labels: Array.isArray(data) ? data : (data.labels || []),
        owner: data.owner || '',
        notes: data.notes || '',
        lastSeen: data.lastSeen || ''
      };
      tagExport[key] = entry;
    });
    content = JSON.stringify(tagExport, null, 2);
    filename = 'netintel-tags.json';
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

// === TOPOLOGY VIEW ===
function initTopology() {
  const container = document.getElementById('topo-canvas');
  if (!container) return;

  const refreshBtn = document.getElementById('topo-refresh');
  const layoutSelect = document.getElementById('topo-layout');

  if (refreshBtn) refreshBtn.addEventListener('click', () => renderTopology());
  if (layoutSelect) layoutSelect.addEventListener('change', () => renderTopology());
}

function renderTopology() {
  const container = document.getElementById('topo-canvas');
  if (!container) return;

  const layoutSelect = document.getElementById('topo-layout');
  const layout = layoutSelect ? layoutSelect.value : 'hierarchical';

  // Collect all unique nodes and edges from traceroute data
  const nodes = new Map();
  const edges = [];

  // Add scanner node (assumed to be at hop 0)
  nodes.set('scanner', { id: 'scanner', type: 'scanner', label: 'Scanner' });

  state.data.hosts.filter(h => h.status === 'up').forEach(host => {
    // Add target node
    nodes.set(host.ip, {
      id: host.ip,
      type: 'target',
      label: host.hostname || host.ip,
      host
    });

    // Process traceroute hops
    if (host.trace && host.trace.length > 0) {
      let prevNode = 'scanner';
      host.trace.forEach((hop, i) => {
        if (hop.ip && hop.ip !== '*') {
          // Add hop node if not already a target
          if (!nodes.has(hop.ip)) {
            nodes.set(hop.ip, {
              id: hop.ip,
              type: 'hop',
              label: hop.host || hop.ip,
              ttl: hop.ttl
            });
          }

          // Add edge from previous node
          edges.push({ from: prevNode, to: hop.ip, ttl: hop.ttl });
          prevNode = hop.ip;
        }
      });

      // Add edge to target
      if (prevNode !== host.ip) {
        edges.push({ from: prevNode, to: host.ip });
      }
    } else {
      // No traceroute - direct connection from scanner
      edges.push({ from: 'scanner', to: host.ip });
    }
  });

  // Calculate positions based on layout
  const positions = calculateLayout(nodes, edges, layout, container);

  // Clear and render
  container.innerHTML = '';

  // Render edges first (behind nodes)
  edges.forEach(edge => {
    const fromPos = positions.get(edge.from);
    const toPos = positions.get(edge.to);
    if (fromPos && toPos) {
      renderEdge(container, fromPos, toPos);
    }
  });

  // Render nodes
  nodes.forEach((node, id) => {
    const pos = positions.get(id);
    if (pos) {
      renderNode(container, node, pos);
    }
  });

  // Update details panel
  updateTopoDetails(nodes, edges);
}

function calculateLayout(nodes, edges, layout, container) {
  const positions = new Map();
  const width = container.offsetWidth || 800;
  const height = container.offsetHeight || 500;
  const padding = 80;

  if (layout === 'radial') {
    // Radial layout - scanner in center
    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(width, height) / 2 - padding;

    positions.set('scanner', { x: centerX, y: centerY });

    // Group nodes by distance from scanner
    const hops = new Map();
    nodes.forEach((node, id) => {
      if (id === 'scanner') return;
      const maxTtl = node.ttl || (node.type === 'target' ? 10 : 5);
      if (!hops.has(maxTtl)) hops.set(maxTtl, []);
      hops.get(maxTtl).push(id);
    });

    // Position each ring
    const sortedTtls = Array.from(hops.keys()).sort((a, b) => a - b);
    sortedTtls.forEach((ttl, ringIndex) => {
      const ringNodes = hops.get(ttl);
      const ringRadius = (radius / sortedTtls.length) * (ringIndex + 1);
      ringNodes.forEach((id, i) => {
        const angle = (2 * Math.PI * i) / ringNodes.length - Math.PI / 2;
        positions.set(id, {
          x: centerX + ringRadius * Math.cos(angle),
          y: centerY + ringRadius * Math.sin(angle)
        });
      });
    });
  } else {
    // Hierarchical layout
    positions.set('scanner', { x: padding, y: height / 2 });

    // Group by hop count
    const levels = new Map();
    nodes.forEach((node, id) => {
      if (id === 'scanner') return;
      const level = node.ttl || (node.type === 'target' ? 10 : 5);
      if (!levels.has(level)) levels.set(level, []);
      levels.get(level).push(id);
    });

    const sortedLevels = Array.from(levels.keys()).sort((a, b) => a - b);
    const levelWidth = (width - padding * 2) / (sortedLevels.length + 1);

    sortedLevels.forEach((level, levelIndex) => {
      const levelNodes = levels.get(level);
      const levelHeight = height - padding * 2;
      const nodeSpacing = levelHeight / (levelNodes.length + 1);

      levelNodes.forEach((id, i) => {
        positions.set(id, {
          x: padding + levelWidth * (levelIndex + 1),
          y: padding + nodeSpacing * (i + 1)
        });
      });
    });
  }

  return positions;
}

function renderNode(container, node, pos) {
  const el = document.createElement('div');
  el.className = `topo-node ${node.type}`;
  el.style.left = `${pos.x - 50}px`;
  el.style.top = `${pos.y - 20}px`;
  el.innerHTML = `
    <div class="topo-node-ip">${node.id === 'scanner' ? 'Scanner' : node.id}</div>
    ${node.label && node.label !== node.id ? `<div class="topo-node-label">${node.label}</div>` : ''}
  `;
  el.addEventListener('click', () => showNodeDetails(node));
  container.appendChild(el);
}

function renderEdge(container, from, to) {
  const el = document.createElement('div');
  el.className = 'topo-edge';

  const dx = to.x - from.x;
  const dy = to.y - from.y;
  const length = Math.sqrt(dx * dx + dy * dy);
  const angle = Math.atan2(dy, dx) * 180 / Math.PI;

  el.style.left = `${from.x}px`;
  el.style.top = `${from.y}px`;
  el.style.width = `${length}px`;
  el.style.transform = `rotate(${angle}deg)`;

  container.appendChild(el);
}

function showNodeDetails(node) {
  const detailsEl = document.getElementById('topo-details');
  if (!detailsEl) return;

  if (node.type === 'scanner') {
    detailsEl.innerHTML = '<p style="color:#8b949e;">Scanner node (origin of all traceroutes)</p>';
    return;
  }

  if (node.host) {
    const h = node.host;
    const fp = parseFingerprint(h.osFingerprint);
    detailsEl.innerHTML = `
      <div class="mb-4">
        <strong>${h.ip}</strong> ${h.hostname ? `(${h.hostname})` : ''}
      </div>
      ${h.trace.length > 0 ? `
        <div class="fp-section">
          <div class="fp-title">Traceroute Path (${h.trace.length} hops)</div>
          <div class="tbl-wrap">
            <table class="tbl">
              <thead><tr><th>TTL</th><th>IP</th><th>Hostname</th><th>RTT</th></tr></thead>
              <tbody>
                ${h.trace.map(hop => `
                  <tr>
                    <td>${hop.ttl}</td>
                    <td class="mono">${hop.ip || '*'}</td>
                    <td>${hop.host || ''}</td>
                    <td>${hop.rtt ? hop.rtt + 'ms' : ''}</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        </div>
      ` : '<p style="color:#8b949e;">No traceroute data available</p>'}
      ${fp ? `
        <div class="fp-section mt-4">
          <div class="fp-title">OS Fingerprint</div>
          <div class="fp-grid">
            ${Object.entries(fp).slice(0, 12).map(([k, v]) => `
              <div class="fp-item"><span class="fp-key">${k}:</span><span class="fp-val">${v}</span></div>
            `).join('')}
          </div>
        </div>
      ` : ''}
    `;
  } else {
    detailsEl.innerHTML = `
      <div class="mb-4">
        <strong>${node.id}</strong> - Intermediate hop
        ${node.label && node.label !== node.id ? `<br><span style="color:#8b949e;">${node.label}</span>` : ''}
      </div>
    `;
  }
}

function updateTopoDetails(nodes, edges) {
  const targetCount = Array.from(nodes.values()).filter(n => n.type === 'target').length;
  const hopCount = Array.from(nodes.values()).filter(n => n.type === 'hop').length;

  const detailsEl = document.getElementById('topo-details');
  if (detailsEl && !detailsEl.querySelector('.tbl-wrap')) {
    detailsEl.innerHTML = `
      <p style="color:#8b949e;">
        Showing ${targetCount} targets and ${hopCount} intermediate hops.
        Click on a node to see details.
      </p>
    `;
  }
}

// === FINGERPRINT PARSING ===
function parseFingerprint(fp) {
  if (!fp) return null;

  // Nmap fingerprints are URL-encoded key=value pairs separated by %
  // Example: SCAN(V=7.94%E=4%D=11/5%OT=22%CT=1%CU=%PV=Y%DS=2...)
  const result = {};

  try {
    // Decode URL encoding
    const decoded = decodeURIComponent(fp.replace(/\+/g, ' '));

    // Parse sections like SCAN(...) SEQ(...) OPS(...) etc
    const sectionRegex = /([A-Z]+)\(([^)]+)\)/g;
    let match;

    while ((match = sectionRegex.exec(decoded)) !== null) {
      const sectionName = match[1];
      const sectionData = match[2];

      // Parse key=value pairs within section
      sectionData.split('%').forEach(pair => {
        const [key, value] = pair.split('=');
        if (key && value !== undefined) {
          result[`${sectionName}.${key}`] = value;
        }
      });
    }
  } catch (e) {
    console.error('[NetIntel] Error parsing fingerprint:', e);
  }

  return Object.keys(result).length > 0 ? result : null;
}

// Parse service fingerprint
function parseServiceFingerprint(fp) {
  if (!fp) return null;

  const result = {};
  try {
    const decoded = decodeURIComponent(fp);
    // Service fingerprints often have SF: prefix and contain probe responses
    const parts = decoded.split(/SF[-:]?/);
    if (parts.length > 1) {
      result.response = parts[1].substring(0, 200); // Truncate
    }
  } catch (e) {
    // Ignore parse errors
  }

  return Object.keys(result).length > 0 ? result : null;
}

// === TIMELINE VIEW ===
let timelineScans = [];

function initTimeline() {
  const addBtn = document.getElementById('timeline-add');
  if (addBtn) {
    addBtn.addEventListener('click', () => {
      // Create file input dynamically
      const input = document.createElement('input');
      input.type = 'file';
      input.accept = '.xml';
      input.addEventListener('change', () => {
        if (input.files[0]) addTimelineScan(input.files[0]);
      });
      input.click();
    });
  }

  // Initialize with current scan
  timelineScans = [{
    id: 'current',
    timestamp: new Date(state.data.scanInfo.start * 1000),
    startstr: state.data.scanInfo.startstr,
    hosts: state.data.hosts,
    stats: state.data.stats
  }];
}

function addTimelineScan(file) {
  const reader = new FileReader();
  reader.onload = e => {
    try {
      const parser = new DOMParser();
      const doc = parser.parseFromString(e.target.result, 'text/xml');
      if (!doc.querySelector('nmaprun')) {
        alert('Not a valid Nmap XML file');
        return;
      }

      const nmaprun = doc.querySelector('nmaprun');
      const hosts = parseNmapXml(doc);
      const runstats = doc.querySelector('runstats hosts');

      const scan = {
        id: `scan-${Date.now()}`,
        timestamp: new Date(nmaprun.getAttribute('start') * 1000),
        startstr: nmaprun.getAttribute('startstr'),
        filename: file.name,
        hosts,
        stats: {
          total: parseInt(runstats?.getAttribute('total') || hosts.length),
          up: parseInt(runstats?.getAttribute('up') || hosts.filter(h => h.status === 'up').length),
          down: parseInt(runstats?.getAttribute('down') || 0)
        }
      };

      timelineScans.push(scan);
      timelineScans.sort((a, b) => a.timestamp - b.timestamp);

      renderTimeline();
      console.log('[NetIntel] Added timeline scan:', file.name);
    } catch (err) {
      console.error('[NetIntel] Timeline parse error:', err);
      alert('Error parsing scan file');
    }
  };
  reader.readAsText(file);
}

function renderTimeline() {
  const track = document.getElementById('timeline-track');
  if (!track) return;

  track.innerHTML = timelineScans.map((scan, i) => `
    <div class="timeline-scan ${i === timelineScans.length - 1 ? 'active' : ''}" data-scan="${scan.id}">
      <div class="timeline-scan-date">${scan.timestamp.toLocaleDateString()}</div>
      <div class="timeline-scan-time">${scan.timestamp.toLocaleTimeString()}</div>
      <div class="timeline-scan-stats">
        <span class="timeline-scan-stat">${scan.stats.up} hosts</span>
        <span class="timeline-scan-stat">${scan.hosts.reduce((sum, h) => sum + h.ports.filter(p => p.state === 'open').length, 0)} ports</span>
      </div>
      ${scan.filename ? `<div style="font-size:.7rem;color:#8b949e;margin-top:.25rem;">${scan.filename}</div>` : ''}
    </div>
  `).join('');

  // Click handlers
  track.querySelectorAll('.timeline-scan').forEach(el => {
    el.addEventListener('click', () => {
      track.querySelectorAll('.timeline-scan').forEach(s => s.classList.remove('active'));
      el.classList.add('active');
    });
  });

  renderTimelineChart();
  renderTimelineChanges();
}

function renderTimelineChart() {
  const chart = document.getElementById('timeline-chart');
  if (!chart || timelineScans.length < 2) return;

  const maxHosts = Math.max(...timelineScans.map(s => s.stats.up));
  const maxPorts = Math.max(...timelineScans.map(s =>
    s.hosts.reduce((sum, h) => sum + h.ports.filter(p => p.state === 'open').length, 0)
  ));

  const barWidth = Math.max(20, (chart.offsetWidth - 100) / timelineScans.length - 10);

  chart.innerHTML = timelineScans.map((scan, i) => {
    const hostHeight = (scan.stats.up / maxHosts) * 150;
    const portCount = scan.hosts.reduce((sum, h) => sum + h.ports.filter(p => p.state === 'open').length, 0);
    const portHeight = (portCount / maxPorts) * 150;

    return `
      <div style="position:absolute;left:${50 + i * (barWidth + 10)}px;bottom:2rem;text-align:center;">
        <div class="timeline-bar hosts" style="height:${hostHeight}px;width:${barWidth/2 - 2}px;display:inline-block;" title="${scan.stats.up} hosts"></div>
        <div class="timeline-bar ports" style="height:${portHeight}px;width:${barWidth/2 - 2}px;display:inline-block;" title="${portCount} ports"></div>
        <div style="font-size:.7rem;color:#8b949e;margin-top:.25rem;">${scan.timestamp.toLocaleDateString()}</div>
      </div>
    `;
  }).join('') + `
    <div style="position:absolute;right:1rem;top:1rem;font-size:.75rem;">
      <span style="color:#238636;">■</span> Hosts
      <span style="color:#58a6ff;margin-left:.5rem;">■</span> Ports
    </div>
  `;
}

function renderTimelineChanges() {
  const changesEl = document.getElementById('timeline-changes');
  if (!changesEl || timelineScans.length < 2) return;

  const changes = [];

  for (let i = 1; i < timelineScans.length; i++) {
    const prev = timelineScans[i - 1];
    const curr = timelineScans[i];
    const diff = computeDiff(prev.hosts, curr.hosts);

    if (diff.summary.new > 0 || diff.summary.removed > 0 || diff.summary.changed > 0) {
      changes.push({
        from: prev.timestamp,
        to: curr.timestamp,
        diff
      });
    }
  }

  changesEl.innerHTML = changes.length ? changes.map(c => `
    <div class="diff-item" style="flex-direction:column;align-items:stretch;">
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <span style="color:#8b949e;">${c.from.toLocaleDateString()} -> ${c.to.toLocaleDateString()}</span>
        <div>
          ${c.diff.summary.new > 0 ? `<span class="badge badge-low">+${c.diff.summary.new} new</span>` : ''}
          ${c.diff.summary.removed > 0 ? `<span class="badge badge-critical">-${c.diff.summary.removed} removed</span>` : ''}
          ${c.diff.summary.changed > 0 ? `<span class="badge badge-high">${c.diff.summary.changed} changed</span>` : ''}
        </div>
      </div>
    </div>
  `).join('') : '<p style="color:#8b949e;">No changes between scans</p>';
}

// === SEARCH ===
// Field-aware search: port:22, service:ssh, os:windows, tag:ckt, cve:CVE-*, owner:john, risk:>50
document.getElementById('search')?.addEventListener('input', e => {
  const query = e.target.value;
  const filterEl = document.getElementById('entity-filter');
  const filter = filterEl ? filterEl.value : 'all';
  const searchTerms = parseSearchQuery(query);

  let visible = 0, total = 0;

  document.querySelectorAll('.entity[data-ip]').forEach(card => {
    const ip = card.dataset.ip;
    const host = state.data.hosts.find(h => h.ip === ip);
    if (!host) return;

    total++;

    // Check search terms
    const matchesSearch = query.trim() === '' || matchesSearchTerms(host, searchTerms);

    // Check filter
    let passesFilter = true;
    if (filter !== 'all') {
      const open = host.ports.filter(p => p.state === 'open');
      const hasCleartext = open.some(p => CLEARTEXT[p.port]);
      const hasAdmin = open.some(p => ADMIN_PORTS[p.port]);
      const risk = calculateRisk(host);
      const tagData = getAssetTags(host);
      const labels = Array.isArray(tagData) ? tagData : (tagData.labels || []);
      const isTagged = labels.length > 0 || tagData.owner || tagData.notes;
      const isCkt = labels.some(l => ['ckt', 'mission-critical', 'mission-essential', 'crown'].includes(l));
      const isProd = labels.includes('production');

      switch (filter) {
        case 'up': passesFilter = host.status === 'up'; break;
        case 'ckt': passesFilter = isCkt; break;
        case 'tagged': passesFilter = isTagged; break;
        case 'admin': passesFilter = hasAdmin; break;
        case 'cleartext': passesFilter = hasCleartext; break;
        case 'risk': passesFilter = risk >= 50; break;
        case 'production': passesFilter = isProd; break;
      }
    }

    const show = matchesSearch && passesFilter;
    card.style.display = show ? '' : 'none';
    if (show) visible++;
  });

  // Update search result count
  updateSearchCount(visible, total, query);

  // Debounce URL sync to avoid history spam
  clearTimeout(window._searchUrlTimeout);
  window._searchUrlTimeout = setTimeout(() => syncFilterToUrl(), 500);
});

function updateSearchCount(visible, total, query) {
  let countEl = document.getElementById('search-count');
  if (!countEl) {
    const searchBox = document.getElementById('search');
    if (searchBox) {
      countEl = document.createElement('span');
      countEl.id = 'search-count';
      countEl.className = 'search-count';
      searchBox.parentNode.insertBefore(countEl, searchBox.nextSibling);
    }
  }
  if (countEl) {
    if (query.trim()) {
      countEl.textContent = `${visible} of ${total}`;
      countEl.style.display = 'inline';
    } else {
      countEl.style.display = 'none';
    }
  }
}
]]></xsl:text>
</script>
</xsl:template>

</xsl:stylesheet>
