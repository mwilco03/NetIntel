# Screenshots

Add screenshots here. Recommended captures:

## Required Screenshots

1. **dashboard.png** - Dashboard view showing:
   - Stats cards (hosts up, open ports, cleartext count, risk score)
   - Top risks panel
   - Cleartext warnings panel

2. **entities.png** - Entity Cards view showing:
   - Host cards with ports and services
   - OS icons
   - Risk badges
   - Tag indicators

3. **topology.png** - Topology view showing:
   - Network graph from traceroute
   - Scanner node, hop nodes, target nodes
   - Edge connections

4. **diff.png** - Scan Diff view showing:
   - New/removed/changed hosts
   - Port changes highlighted

## Capture Instructions

1. Generate a report: `xsltproc nmap-intel.xsl Test.xml > report.html`
2. Open in Chrome/Chromium
3. Navigate to each view
4. Use browser DevTools (F12) > Device toolbar for consistent viewport (1280x800 recommended)
5. Take screenshot with Cmd+Shift+4 (Mac) or Snipping Tool (Windows)
6. Save as PNG with the names above

## Optional Screenshots

- `cleartext.png` - Cleartext protocol analysis page
- `timeline.png` - Timeline view with multiple scans
- `sources.png` - Data sources panel
- `tagging.png` - Right-click context menu for tagging
