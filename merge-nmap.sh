#!/bin/sh
# nmap-merge.sh — Generate a NetIntel manifest from multiple nmap XML files
#
# The manifest uses XSLT document() to load each scan at transform time,
# so each source retains its full metadata (args, timestamps, stats).
#
# Usage:
#   ./nmap-merge.sh scan1.xml scan2.xml scan3.xml > scans.xml
#   xsltproc nmap-intel.xsl scans.xml > report.html
#
# One-liner:
#   ./nmap-merge.sh *.xml | xsltproc nmap-intel.xsl - > report.html
#   (NOTE: piping won't work with document() — write to a file first)
#
# Correct usage:
#   ./nmap-merge.sh *.xml > scans.xml && xsltproc nmap-intel.xsl scans.xml > report.html

set -e

if [ $# -eq 0 ]; then
  echo "Usage: $0 file1.xml [file2.xml ...] > scans.xml" >&2
  echo "" >&2
  echo "Then:  xsltproc nmap-intel.xsl scans.xml > report.html" >&2
  exit 1
fi

echo '<?xml version="1.0" encoding="UTF-8"?>'
echo '<netintel-scans>'
for f in "$@"; do
  # Resolve to absolute path so document() can find it regardless of CWD
  case "$f" in
    /*) abs="$f" ;;
    *)  abs="$(cd "$(dirname "$f")" && pwd)/$(basename "$f")" ;;
  esac
  echo "  <scan file=\"$abs\"/>"
done
echo '</netintel-scans>'
