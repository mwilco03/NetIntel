#!/bin/sh
# merge-nmap.sh — Merge multiple nmap XML files into one for xsltproc
#
# Usage:
#   ./merge-nmap.sh *.xml > merged.xml
#   ./merge-nmap.sh scan1.xml scan2.xml scan3.xml | xsltproc nmap-intel.xsl - > report.html
#
# One-liner:
#   ./merge-nmap.sh *.xml | xsltproc nmap-intel.xsl - > report.html

set -e

if [ $# -eq 0 ]; then
  echo "Usage: $0 file1.xml [file2.xml ...] > merged.xml" >&2
  exit 1
fi

# Use first file for nmaprun attributes
FIRST="$1"

# Extract attributes from the first file's <nmaprun> tag
SCANNER=$(sed -n 's/.*scanner="\([^"]*\)".*/\1/p' "$FIRST" | head -1)
ARGS=$(sed -n 's/.*<nmaprun[^>]* args="\([^"]*\)".*/\1/p' "$FIRST" | head -1)
START=$(sed -n 's/.*<nmaprun[^>]* start="\([^"]*\)".*/\1/p' "$FIRST" | head -1)
STARTSTR=$(sed -n 's/.*<nmaprun[^>]* startstr="\([^"]*\)".*/\1/p' "$FIRST" | head -1)
VERSION=$(sed -n 's/.*<nmaprun[^>]* version="\([^"]*\)".*/\1/p' "$FIRST" | head -1)
XMLVER=$(sed -n 's/.*xmloutputversion="\([^"]*\)".*/\1/p' "$FIRST" | head -1)

# Count totals across all files
TOTAL_UP=0
TOTAL_DOWN=0
TOTAL_ALL=0
LAST_TIMESTR=""
LAST_TIME=""

for f in "$@"; do
  UP=$(sed -n 's/.*<hosts[^>]* up="\([^"]*\)".*/\1/p' "$f" | tail -1)
  DOWN=$(sed -n 's/.*<hosts[^>]* down="\([^"]*\)".*/\1/p' "$f" | tail -1)
  TOT=$(sed -n 's/.*<hosts[^>]* total="\([^"]*\)".*/\1/p' "$f" | tail -1)
  FTIME=$(sed -n 's/.*<finished[^>]* time="\([^"]*\)".*/\1/p' "$f" | tail -1)
  FTIMESTR=$(sed -n 's/.*<finished[^>]* timestr="\([^"]*\)".*/\1/p' "$f" | tail -1)
  TOTAL_UP=$((TOTAL_UP + ${UP:-0}))
  TOTAL_DOWN=$((TOTAL_DOWN + ${DOWN:-0}))
  TOTAL_ALL=$((TOTAL_ALL + ${TOT:-0}))
  LAST_TIME="${FTIME:-$LAST_TIME}"
  LAST_TIMESTR="${FTIMESTR:-$LAST_TIMESTR}"
done

# Emit merged XML
cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="${SCANNER}" args="merged: $# files" start="${START}" startstr="${STARTSTR}" version="${VERSION}" xmloutputversion="${XMLVER}">
<scaninfo type="syn" protocol="tcp" numservices="65535" services="1-65535"/>
<verbose level="0"/>
<debugging level="0"/>
EOF

# Extract <host>...</host> blocks from each file
for f in "$@"; do
  sed -n '/<host\b/,/<\/host>/p' "$f"
done

cat <<EOF
<runstats><finished time="${LAST_TIME}" timestr="${LAST_TIMESTR}" summary="Merged $# nmap scans; ${TOTAL_UP} hosts up out of ${TOTAL_ALL} total" elapsed="0" exit="success"/><hosts up="${TOTAL_UP}" down="${TOTAL_DOWN}" total="${TOTAL_ALL}"/></runstats>
</nmaprun>
EOF
