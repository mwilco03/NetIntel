# NetIntel Examples

Sample files for testing and demonstration.

## Files

### sample-vuln-db.json

A sample CPE-to-CVE vulnerability database for testing the CVE matching feature.

**Usage:**
1. Generate a report: `xsltproc ../nmap-intel.xsl ../Test.xml > report.html`
2. Open `report.html` in a browser
3. Go to **Tools > Vuln Database**
4. Drag and drop `sample-vuln-db.json` or click to browse
5. CVE counts will appear on host cards with matching CPEs

**Note:** This is sample data for demonstration. For production use, generate a real vulnerability database using `tools/nvd-to-vulndb.py` with data from the NVD API.

### Creating Your Own Test Scans

```bash
# Quick scan for testing
nmap -sV -oX my-scan.xml 192.168.1.0/24

# Full scan with OS detection and traceroute
nmap -sV -sC -O --traceroute -oX my-scan.xml 192.168.1.0/24

# Generate report
xsltproc ../nmap-intel.xsl my-scan.xml > my-report.html
```

## Sample Nmap Commands by Use Case

### Internal Network Assessment
```bash
nmap -sV -sC -O --traceroute -oX internal.xml 10.0.0.0/8
```

### Web Server Audit
```bash
nmap -sV --script=http-enum,http-headers,ssl-cert -p 80,443,8080,8443 -oX web.xml targets.txt
```

### Database Discovery
```bash
nmap -sV -p 1433,1521,3306,5432,27017,6379,9200 -oX databases.xml 192.168.0.0/16
```

### Container/Cloud Infrastructure
```bash
nmap -sV -p 2375,2376,2377,4243,6443,10250,10255,2379,8500,9000 -oX containers.xml 172.16.0.0/12
```
