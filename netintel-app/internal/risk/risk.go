package risk

import (
	"math"
	"regexp"
	"sort"
	"strings"

	"netintel-app/internal/models"
)

// Port-based risk weights (matching existing XSL)
var portWeights = map[int]int{
	// Critical RCE (10)
	23: 10, 2375: 10, 4243: 10, 6443: 10, 10250: 10, 2379: 10, 623: 10,
	// Legacy/NoAuth (9)
	512: 9, 513: 9, 514: 9, 6379: 9,
	// Database/Admin (8)
	445: 8, 1433: 8, 1521: 8, 27017: 8, 2376: 8, 5985: 8, 5986: 8, 9200: 8, 1099: 8,
	// Common Targets (7)
	21: 7, 139: 7, 161: 7, 3306: 7, 3389: 7, 5900: 7, 10000: 7,
	// Sensitive (6)
	110: 6, 135: 6, 143: 6, 389: 6, 5432: 6,
	// Encrypted (3)
	22: 3, 53: 3,
	// Web (1-2)
	80: 2, 443: 1, 8080: 2, 8443: 1,
}

// Service-name based risk weights
var svcWeights = map[string]int{
	"telnet": 10, "docker": 10, "kubernetes": 10,
	"redis": 9, "rsh": 9, "rlogin": 9, "rexec": 9,
	"microsoft-ds": 8, "ms-sql-s": 8, "oracle-tns": 8, "mongodb": 8, "elasticsearch": 8,
	"ftp": 7, "netbios-ssn": 7, "snmp": 7, "mysql": 7, "ms-wbt-server": 7, "vnc": 7,
	"pop3": 6, "msrpc": 6, "imap": 6, "ldap": 6, "postgresql": 6,
	"ssh": 3, "domain": 3,
	"http": 2, "https": 1, "http-proxy": 2,
}

var cleartextPorts = map[int]string{
	21: "FTP", 23: "Telnet", 80: "HTTP", 110: "POP3", 143: "IMAP",
	161: "SNMP", 389: "LDAP", 512: "rexec", 513: "rlogin", 514: "rsh",
	8080: "HTTP-Alt", 8000: "HTTP-Alt", 8888: "HTTP-Alt",
}

var cleartextSvcs = map[string]string{
	"ftp": "FTP", "telnet": "Telnet", "http": "HTTP", "pop3": "POP3",
	"imap": "IMAP", "snmp": "SNMP", "ldap": "LDAP", "rsh": "rsh",
	"rlogin": "rlogin", "rexec": "rexec", "http-proxy": "HTTP Proxy",
}

var (
	winPattern = regexp.MustCompile(`(?i)windows|microsoft`)
	linPattern = regexp.MustCompile(`(?i)linux|ubuntu|debian|centos|fedora|redhat|rhel|suse`)
	netPattern = regexp.MustCompile(`(?i)cisco|juniper|arista|palo alto|fortinet|mikrotik|vyos|router|switch`)
)

func IsCleartext(p models.Port) bool {
	if _, ok := cleartextPorts[p.Port]; ok {
		return true
	}
	svc := strings.ToLower(p.Service)
	_, ok := cleartextSvcs[svc]
	return ok
}

func CleartextName(p models.Port) string {
	if name, ok := cleartextPorts[p.Port]; ok {
		return name
	}
	svc := strings.ToLower(p.Service)
	if name, ok := cleartextSvcs[svc]; ok {
		return name
	}
	return ""
}

func CalculateRisk(host models.Host) int {
	openPorts := make([]models.Port, 0)
	for _, p := range host.Ports {
		if p.State == "open" {
			openPorts = append(openPorts, p)
		}
	}

	// Collect weights for each open port (max of port-based and service-based)
	weights := make([]int, 0, len(openPorts))
	cleartextCount := 0
	for _, p := range openPorts {
		w := 0
		if pw, ok := portWeights[p.Port]; ok {
			w = pw
		}
		svc := strings.ToLower(p.Service)
		if sw, ok := svcWeights[svc]; ok && sw > w {
			w = sw
		}
		if IsCleartext(p) {
			w += 3
			cleartextCount++
		}
		if w > 0 {
			weights = append(weights, w)
		}
	}

	// Sort descending
	sort.Sort(sort.Reverse(sort.IntSlice(weights)))

	// Logarithmic diminishing returns
	portRisk := 0.0
	for i, w := range weights {
		if i == 0 {
			portRisk += float64(w)
		} else {
			portRisk += float64(w) / math.Log2(float64(i+2))
		}
	}

	// Nessus vulnerability risk
	vulnRisk := 0.0
	sevWeights := map[int]float64{4: 25, 3: 15, 2: 5, 1: 1}
	for _, f := range host.NessusFindings {
		if sw, ok := sevWeights[f.Severity]; ok {
			vulnRisk += sw
			if f.ExploitAvailable {
				vulnRisk += 5
			}
		}
	}

	risk := int(math.Max(portRisk, vulnRisk))
	if risk > 100 {
		risk = 100
	}
	return risk
}

func ScoreHosts(hosts []models.Host) []models.Host {
	for i := range hosts {
		hosts[i].RiskScore = CalculateRisk(hosts[i])
		ct := 0
		for _, p := range hosts[i].Ports {
			if p.State == "open" && IsCleartext(p) {
				ct++
			}
		}
		hosts[i].CleartextCount = ct
	}
	return hosts
}

func ComputeStats(hosts []models.Host) models.DashboardStats {
	stats := models.DashboardStats{
		OSDist: make(map[string]int),
	}

	totalRisk := 0
	riskEntries := make([]models.HostRiskEntry, 0)

	for _, h := range hosts {
		stats.TotalHosts++
		if h.Status == "up" {
			stats.HostsUp++
		}

		openPorts := 0
		for _, p := range h.Ports {
			if p.State == "open" {
				openPorts++
				if IsCleartext(p) {
					stats.CleartextCount++
				}
			}
		}
		stats.TotalPorts += openPorts

		totalRisk += h.RiskScore
		riskEntries = append(riskEntries, models.HostRiskEntry{
			IP:       h.IP,
			Hostname: h.Hostname,
			Risk:     h.RiskScore,
		})

		// OS distribution
		osType := "Unknown"
		if len(h.OS) > 0 {
			name := h.OS[0].Name
			switch {
			case winPattern.MatchString(name):
				osType = "Windows"
			case linPattern.MatchString(name):
				osType = "Linux"
			case netPattern.MatchString(name):
				osType = "Network"
			}
		}
		stats.OSDist[osType]++
	}

	if stats.HostsUp > 0 {
		stats.AvgRisk = totalRisk / stats.HostsUp
	}

	sort.Slice(riskEntries, func(i, j int) bool {
		return riskEntries[i].Risk > riskEntries[j].Risk
	})
	if len(riskEntries) > 5 {
		riskEntries = riskEntries[:5]
	}
	stats.TopRisks = riskEntries

	// Nessus severity counts
	sevCounts := map[string]int{}
	for _, h := range hosts {
		for _, f := range h.NessusFindings {
			sevCounts[f.SeverityLabel]++
		}
	}
	if len(sevCounts) > 0 {
		stats.SeverityCounts = sevCounts
	}

	return stats
}

func ClassifyOS(name string) string {
	switch {
	case winPattern.MatchString(name):
		return "windows"
	case linPattern.MatchString(name):
		return "linux"
	case netPattern.MatchString(name):
		return "network"
	default:
		return "unknown"
	}
}
