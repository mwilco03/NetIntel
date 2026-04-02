package models

type Host struct {
	IP              string          `json:"ip"`
	MAC             string          `json:"mac,omitempty"`
	MACVendor       string          `json:"macVendor,omitempty"`
	Hostname        string          `json:"hostname,omitempty"`
	NetBIOSName     string          `json:"netbiosName,omitempty"`
	Status          string          `json:"status"`
	OS              []OSMatch       `json:"os,omitempty"`
	Ports           []Port          `json:"ports,omitempty"`
	Trace           []TraceHop      `json:"trace,omitempty"`
	CPEs            []string        `json:"cpes,omitempty"`
	NessusFindings  []NessusFinding `json:"nessusFindings,omitempty"`
	CredScan        bool            `json:"credentialedScan,omitempty"`
	RiskScore       int             `json:"riskScore"`
	CleartextCount  int             `json:"cleartextCount"`
}

type Port struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	State   string `json:"state"`
	Service string `json:"svc"`
	Product string `json:"product,omitempty"`
	Version string `json:"version,omitempty"`
	CPE     string `json:"cpe,omitempty"`
}

type OSMatch struct {
	Name     string `json:"name"`
	Accuracy int    `json:"accuracy"`
}

type TraceHop struct {
	TTL  int     `json:"ttl"`
	IP   string  `json:"ip"`
	Host string  `json:"host,omitempty"`
	RTT  float64 `json:"rtt"`
}

type NessusFinding struct {
	PluginID         int      `json:"pluginID"`
	PluginName       string   `json:"pluginName"`
	Severity         int      `json:"severity"`
	SeverityLabel    string   `json:"severityLabel"`
	RiskFactor       string   `json:"riskFactor"`
	CVSS             float64  `json:"cvss,omitempty"`
	CVSS3            float64  `json:"cvss3,omitempty"`
	VPR              float64  `json:"vpr,omitempty"`
	CVEs             []string `json:"cves,omitempty"`
	CPE              string   `json:"cpe,omitempty"`
	Synopsis         string   `json:"synopsis,omitempty"`
	Description      string   `json:"description,omitempty"`
	Solution         string   `json:"solution,omitempty"`
	Output           string   `json:"output,omitempty"`
	ExploitAvailable bool     `json:"exploitAvailable"`
	STIGSeverity     string   `json:"stigSeverity,omitempty"`
	References       string   `json:"references,omitempty"`
	XRefs            []string `json:"xrefs,omitempty"`
	Port             int      `json:"port"`
	Proto            string   `json:"proto,omitempty"`
	HostIP           string   `json:"hostIp,omitempty"`
}

type ScanSource struct {
	Name      string `json:"name"`
	Type      string `json:"type"` // "nmap" or "nessus"
	Hosts     int    `json:"hosts"`
	Timestamp string `json:"timestamp"`
}

type ScanData struct {
	Hosts   []Host       `json:"hosts"`
	Sources []ScanSource `json:"sources"`
}

type DashboardStats struct {
	TotalHosts     int              `json:"totalHosts"`
	HostsUp        int              `json:"hostsUp"`
	TotalPorts     int              `json:"totalPorts"`
	CleartextCount int              `json:"cleartextCount"`
	AvgRisk        int              `json:"avgRisk"`
	TopRisks       []HostRiskEntry  `json:"topRisks"`
	OSDist         map[string]int   `json:"osDist"`
	SeverityCounts map[string]int   `json:"severityCounts,omitempty"`
}

type HostRiskEntry struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
	Risk     int    `json:"risk"`
}
