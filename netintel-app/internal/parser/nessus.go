package parser

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"

	"netintel-app/internal/models"
)

// Nessus XML structures

type nessusRoot struct {
	XMLName xml.Name       `xml:"NessusClientData_v2"`
	Reports []nessusReport `xml:"Report"`
}

type nessusReport struct {
	Name  string             `xml:"name,attr"`
	Hosts []nessusReportHost `xml:"ReportHost"`
}

type nessusReportHost struct {
	Name       string              `xml:"name,attr"`
	Properties nessusHostProps     `xml:"HostProperties"`
	Items      []nessusReportItem  `xml:"ReportItem"`
}

type nessusHostProps struct {
	Tags []nessusTag `xml:"tag"`
}

type nessusTag struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

type nessusReportItem struct {
	Port             int    `xml:"port,attr"`
	Protocol         string `xml:"protocol,attr"`
	SvcName          string `xml:"svc_name,attr"`
	PluginID         int    `xml:"pluginID,attr"`
	PluginName       string `xml:"pluginName,attr"`
	Severity         int    `xml:"severity,attr"`
	RiskFactor       string `xml:"risk_factor"`
	Synopsis         string `xml:"synopsis"`
	Description      string `xml:"description"`
	Solution         string `xml:"solution"`
	PluginOutput     string `xml:"plugin_output"`
	CVSSBaseScore    string `xml:"cvss_base_score"`
	CVSS3BaseScore   string `xml:"cvss3_base_score"`
	VPRScore         string `xml:"vpr_score"`
	ExploitAvailable string `xml:"exploit_available"`
	STIGSeverity     string `xml:"stig_severity"`
	SeeAlso          string `xml:"see_also"`
	CPE              string `xml:"cpe"`
	CVEs             []struct {
		Value string `xml:",chardata"`
	} `xml:"cve"`
	XRefs []struct {
		Value string `xml:",chardata"`
	} `xml:"xref"`
}

func ParseNessusXML(data []byte) ([]models.Host, *models.ScanSource, error) {
	var root nessusRoot
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil, nil, fmt.Errorf("invalid nessus XML: %w", err)
	}

	if len(root.Reports) == 0 {
		return nil, nil, fmt.Errorf("no reports found in nessus file")
	}

	report := root.Reports[0]
	hosts := make([]models.Host, 0, len(report.Hosts))

	for _, rh := range report.Hosts {
		props := make(map[string]string)
		for _, t := range rh.Properties.Tags {
			props[t.Name] = t.Value
		}

		h := models.Host{
			IP:       propOr(props, "host-ip", rh.Name),
			Hostname: propOr(props, "hostname", ""),
			Status:   "up",
		}

		if nb := props["netbios-name"]; nb != "" {
			h.NetBIOSName = nb
		}
		if props["Credentialed_Scan"] == "true" {
			h.CredScan = true
		}

		// OS from properties
		if os := props["operating-system"]; os != "" {
			acc := 0
			if a := props["operating-system-conf"]; a != "" {
				acc, _ = strconv.Atoi(a)
			}
			h.OS = append(h.OS, models.OSMatch{Name: os, Accuracy: acc})
		}

		// CPEs from properties
		for k, v := range props {
			if strings.HasPrefix(k, "cpe") && v != "" {
				h.CPEs = append(h.CPEs, v)
			}
		}

		// Traceroute hops
		for i := 0; i < 256; i++ {
			key := fmt.Sprintf("traceroute-hop-%d", i)
			if val, ok := props[key]; ok {
				h.Trace = append(h.Trace, models.TraceHop{
					TTL: i,
					IP:  val,
				})
			}
		}

		// Process report items
		portSeen := make(map[string]bool)
		for _, item := range rh.Items {
			// Port entries (dedup by port+proto)
			if item.Port > 0 {
				key := fmt.Sprintf("%d/%s", item.Port, item.Protocol)
				if !portSeen[key] {
					portSeen[key] = true
					h.Ports = append(h.Ports, models.Port{
						Port:    item.Port,
						Proto:   item.Protocol,
						State:   "open",
						Service: item.SvcName,
						CPE:     item.CPE,
					})
				}
			}

			// Findings (severity > 0)
			if item.Severity > 0 {
				f := models.NessusFinding{
					PluginID:      item.PluginID,
					PluginName:    item.PluginName,
					Severity:      item.Severity,
					SeverityLabel: severityLabel(item.Severity),
					RiskFactor:    item.RiskFactor,
					Synopsis:      item.Synopsis,
					Description:   item.Description,
					Solution:      item.Solution,
					Output:        item.PluginOutput,
					STIGSeverity:  item.STIGSeverity,
					References:    item.SeeAlso,
					CPE:           item.CPE,
					Port:          item.Port,
					Proto:         item.Protocol,
					HostIP:        h.IP,
				}

				if v, err := strconv.ParseFloat(item.CVSSBaseScore, 64); err == nil {
					f.CVSS = v
				}
				if v, err := strconv.ParseFloat(item.CVSS3BaseScore, 64); err == nil {
					f.CVSS3 = v
				}
				if v, err := strconv.ParseFloat(item.VPRScore, 64); err == nil {
					f.VPR = v
				}

				f.ExploitAvailable = strings.EqualFold(item.ExploitAvailable, "true")

				for _, c := range item.CVEs {
					f.CVEs = append(f.CVEs, c.Value)
				}
				for _, x := range item.XRefs {
					f.XRefs = append(f.XRefs, x.Value)
				}

				h.NessusFindings = append(h.NessusFindings, f)
			}
		}

		hosts = append(hosts, h)
	}

	source := &models.ScanSource{
		Name:      report.Name,
		Type:      "nessus",
		Hosts:     len(hosts),
		Timestamp: "", // Nessus doesn't have a single scan timestamp at report level
	}

	return hosts, source, nil
}

func severityLabel(sev int) string {
	switch sev {
	case 4:
		return "Critical"
	case 3:
		return "High"
	case 2:
		return "Medium"
	case 1:
		return "Low"
	default:
		return "Info"
	}
}

func propOr(props map[string]string, key, fallback string) string {
	if v, ok := props[key]; ok && v != "" {
		return v
	}
	return fallback
}
