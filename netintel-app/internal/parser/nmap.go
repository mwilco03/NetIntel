package parser

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"

	"netintel-app/internal/models"
)

// Nmap XML structures

type nmapRun struct {
	XMLName   xml.Name   `xml:"nmaprun"`
	Scanner   string     `xml:"scanner,attr"`
	Args      string     `xml:"args,attr"`
	StartStr  string     `xml:"startstr,attr"`
	Hosts     []nmapHost `xml:"host"`
}

type nmapHost struct {
	StartTime string          `xml:"starttime,attr"`
	EndTime   string          `xml:"endtime,attr"`
	Status    nmapStatus      `xml:"status"`
	Addresses []nmapAddress   `xml:"address"`
	Hostnames []nmapHostname  `xml:"hostnames>hostname"`
	Ports     []nmapPort      `xml:"ports>port"`
	OS        nmapOS          `xml:"os"`
	Trace     nmapTrace       `xml:"trace"`
}

type nmapStatus struct {
	State string `xml:"state,attr"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type nmapPort struct {
	PortID   int         `xml:"portid,attr"`
	Protocol string      `xml:"protocol,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name    string     `xml:"name,attr"`
	Product string     `xml:"product,attr"`
	Version string     `xml:"version,attr"`
	CPEs    []nmapCPE  `xml:"cpe"`
}

type nmapCPE struct {
	Value string `xml:",chardata"`
}

type nmapOS struct {
	Matches []nmapOSMatch `xml:"osmatch"`
}

type nmapOSMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy string `xml:"accuracy,attr"`
}

type nmapTrace struct {
	Hops []nmapHop `xml:"hop"`
}

type nmapHop struct {
	TTL  string `xml:"ttl,attr"`
	IP   string `xml:"ipaddr,attr"`
	Host string `xml:"host,attr"`
	RTT  string `xml:"rtt,attr"`
}

func ParseNmapXML(data []byte) ([]models.Host, *models.ScanSource, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, nil, fmt.Errorf("invalid nmap XML: %w", err)
	}

	if run.XMLName.Local != "nmaprun" {
		return nil, nil, fmt.Errorf("not an nmap XML file (root element: %s)", run.XMLName.Local)
	}

	hosts := make([]models.Host, 0, len(run.Hosts))

	for _, xh := range run.Hosts {
		h := models.Host{
			Status: xh.Status.State,
		}

		// Addresses
		for _, addr := range xh.Addresses {
			switch addr.AddrType {
			case "ipv4", "ipv6":
				if h.IP == "" {
					h.IP = addr.Addr
				}
			case "mac":
				h.MAC = addr.Addr
				h.MACVendor = addr.Vendor
			}
		}

		// Hostnames
		for _, hn := range xh.Hostnames {
			if h.Hostname == "" {
				h.Hostname = hn.Name
			}
		}

		// OS matches
		for _, om := range xh.OS.Matches {
			acc, _ := strconv.Atoi(om.Accuracy)
			h.OS = append(h.OS, models.OSMatch{
				Name:     om.Name,
				Accuracy: acc,
			})
		}

		// Ports
		for _, xp := range xh.Ports {
			p := models.Port{
				Port:    xp.PortID,
				Proto:   xp.Protocol,
				State:   xp.State.State,
				Service: xp.Service.Name,
				Product: xp.Service.Product,
				Version: xp.Service.Version,
			}
			if len(xp.Service.CPEs) > 0 {
				p.CPE = xp.Service.CPEs[0].Value
				for _, c := range xp.Service.CPEs {
					h.CPEs = append(h.CPEs, c.Value)
				}
			}
			h.Ports = append(h.Ports, p)
		}

		// Traceroute
		for _, hop := range xh.Trace.Hops {
			ttl, _ := strconv.Atoi(hop.TTL)
			rtt, _ := strconv.ParseFloat(hop.RTT, 64)
			h.Trace = append(h.Trace, models.TraceHop{
				TTL:  ttl,
				IP:   hop.IP,
				Host: hop.Host,
				RTT:  rtt,
			})
		}

		if h.IP != "" {
			hosts = append(hosts, h)
		}
	}

	scanName := "Nmap Scan"
	if run.Args != "" {
		scanName = run.Args
	}

	source := &models.ScanSource{
		Name:      scanName,
		Type:      "nmap",
		Hosts:     len(hosts),
		Timestamp: run.StartStr,
	}

	return hosts, source, nil
}

// DetectFormat checks the root XML element to determine file type.
func DetectFormat(data []byte) string {
	// Quick check without full parse
	s := strings.TrimSpace(string(data[:min(500, len(data))]))
	if strings.Contains(s, "<nmaprun") {
		return "nmap"
	}
	if strings.Contains(s, "<NessusClientData") {
		return "nessus"
	}
	return "unknown"
}
