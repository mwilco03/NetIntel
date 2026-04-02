package store

import (
	"fmt"
	"sort"
	"sync"

	"netintel-app/internal/models"
)

// Store holds scan data in memory. SQLite persistence can be added later.
type Store struct {
	mu   sync.RWMutex
	data models.ScanData
}

func New() *Store {
	return &Store{
		data: models.ScanData{
			Hosts:   []models.Host{},
			Sources: []models.ScanSource{},
		},
	}
}

func (s *Store) GetData() models.ScanData {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data
}

func (s *Store) SetData(data models.ScanData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = data
}

func (s *Store) AddHosts(hosts []models.Host, source *models.ScanSource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.Hosts = mergeHosts(s.data.Hosts, hosts)
	if source != nil {
		s.data.Sources = append(s.data.Sources, *source)
	}
}

func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = models.ScanData{
		Hosts:   []models.Host{},
		Sources: []models.ScanSource{},
	}
}

// mergeHosts merges incoming hosts with existing by IP.
func mergeHosts(existing, incoming []models.Host) []models.Host {
	byIP := make(map[string]*models.Host)
	for i := range existing {
		byIP[existing[i].IP] = &existing[i]
	}

	for _, h := range incoming {
		if ex, ok := byIP[h.IP]; ok {
			// Merge ports (dedup by port+proto)
			portKey := make(map[string]bool)
			for _, p := range ex.Ports {
				portKey[portID(p)] = true
			}
			for _, p := range h.Ports {
				if !portKey[portID(p)] {
					ex.Ports = append(ex.Ports, p)
				}
			}

			// Merge OS (take higher accuracy)
			if len(h.OS) > 0 {
				if len(ex.OS) == 0 || (h.OS[0].Accuracy > ex.OS[0].Accuracy) {
					ex.OS = h.OS
				}
			}

			// Merge hostname
			if ex.Hostname == "" && h.Hostname != "" {
				ex.Hostname = h.Hostname
			}

			// Merge MAC
			if ex.MAC == "" && h.MAC != "" {
				ex.MAC = h.MAC
				ex.MACVendor = h.MACVendor
			}

			// Merge Nessus findings (dedup by pluginID)
			if len(h.NessusFindings) > 0 {
				pluginSeen := make(map[int]bool)
				for _, f := range ex.NessusFindings {
					pluginSeen[f.PluginID] = true
				}
				for _, f := range h.NessusFindings {
					if !pluginSeen[f.PluginID] {
						ex.NessusFindings = append(ex.NessusFindings, f)
					}
				}
			}

			// Merge CPEs
			if len(h.CPEs) > 0 {
				cpeSeen := make(map[string]bool)
				for _, c := range ex.CPEs {
					cpeSeen[c] = true
				}
				for _, c := range h.CPEs {
					if !cpeSeen[c] {
						ex.CPEs = append(ex.CPEs, c)
					}
				}
			}

			// Merge trace (take longer trace)
			if len(h.Trace) > len(ex.Trace) {
				ex.Trace = h.Trace
			}

			// NetBIOS
			if ex.NetBIOSName == "" && h.NetBIOSName != "" {
				ex.NetBIOSName = h.NetBIOSName
			}

			// Credentialed scan
			if h.CredScan {
				ex.CredScan = true
			}
		} else {
			hostCopy := h
			byIP[h.IP] = &hostCopy
		}
	}

	result := make([]models.Host, 0, len(byIP))
	for _, h := range byIP {
		result = append(result, *h)
	}

	// Sort by IP for consistent ordering
	sort.Slice(result, func(i, j int) bool {
		return result[i].IP < result[j].IP
	})

	return result
}

func portID(p models.Port) string {
	return fmt.Sprintf("%s/%d", p.Proto, p.Port)
}
