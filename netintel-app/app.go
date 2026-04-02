package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"netintel-app/internal/models"
	"netintel-app/internal/parser"
	"netintel-app/internal/risk"
	"netintel-app/internal/store"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

type App struct {
	ctx   context.Context
	store *store.Store
}

func NewApp() *App {
	return &App{
		store: store.New(),
	}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// ImportFile opens a file dialog and imports the selected scan file.
func (a *App) ImportFile() (*models.ScanData, error) {
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Import Scan File",
		Filters: []runtime.FileFilter{
			{DisplayName: "Scan Files (*.xml, *.nessus)", Pattern: "*.xml;*.nessus"},
			{DisplayName: "All Files", Pattern: "*.*"},
		},
	})
	if err != nil {
		return nil, err
	}
	if path == "" {
		return nil, nil // cancelled
	}

	return a.ImportFilePath(path)
}

// ImportFilePath imports a scan file from a given path.
func (a *App) ImportFilePath(path string) (*models.ScanData, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	format := parser.DetectFormat(data)

	var hosts []models.Host
	var source *models.ScanSource

	switch format {
	case "nmap":
		hosts, source, err = parser.ParseNmapXML(data)
	case "nessus":
		hosts, source, err = parser.ParseNessusXML(data)
	default:
		return nil, &ImportError{File: filepath.Base(path), Msg: "unrecognized file format (expected nmap XML or .nessus)"}
	}

	if err != nil {
		return nil, err
	}

	// Score risks
	hosts = risk.ScoreHosts(hosts)

	// Update source name to include filename
	if source != nil {
		source.Name = filepath.Base(path)
	}

	a.store.AddHosts(hosts, source)

	result := a.store.GetData()
	return &result, nil
}

// GetScanData returns the current scan data.
func (a *App) GetScanData() models.ScanData {
	return a.store.GetData()
}

// GetDashboardStats returns pre-computed dashboard statistics.
func (a *App) GetDashboardStats() models.DashboardStats {
	data := a.store.GetData()
	return risk.ComputeStats(data.Hosts)
}

// ClearData resets all imported data.
func (a *App) ClearData() {
	a.store.Clear()
}

// ExportJSON exports scan data as JSON.
func (a *App) ExportJSON() (string, error) {
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "Export JSON",
		DefaultFilename: "netintel-export.json",
		Filters: []runtime.FileFilter{
			{DisplayName: "JSON Files", Pattern: "*.json"},
		},
	})
	if err != nil || path == "" {
		return "", err
	}

	data := a.store.GetData()
	jsonBytes, err := jsonMarshal(data)
	if err != nil {
		return "", err
	}

	if err := os.WriteFile(path, jsonBytes, 0644); err != nil {
		return "", err
	}
	return path, nil
}

// ExportCSV exports host summary as CSV.
func (a *App) ExportCSV() (string, error) {
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "Export CSV",
		DefaultFilename: "netintel-export.csv",
		Filters: []runtime.FileFilter{
			{DisplayName: "CSV Files", Pattern: "*.csv"},
		},
	})
	if err != nil || path == "" {
		return "", err
	}

	data := a.store.GetData()
	var sb strings.Builder
	sb.WriteString("IP,Hostname,Status,OS,OpenPorts,RiskScore,CleartextCount\n")
	for _, h := range data.Hosts {
		osName := ""
		if len(h.OS) > 0 {
			osName = h.OS[0].Name
		}
		openPorts := 0
		for _, p := range h.Ports {
			if p.State == "open" {
				openPorts++
			}
		}
		sb.WriteString(csvLine(h.IP, h.Hostname, h.Status, osName, openPorts, h.RiskScore, h.CleartextCount))
	}

	if err := os.WriteFile(path, []byte(sb.String()), 0644); err != nil {
		return "", err
	}
	return path, nil
}

type ImportError struct {
	File string
	Msg  string
}

func (e *ImportError) Error() string {
	return e.File + ": " + e.Msg
}
