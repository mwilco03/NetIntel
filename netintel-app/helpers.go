package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

func jsonMarshal(v interface{}) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

func csvLine(ip, hostname, status, os string, openPorts, riskScore, cleartext int) string {
	return fmt.Sprintf("%s,%s,%s,%s,%d,%d,%d\n",
		csvEscape(ip), csvEscape(hostname), csvEscape(status), csvEscape(os),
		openPorts, riskScore, cleartext)
}

func csvEscape(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}
