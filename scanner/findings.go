package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"cicd-guard/types"

	"github.com/fatih/color"
)

// Findings represents a collection of findings
type Findings struct {
	items []types.Finding
}

// NewFindings creates a new findings collection
func NewFindings() *Findings {
	return &Findings{
		items: make([]types.Finding, 0),
	}
}

// Add adds findings to the collection
func (f *Findings) Add(findings ...types.Finding) {
	f.items = append(f.items, findings...)
}

// FilterBySeverity filters findings by severity level
func (f *Findings) FilterBySeverity(severity string) *Findings {
	filtered := NewFindings()
	sev := types.Severity(strings.ToUpper(severity))

	for _, finding := range f.items {
		if finding.Severity == sev {
			filtered.Add(finding)
		}
	}

	return filtered
}

// OutputConsole outputs findings to console with color coding
func (f *Findings) OutputConsole() error {
	if len(f.items) == 0 {
		color.Green("✅ No security issues found!")
		return nil
	}

	// Sort by severity and file
	sort.Slice(f.items, func(i, j int) bool {
		if f.items[i].Severity != f.items[j].Severity {
			return f.items[i].Severity == types.SeverityHigh
		}
		return f.items[i].File < f.items[j].File
	})

	color.Red("🚨 Found %d security issues:\n", len(f.items))

	for _, finding := range f.items {
		switch finding.Severity {
		case types.SeverityHigh:
			color.Red("[%s]", finding.Severity)
		case types.SeverityMedium:
			color.Yellow("[%s]", finding.Severity)
		case types.SeverityLow:
			color.Blue("[%s]", finding.Severity)
		}

		fmt.Printf(" %s (%s)", finding.Message, finding.RuleID)
		fmt.Printf(" File: %s:%d", finding.File, finding.Line)
		fmt.Println()

		if finding.Rule != "" {
			color.Cyan("   Rule: %s", finding.Rule)
		}
		if finding.Context != "" {
			color.Cyan("   Context: %s", finding.Context)
		}
		fmt.Println()
	}

	return nil
}

// OutputJSON outputs findings in JSON format
func (f *Findings) OutputJSON() error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(f.items)
}
