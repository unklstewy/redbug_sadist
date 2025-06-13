package analyzer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/unklstewy/redbug_sadist/pkg/protocol"
)

// AnalyzerInfo contains metadata about a registered analyzer
type AnalyzerInfo struct {
	Vendor string
	Model  string
	Modes  string // Comma-separated list: "read,write"
}

// Analyzer is the interface that all protocol analyzers must implement
type Analyzer interface {
	// Analyze performs analysis on the given file and returns structured results
	Analyze(filename string) (*protocol.AnalysisResult, error)

	// GetInfo returns metadata about this analyzer
	GetInfo() AnalyzerInfo
}

// registry holds all registered analyzers
var registry = make(map[string]map[string]map[string]Analyzer)

// RegisterAnalyzer registers a new analyzer for a specific vendor, model, and mode
func RegisterAnalyzer(analyzer Analyzer) {
	info := analyzer.GetInfo()
	vendor := strings.ToLower(info.Vendor)
	model := strings.ToLower(info.Model)

	// Initialize nested maps if they don't exist
	if _, exists := registry[vendor]; !exists {
		registry[vendor] = make(map[string]map[string]Analyzer)
	}

	if _, exists := registry[vendor][model]; !exists {
		registry[vendor][model] = make(map[string]Analyzer)
	}

	// Register for each supported mode
	modes := strings.Split(info.Modes, ",")
	for _, mode := range modes {
		mode = strings.TrimSpace(strings.ToLower(mode))
		registry[vendor][model][mode] = analyzer
	}
}

// GetAnalyzer retrieves the appropriate analyzer for a vendor, model, and mode
func GetAnalyzer(vendor, model, mode string) (Analyzer, error) {
	vendor = strings.ToLower(vendor)
	model = strings.ToLower(model)
	mode = strings.ToLower(mode)

	if vendorMap, exists := registry[vendor]; exists {
		if modelMap, exists := vendorMap[model]; exists {
			if analyzer, exists := modelMap[mode]; exists {
				return analyzer, nil
			}
			return nil, fmt.Errorf("no '%s' analyzer available for %s %s", mode, vendor, model)
		}
		return nil, fmt.Errorf("no analyzer available for %s %s", vendor, model)
	}
	return nil, fmt.Errorf("no analyzers available for vendor: %s", vendor)
}

// ListAvailableAnalyzers returns a list of all registered analyzers
func ListAvailableAnalyzers() []AnalyzerInfo {
	var result []AnalyzerInfo
	seen := make(map[string]bool)

	for vendor, vendorMap := range registry {
		for model, modelMap := range vendorMap {
			// Create a set of modes for this vendor/model combination
			modes := make([]string, 0, len(modelMap))
			for mode := range modelMap {
				modes = append(modes, mode)
			}
			sort.Strings(modes)

			key := vendor + "/" + model
			if !seen[key] {
				seen[key] = true
				result = append(result, AnalyzerInfo{
					Vendor: vendor,
					Model:  model,
					Modes:  strings.Join(modes, ","),
				})
			}
		}
	}

	// Sort results by vendor and model
	sort.Slice(result, func(i, j int) bool {
		if result[i].Vendor != result[j].Vendor {
			return result[i].Vendor < result[j].Vendor
		}
		return result[i].Model < result[j].Model
	})
urn result
	return result
}