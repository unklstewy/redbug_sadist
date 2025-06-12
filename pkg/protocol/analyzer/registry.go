package analyzer

import (
	"fmt"
	"sort"
	"strings"
)

// AnalyzerInfo contains metadata about a registered analyzer
type AnalyzerInfo struct {
	Vendor string
	Model  string
	Modes  string // Comma-separated list: "read,write"
}

// Analyzer is the interface that all protocol analyzers must implement
type Analyzer interface {
	// Analyze performs analysis on the given file
	Analyze(filename string) error

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

	// Check if the vendor exists
	if vendorMap, exists := registry[vendor]; exists {
		// Check if the model exists
		if modelMap, exists := vendorMap[model]; exists {
			// Check if the mode exists
			if analyzer, exists := modelMap[mode]; exists {
				return analyzer, nil
			} else {
				return nil, fmt.Errorf("no '%s' analyzer available for %s %s", mode, vendor, model)
			}
		} else {
			return nil, fmt.Errorf("no analyzer available for %s %s", vendor, model)
		}
	} else {
		return nil, fmt.Errorf("no analyzers available for vendor: %s", vendor)
	}
}

// ListAvailableAnalyzers returns a list of all registered analyzers
func ListAvailableAnalyzers() []AnalyzerInfo {
	var result []AnalyzerInfo

	// Collect unique analyzer info entries
	seen := make(map[string]bool)

	for vendor, vendorMap := range registry {
		for model, modelMap := range vendorMap {
			// Create a set of modes for this vendor/model combination
			modes := make([]string, 0, len(modelMap))
			for mode := range modelMap {
				modes = append(modes, mode)
			}

			// Sort modes for consistent output
			sort.Strings(modes)

			// Create a unique key for this vendor/model
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

	return result
}
