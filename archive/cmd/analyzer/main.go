// ARCHIVED FILE - Original from: /home/sannis/REDBUG/redbug_sadist/cmd/analyzer/main.go
// Archived on: 2025-06-13
// This file was archived during project restructuring and kept for reference.
// The functionality has been migrated to new implementations.

package main

import (
	"fmt"
	"os"

	"github.com/unklstewy/redbug_sadist/pkg/protocol/analyzer"
)

func main() {
	if len(os.Args) < 5 {
		printUsage()
		os.Exit(1)
	}

	// Parse command line arguments
	vendor := os.Args[1]
	model := os.Args[2]
	mode := os.Args[3]
	file := os.Args[4]

	// Validate mode
	if mode != "read" && mode != "write" {
		fmt.Printf("Error: Invalid mode '%s'. Must be 'read' or 'write'.\n", mode)
		printUsage()
		os.Exit(1)
	}

	// Find the appropriate analyzer
	analyzerInstance, err := analyzer.GetAnalyzer(vendor, model, mode)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		printAvailableAnalyzers()
		os.Exit(1)
	}

	// Run the analyzer
	err = analyzerInstance.Analyze(file)
	if err != nil {
		fmt.Printf("Error during analysis: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Analysis completed successfully!")
}

func printUsage() {
	fmt.Println("Radio Protocol Analyzer")
	fmt.Println("=====================")
	fmt.Println("Usage:")
	fmt.Println("  redbug_sadist <vendor> <model> <mode> <file>")
	fmt.Println()
	fmt.Println("Parameters:")
	fmt.Println("  vendor - Radio manufacturer (e.g., baofeng, tyt, kenwood)")
	fmt.Println("  model  - Radio model (e.g., dm32uv, md380, th-d74)")
	fmt.Println("  mode   - Analysis mode: read or write")
	fmt.Println("  file   - Trace file to analyze")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  redbug_sadist baofeng dm32uv read dmr_cps_read_capture.log")
	fmt.Println("  redbug_sadist tyt md380 write dmr_cps_write_capture.log")
}

func printAvailableAnalyzers() {
	fmt.Println("\nAvailable analyzers:")

	analyzers := analyzer.ListAvailableAnalyzers()
	for _, a := range analyzers {
		fmt.Printf("  - %s %s (%s)\n", a.Vendor, a.Model, a.Modes)
	}
}
