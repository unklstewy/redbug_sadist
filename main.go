package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/unklstewy/redbug/pkg/cli"
	"github.com/unklstewy/redbug_sadist/pkg/protocol"
	"github.com/unklstewy/redbug_sadist/pkg/protocol/analyzer"
)

var sadistCommand = cli.CommandInfo{
	Name:        "analyze",
	Description: "Serial Protocol Analysis Tool",
	Usage:       "analyze <vendor> <model> <mode> <file> [flags]",
	Examples: []string{
		"analyze baofeng dm32uv read dmr_cps_read_capture.log",
		"analyze tyt md380 write dmr_cps_write_capture.log",
		"analyze --list-radios",
	},
}

func main() {
	// Check for list-radios flag
	if len(os.Args) > 1 && (os.Args[1] == "--list-radios" || os.Args[1] == "-l") {
		listSupportedRadios()
		return
	}

	// Check for help flag
	if len(os.Args) > 1 && (os.Args[1] == "--help" || os.Args[1] == "-h") {
		cli.PrintHelp(sadistCommand)
		return
	}

	if len(os.Args) < 4 {
		fmt.Println("Error: Insufficient arguments")
		cli.PrintHelp(sadistCommand)
		os.Exit(1)
	}

	// Parse command line arguments
	vendor := os.Args[1]
	model := os.Args[2]
	mode := os.Args[3]

	if mode != "read" && mode != "write" {
		fmt.Printf("Error: Invalid mode '%s'. Must be 'read' or 'write'.\n", mode)
		cli.PrintHelp(sadistCommand)
		os.Exit(1)
	}

	if len(os.Args) < 5 {
		fmt.Println("Error: Input file required")
		cli.PrintHelp(sadistCommand)
		os.Exit(1)
	}

	file := os.Args[4]

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

func listSupportedRadios() {
	fmt.Println("Supported Radios:")
	fmt.Println("================")

	radios := protocol.GetSupportedRadios()

	// Group by radio type
	radioTypes := make(map[string][]protocol.SupportedRadio)
	for _, radio := range radios {
		radioTypes[radio.Type] = append(radioTypes[radio.Type], radio)
	}

	// Display by type
	for typeName, typeRadios := range radioTypes {
		fmt.Printf("\n%s Radios:\n", typeName)
		fmt.Println(strings.Repeat("-", len(typeName)+8))

		for _, radio := range typeRadios {
			support := ""
			if radio.ReadSupport && radio.WriteSupport {
				support = "(Read/Write)"
			} else if radio.ReadSupport {
				support = "(Read only)"
			} else if radio.WriteSupport {
				support = "(Write only)"
			} else {
				support = "(No analysis yet)"
			}

			fmt.Printf("%-25s %-15s %s\n", radio.DisplayName, support, radio.Description)
		}
	}

	fmt.Println("\nUse 'analyze <vendor> <model> <mode> <file>' to analyze a capture file")
}

func printAvailableAnalyzers() {
	fmt.Println("\nAvailable analyzers:")

	analyzers := analyzer.ListAvailableAnalyzers()
	for _, a := range analyzers {
		fmt.Printf("  - %s %s (%s)\n", a.Vendor, a.Model, a.Modes)
	}
}
