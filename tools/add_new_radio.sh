#!/bin/bash
# filepath: REDBUG/redbug_sadist/tools/add_new_radio.sh

# Script to create a new radio analyzer template

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <vendor> <model> <mode>"
    echo "Example: $0 kenwood th-d74 read"
    exit 1
fi

VENDOR=$1
MODEL=$2
MODE=$3

# Convert to lowercase for directory names
VENDOR_LOWER=$(echo $VENDOR | tr '[:upper:]' '[:lower:]')
MODEL_LOWER=$(echo $MODEL | tr '[:upper:]' '[:lower:]')
MODE_LOWER=$(echo $MODE | tr '[:upper:]' '[:lower:]')

# Validate mode
if [ "$MODE_LOWER" != "read" ] && [ "$MODE_LOWER" != "write" ]; then
    echo "Error: Mode must be 'read' or 'write'"
    exit 1
fi

# Create directory structure
DIR_PATH="pkg/protocol/$VENDOR_LOWER/$MODEL_LOWER/$MODE_LOWER"
mkdir -p "$DIR_PATH"

# Create analyzer.go file
cat > "$DIR_PATH/analyzer.go" << EOF
package $MODE_LOWER

import (
    "fmt"
    
    "github.com/unklstewy/redbug_pulitzer/pkg/reporting"
    "github.com/unklstewy/redbug_sadist/pkg/protocol/analyzer"
)

// ${MODEL_LOWER^}${MODE^}Analyzer implements the analyzer interface for $VENDOR $MODEL $MODE operations
type ${MODEL_LOWER^}${MODE^}Analyzer struct{}

// Initialize the analyzer by registering it
func init() {
    analyzer.RegisterAnalyzer(&${MODEL_LOWER^}${MODE^}Analyzer{})
}

// GetInfo returns metadata about this analyzer
func (a *${MODEL_LOWER^}${MODE^}Analyzer) GetInfo() analyzer.AnalyzerInfo {
    return analyzer.AnalyzerInfo{
        Vendor: "$VENDOR_LOWER",
        Model:  "$MODEL_LOWER",
        Modes:  "$MODE_LOWER",
    }
}

// Analyze performs the full analysis workflow on a trace file
func (a *${MODEL_LOWER^}${MODE^}Analyzer) Analyze(filename string) error {
    fmt.Printf("$VENDOR $MODEL $MODE Operation Protocol Analyzer\n")
    fmt.Printf("=============================================\n")
    fmt.Printf("Analyzing file: %s\n\n", filename)
    
    // TODO: Implement analyzer logic here
    
    // Define vendor and model
    vendor := "$VENDOR_LOWER"
    model := "$MODEL_LOWER"
    
    // Generate analysis report HTML
    reportFilename := "${MODEL_LOWER}_${MODE_LOWER}_analysis.html"
    analysisReportPath := reporting.GetReportPath(vendor, model, reporting.ReportType${MODE^}Analysis, reportFilename)
    
    // TODO: Generate the report
    
    fmt.Printf("\nAnalysis complete! Generated reports:\n")
    fmt.Printf("- Analysis report: %s\n", analysisReportPath)
    
    return nil
}
EOF

# Update supported_radios.go
# This would be more complex in reality to avoid duplicates, so just providing instructions
echo ""
echo "New radio analyzer template created at: $DIR_PATH/analyzer.go"
echo ""
echo "Next steps:"
echo "1. Implement the analyzer logic in $DIR_PATH/analyzer.go"
echo "2. Update pkg/protocol/supported_radios.go to include this radio"
echo "3. Test with: redbug_sadist $VENDOR $MODEL $MODE <file>"
