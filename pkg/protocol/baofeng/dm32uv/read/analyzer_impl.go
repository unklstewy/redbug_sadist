// filepath: /home/sannis/REDBUG/redbug_sadist/pkg/protocol/baofeng/dm32uv/read/analyzer_impl.go
package read

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"

	"github.com/unklstewy/redbug_pulitzer/pkg/reporting"
	"github.com/unklstewy/redbug_sadist/pkg/protocol"
)

// identifyResponseType determines the type of response based on content
func (a *DM32UVReadAnalyzer) identifyResponseType(data []byte) string {
	if len(data) == 0 {
		return "Empty"
	}

	// Check for common response types
	switch data[0] {
	case protocol.ACK: // ACK
		return "ACK (Acknowledge)"
	case protocol.NAK: // NAK
		return "NAK (Negative Acknowledge)"
	case protocol.STX: // STX
		return "Data Packet"
	default:
		return "Unknown Response"
	}
}

// analyzeCommandResponses matches commands with their responses
func (a *DM32UVReadAnalyzer) analyzeCommandResponses(communications []localCommunication) []protocol.CommandResponse {
	var commandResponses []protocol.CommandResponse

	// Track command-response pairs
	for i := 0; i < len(communications)-1; i++ {
		// Look for PC→Radio followed by Radio→PC
		if communications[i].Direction == "PC→Radio" && communications[i+1].Direction == "Radio→PC" {
			// Convert to protocol.Communication
			cmd := protocol.Communication{
				Timestamp:    communications[i].Timestamp,
				Direction:    communications[i].Direction,
				RawHex:       communications[i].RawHex,
				DecodedASCII: communications[i].DecodedASCII,
				Length:       communications[i].Length,
				CommandType:  communications[i].CommandType,
				Notes:        communications[i].Notes,
			}

			resp := protocol.Communication{
				Timestamp:    communications[i+1].Timestamp,
				Direction:    communications[i+1].Direction,
				RawHex:       communications[i+1].RawHex,
				DecodedASCII: communications[i+1].DecodedASCII,
				Length:       communications[i+1].Length,
				CommandType:  communications[i+1].CommandType,
				Notes:        communications[i+1].Notes,
			}

			// Create a command-response pair
			pair := protocol.CommandResponse{
				SequenceID:  i + 1, // 1-based index
				Command:     cmd,
				Response:    resp,
				TimeDelta:   "100ms", // Calculate actual time delta in a real implementation
				IsHandshake: a.isHandshakeSequence(cmd, resp),
				Description: fmt.Sprintf("%s - %s", cmd.CommandType, resp.CommandType),
			}

			commandResponses = append(commandResponses, pair)
		}
	}

	return commandResponses
}

// isHandshakeSequence determines if a command-response pair is part of a handshake
func (a *DM32UVReadAnalyzer) isHandshakeSequence(cmd, resp protocol.Communication) bool {
	// Simple handshake detection logic
	if cmd.CommandType == "Read Request" && resp.CommandType == "ACK (Acknowledge)" {
		return true
	}
	return false
}

// generateAnalysisReport creates a comprehensive analysis report
func (a *DM32UVReadAnalyzer) generateAnalysisReport(communications []localCommunication, cmdResponses []protocol.CommandResponse) protocol.AnalysisReport {
	report := protocol.AnalysisReport{
		Vendor:              "baofeng",
		Model:               "dm32uv",
		AnalysisType:        "read",
		TotalCommunications: len(communications),
		CommandCount:        0,
		ResponseCount:       0,
		HandshakeCount:      0,
		DataTransferCount:   0,
		ErrorCount:          0,
		TimestampStart:      "",
		TimestampEnd:        "",
		AverageResponseTime: "0ms", // Calculate this in a real implementation
		CommandResponses:    cmdResponses,
	}

	// Count command types
	for _, comm := range communications {
		if comm.Direction == "PC→Radio" {
			report.CommandCount++
		} else if comm.Direction == "Radio→PC" {
			report.ResponseCount++
		}
	}

	// Count handshakes and errors
	for _, cr := range cmdResponses {
		if cr.IsHandshake {
			report.HandshakeCount++
		}
		if strings.Contains(cr.Response.CommandType, "NAK") {
			report.ErrorCount++
		}
	}

	// Set timestamps
	if len(communications) > 0 {
		report.TimestampStart = communications[0].Timestamp
		report.TimestampEnd = communications[len(communications)-1].Timestamp
	}

	return report
}

// generateHTMLReport creates an HTML report for the analysis
func (a *DM32UVReadAnalyzer) generateHTMLReport(report protocol.AnalysisReport) {
	// Create a filename for the report
	filename := fmt.Sprintf("dm32uv_read_analysis.html")
	reportPath := reporting.GetReportPath("baofeng", "dm32uv", reporting.ReportTypeReadAnalysis, filename)

	// Create directory if it doesn't exist
	dir := filepath.Dir(reportPath)
	os.MkdirAll(dir, 0755)

	// Create a simple HTML template (simplified for this example)
	htmlTemplate := `
<!DOCTYPE html>
<html>
<head>
    <title>DM-32UV Read Protocol Analysis</title>
    <style>
        body { font-family: Arial, sans-serif; }
        h1 { color: #2980b9; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>DM-32UV Read Protocol Analysis</h1>
    <h2>Summary</h2>
    <p>Total Communications: {{.TotalCommunications}}</p>
    <p>Commands: {{.CommandCount}}</p>
    <p>Responses: {{.ResponseCount}}</p>
    <p>Handshakes: {{.HandshakeCount}}</p>
    <p>Errors: {{.ErrorCount}}</p>
    
    <h2>Command-Response Pairs</h2>
    <table>
        <tr>
            <th>Sequence</th>
            <th>Command</th>
            <th>Response</th>
            <th>Time Delta</th>
        </tr>
        {{range .CommandResponses}}
        <tr>
            <td>{{.SequenceID}}</td>
            <td>{{.Command.CommandType}}</td>
            <td>{{.Response.CommandType}}</td>
            <td>{{.TimeDelta}}</td>
        </tr>
        {{end}}
    </table>
</body>
</html>
`

	// Create and parse template
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		fmt.Printf("Error parsing template: %v\n", err)
		return
	}

	// Create output file
	file, err := os.Create(reportPath)
	if err != nil {
		fmt.Printf("Error creating HTML file: %v\n", err)
		return
	}
	defer file.Close()

	// Execute template
	err = tmpl.Execute(file, report)
	if err != nil {
		fmt.Printf("Error executing template: %v\n", err)
		return
	}

	fmt.Printf("Analysis report saved to: %s\n", reportPath)
}

// convertToProtocolAPICommands converts command-response pairs to API documentation
func (a *DM32UVReadAnalyzer) convertToProtocolAPICommands(cmdResponses []protocol.CommandResponse) []protocol.CommandAPI {
	var apiCommands []protocol.CommandAPI

	// Create a map to track unique commands
	commandMap := make(map[string]protocol.CommandAPI)

	for _, cr := range cmdResponses {
		cmd := cr.Command
		resp := cr.Response

		// Skip handshake sequences
		if cr.IsHandshake {
			continue
		}

		// Create a command name based on the hex value
		cmdName := fmt.Sprintf("CMD_%s", strings.ToUpper(cmd.RawHex[:min(4, len(cmd.RawHex))]))

		// Check if we've already seen this command
		if existingCmd, found := commandMap[cmdName]; found {
			// Update frequency count
			existingCmd.FrequencyCount++
			commandMap[cmdName] = existingCmd
		} else {
			// Create a new API command
			apiCmd := protocol.CommandAPI{
				Command:        cmdName,
				HexValue:       cmd.RawHex,
				ASCIIValue:     cmd.DecodedASCII,
				Description:    fmt.Sprintf("Read operation for %s", cmdName),
				ResponseType:   resp.CommandType,
				ResponseHex:    resp.RawHex,
				ResponseASCII:  resp.DecodedASCII,
				FrequencyCount: 1,
				TimingAverage:  cr.TimeDelta,
				DataCategory:   "read",
				SuccessRate:    "100%",
			}

			commandMap[cmdName] = apiCmd
		}
	}

	// Convert map to slice
	for _, cmd := range commandMap {
		apiCommands = append(apiCommands, cmd)
	}

	return apiCommands
}

// generateCommandAPIDocumentation creates API documentation for the protocol
func (a *DM32UVReadAnalyzer) generateCommandAPIDocumentation(apiCommands []protocol.CommandAPI) {
	// Convert to reporting type
	reportingCommands := convertToReportingCommandAPI(apiCommands)

	// Create a filename for the API docs
	filename := "dm32uv_read_api_docs.html"

	// Generate HTML using the reporting package
	reporting.GenerateAPIDocHTML(reportingCommands, filename, reporting.ReadMode, "baofeng", "dm32uv")

	fmt.Printf("API documentation saved\n")
}

// Helper function for min operation
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
