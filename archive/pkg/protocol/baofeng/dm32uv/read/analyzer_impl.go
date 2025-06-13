// ARCHIVED FILE - Original from: /home/sannis/REDBUG/redbug_sadist/pkg/protocol/baofeng/dm32uv/read/analyzer_impl.go
// Archived on: 2025-06-13
// This file was archived during project restructuring and kept for reference.
// The functionality has been migrated to new implementations.

// filepath: /home/sannis/REDBUG/redbug_sadist/pkg/protocol/baofeng/dm32uv/read/analyzer_impl.go
package read

import (
	"encoding/hex"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/unklstewy/redbug_pulitzer/pkg/reporting"
	"github.com/unklstewy/redbug_sadist/pkg/protocol"
	"github.com/unklstewy/redbug_sadist/pkg/protocol/baofeng/dm32uv/common"
)

// identifyResponseType determines the type of response based on content
func (a *DM32UVReadAnalyzer) identifyResponseType(data []byte) string {
	if len(data) == 0 {
		return "Empty"
	}

	// First try to identify using our command database
	if cmdName := a.identifyCommand(data); cmdName != "Unknown Command" {
		return cmdName + " Response"
	}

	// Then fall back to your existing response type identification logic
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
func (a *DM32UVReadAnalyzer) analyzeCommandResponses(comms []common.Communication) *protocol.AnalysisResult {
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

// Add or update parsing logic to handle the specific log format

// parseLogFile parses the CPS log file format
func (a *DM32UVReadAnalyzer) ParseLogFile(data []byte) ([]CommandResponsePair, error) {
	lines := strings.Split(string(data), "\n")
	var pairs []CommandResponsePair
	var currentCmd *Command

	fmt.Printf("Parsing log file with %d lines\n", len(lines))

	// First, let's try to detect the format of the log
	if len(lines) > 0 {
		firstLine := strings.TrimSpace(lines[0])
		fmt.Printf("First line: %s\n", firstLine)

		// Check if it's a strace-style log
		straceRegex := regexp.MustCompile(`(?i)^(\d+)\s+(\d{2}:\d{2}:\d{2}\.\d{6})\s+(read|write)`)

		if straceRegex.MatchString(firstLine) {
			// Parse strace format
			return a.parseStraceFormat(lines)
		}

		// Check if it's a simple CMD/RSP format
		cmdRspRegex := regexp.MustCompile(`(?i)^(CMD|RSP):`)

		if cmdRspRegex.MatchString(firstLine) {
			// Parse CMD/RSP format
			return a.parseCmdRspFormat(lines)
		}
	}

	// If we can't determine the format, try a generic approach
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fmt.Printf("Processing line %d: %s\n", i, line)

		// Try to extract any hex data from the line
		hexPattern := regexp.MustCompile(`[0-9A-Fa-f]+`)
		hexMatches := hexPattern.FindAllString(line, -1)

		if len(hexMatches) > 0 {
			// Find the longest hex string (likely the data)
			var hexData string
			for _, match := range hexMatches {
				if len(match) > len(hexData) {
					hexData = match
				}
			}

			// Only process if we have something that looks like valid hex
			if len(hexData) >= 2 {
				data, err := hex.DecodeString(hexData)
				if err == nil && len(data) > 0 {
					// Guess if it's a command or response based on content
					if strings.Contains(strings.ToLower(line), "cmd") ||
						strings.Contains(strings.ToLower(line), "tx") ||
						strings.Contains(strings.ToLower(line), "write") {
						// This is likely a command
						now := time.Now()
						currentCmd = &Command{Data: data, Timestamp: now}

						// Create a new pair
						pairs = append(pairs, CommandResponsePair{
							Command:   *currentCmd,
							Responses: []Response{},
						})

						fmt.Printf("Found command: %x\n", data)
					} else if currentCmd != nil {
						// This is likely a response to the previous command
						now := time.Now()
						resp := Response{Data: data, Timestamp: now}

						// Add to the last pair
						if len(pairs) > 0 {
							lastPairIdx := len(pairs) - 1
							pairs[lastPairIdx].Responses = append(pairs[lastPairIdx].Responses, resp)
							fmt.Printf("Found response: %x\n", data)
						}
					}
				}
			}
		}
	}

	fmt.Printf("Parsed %d command-response pairs\n", len(pairs))
	return pairs, nil
}

// parseCmdRspFormat parses logs in CMD/RSP format
func (a *DM32UVReadAnalyzer) parseCmdRspFormat(lines []string) ([]CommandResponsePair, error) {
	var pairs []CommandResponsePair
	var currentCmd *Command

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "CMD:") {
			// New command
			hexData := strings.TrimPrefix(line, "CMD:")
			hexData = strings.TrimSpace(hexData)
			data, err := hex.DecodeString(strings.ReplaceAll(hexData, " ", ""))

			if err == nil {
				now := time.Now()
				currentCmd = &Command{Data: data, Timestamp: now}

				// Create a new pair
				pairs = append(pairs, CommandResponsePair{
					Command:   *currentCmd,
					Responses: []Response{},
				})

				fmt.Printf("Found command: %x\n", data)
			}
		} else if strings.HasPrefix(line, "RSP:") && len(pairs) > 0 {
			// Response to current command
			hexData := strings.TrimPrefix(line, "RSP:")
			hexData = strings.TrimSpace(hexData)
			data, err := hex.DecodeString(strings.ReplaceAll(hexData, " ", ""))

			if err == nil {
				now := time.Now()
				resp := Response{Data: data, Timestamp: now}

				// Add to the last pair
				lastPairIdx := len(pairs) - 1
				pairs[lastPairIdx].Responses = append(pairs[lastPairIdx].Responses, resp)
				fmt.Printf("Found response: %x\n", data)
			}
		}
	}

	return pairs, nil
}

// parseStraceFormat parses logs in strace format with hex dumps
func (a *DM32UVReadAnalyzer) parseStraceFormat(lines []string) ([]CommandResponsePair, error) {
	var pairs []CommandResponsePair
	//var currentHexData []byte
	var currentPair *CommandResponsePair

	// Regex for strace write/read lines and hex dumps
	writeRegex := regexp.MustCompile(`(\d+)\s+(\d{2}:\d{2}:\d{2}\.\d+)\s+write\(.*\)`)
	readRegex := regexp.MustCompile(`(\d+)\s+(\d{2}:\d{2}:\d{2}\.\d+)\s+read\(.*\)`)
	hexDumpRegex := regexp.MustCompile(`\|\s+[0-9a-f]+\s+((?:[0-9a-f]{2}\s+)+).*\|`)

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		// Check for write operation (starting a new command)
		if writeRegex.MatchString(line) {
			// Collect hex data from the next lines
			hexData, nextIndex := collectHexDumpData(lines, i+1, hexDumpRegex)
			i = nextIndex // Skip the hex dump lines we just processed

			if len(hexData) > 0 {
				// Create a new command-response pair
				timeVal, _ := time.Parse("15:04:05.000000", "00:00:00.000000") // Default time
				cmd := Command{
					Data:      hexData,
					Timestamp: timeVal,
				}

				currentPair = &CommandResponsePair{
					Command:   cmd,
					Responses: []Response{},
				}
				pairs = append(pairs, *currentPair)
				fmt.Printf("Found command: %x\n", hexData)
			}
			continue
		}

		// Check for read operation (adding a response to the current command)
		if readRegex.MatchString(line) && len(pairs) > 0 {
			// Collect hex data from the next lines
			hexData, nextIndex := collectHexDumpData(lines, i+1, hexDumpRegex)
			i = nextIndex // Skip the hex dump lines we just processed

			if len(hexData) > 0 {
				// Add response to the last pair
				timeVal, _ := time.Parse("15:04:05.000000", "00:00:00.000000") // Default time
				resp := Response{
					Data:      hexData,
					Timestamp: timeVal,
				}

				lastPairIdx := len(pairs) - 1
				pairs[lastPairIdx].Responses = append(pairs[lastPairIdx].Responses, resp)
				fmt.Printf("Found response: %x\n", hexData)
			}
			continue
		}
	}

	// Keep only pairs that have both commands and responses
	var validPairs []CommandResponsePair
	for _, pair := range pairs {
		if len(pair.Command.Data) > 0 && len(pair.Responses) > 0 {
			validPairs = append(validPairs, pair)
		}
	}

	fmt.Printf("Parsed %d valid command-response pairs from strace format\n", len(validPairs))
	return validPairs, nil
}

// collectHexDumpData collects hex data from dump lines following an operation
func collectHexDumpData(lines []string, startIdx int, hexDumpRegex *regexp.Regexp) ([]byte, int) {
	var hexData []byte
	i := startIdx

	for i < len(lines) {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			i++
			continue
		}

		// Check if this is a hex dump line
		if matches := hexDumpRegex.FindStringSubmatch(line); len(matches) >= 2 {
			hexBytes := matches[1]
			// Clean up the hex string
			hexBytes = strings.ReplaceAll(hexBytes, " ", "")

			// Convert to bytes
			lineBytes, err := hex.DecodeString(hexBytes)
			if err == nil {
				hexData = append(hexData, lineBytes...)
			}
			i++
		} else {
			// This is not a hex dump line, so we're done collecting
			break
		}
	}

	return hexData, i - 1 // Return the last processed index
}

// hexToBytes converts hex string to bytes
func hexToBytes(hexStr string) ([]byte, error) {
	// Remove spaces, 0x prefixes, etc.
	hexStr = strings.ReplaceAll(hexStr, " ", "")
	hexStr = strings.ReplaceAll(hexStr, "0x", "")

	return hex.DecodeString(hexStr)
}

// Helper function for min operation
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
