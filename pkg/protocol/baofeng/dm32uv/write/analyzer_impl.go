package write

import (
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/unklstewy/redbug_sadist/pkg/protocol"
	"github.com/unklstewy/redbug_sadist/pkg/protocol/baofeng/dm32uv/dm32uv_commands/write_commands"
	"github.com/unklstewy/redbug_sadist/pkg/utils"
)

// CommandResponse represents a command and its response
type CommandResponse struct {
	Command       localCommunication
	Responses     []localCommunication
	TimeDelta     time.Duration
	ResponseBytes []byte
}

// APICommand represents a documented API command for external use
type APICommand struct {
	Name            string
	Description     string
	Format          string
	Parameters      string
	Direction       string
	Example         string
	Notes           string
	ResponseExample string
	ResponseFormat  string
}

// DM32UVWriteAnalyzer is the analyzer for Baofeng DM-32UV write operations
type DM32UVWriteAnalyzer struct {
	// Configuration options for the analyzer
	Config Config
}

// Config defines configuration options for the analyzer
type Config struct {
	VerboseOutput   bool
	GenerateReports bool
}

// analyzeCommandResponses groups commands with their responses and analyzes the communication
func (a *DM32UVWriteAnalyzer) analyzeCommandResponses(comms []localCommunication) *protocol.AnalysisResult {
	result := &protocol.AnalysisResult{
		AnalyzerName:   "Baofeng DM-32UV Write Protocol Analyzer",
		TimeStamp:      time.Now().Format(time.RFC3339),
		Communications: []protocol.Communication{},
		Summary: protocol.Summary{
			TotalCommands: 0,
			SuccessCount:  0,
			ErrorCount:    0,
			CommandTypes:  make(map[string]int),
		},
	}

	// Group commands and responses for more detailed analysis
	cmdResps := a.pairCommandsWithResponses(comms)

	// Convert local communications to protocol.Communication
	for _, comm := range comms {
		protocolComm := protocol.Communication{
			Timestamp: comm.Timestamp,
			Direction: comm.Direction,
			// Make sure FileDesc exists in protocol.Communication
			// If not, adjust this to match the actual field
			RawHex:       comm.RawHex,
			DecodedASCII: comm.DecodedASCII,
			Length:       comm.Length,
			CommandType:  comm.CommandType,
			Notes:        comm.Notes,
		}

		result.Communications = append(result.Communications, protocolComm)

		// Update summary statistics
		if comm.Direction == "WRITE" {
			result.Summary.TotalCommands++
			result.Summary.CommandTypes[comm.CommandType]++
		} else if comm.Direction == "READ" {
			if strings.Contains(comm.CommandType, "ACK") {
				result.Summary.SuccessCount++
			} else if strings.Contains(comm.CommandType, "NAK") {
				result.Summary.ErrorCount++
			}
		}
	}

	// Generate reports if configured to do so
	if a.Config.GenerateReports {
		reportPath := a.generateDetailedReport(comms, cmdResps)
		if reportPath != "" {
			a.generateHTMLReport(result)
		}
	}

	return result
}

// pairCommandsWithResponses pairs commands with their responses
func (a *DM32UVWriteAnalyzer) pairCommandsWithResponses(comms []localCommunication) []CommandResponse {
	var cmdResponses []CommandResponse

	for i := 0; i < len(comms); i++ {
		// If this is a command from PC to Radio (WRITE)
		if comms[i].Direction == "WRITE" {
			cmd := comms[i]

			// Look for responses (anything from Radio to PC after this command)
			var responses []localCommunication
			j := i + 1
			for j < len(comms) && comms[j].Direction == "READ" {
				responses = append(responses, comms[j])
				j++
			}

			// Calculate time delta if there are responses
			var timeDelta time.Duration
			var responseBytes []byte
			if len(responses) > 0 {
				cmdTime, _ := time.Parse("15:04:05.000000", cmd.Timestamp)
				respTime, _ := time.Parse("15:04:05.000000", responses[0].Timestamp)
				timeDelta = respTime.Sub(cmdTime)

				// Collect all response bytes
				for _, resp := range responses {
					respData, _ := hex.DecodeString(resp.RawHex)
					responseBytes = append(responseBytes, respData...)
				}
			}

			cmdResponse := CommandResponse{
				Command:       cmd,
				Responses:     responses,
				TimeDelta:     timeDelta,
				ResponseBytes: responseBytes,
			}
			cmdResponses = append(cmdResponses, cmdResponse)

			// Skip the responses we just processed
			i = j - 1
		}
	}

	return cmdResponses
}

// generateDetailedReport creates a detailed CSV and text report of the communication
func (a *DM32UVWriteAnalyzer) generateDetailedReport(comms []localCommunication, cmdResps []CommandResponse) string {
	// Create reports directory
	reportsDir := filepath.Join("reports", "protocol", "write", "baofeng", "dm32uv")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		log.Printf("Error creating reports directory: %v\n", err)
		return ""
	}

	// Generate a CSV file
	csvPath := filepath.Join(reportsDir, "dm32uv_write_communications_analysis.csv")
	csvFile, err := os.Create(csvPath)
	if err != nil {
		log.Printf("Error creating CSV file: %v\n", err)
		return ""
	}
	defer csvFile.Close()

	writer := csv.NewWriter(csvFile)
	defer writer.Flush()

	// Write CSV header
	writer.Write([]string{
		"Timestamp", "Direction", "Command Type", "Length", "Raw Hex", "ASCII", "Notes",
	})

	// Write all communications
	for _, comm := range comms {
		writer.Write([]string{
			comm.Timestamp,
			comm.Direction,
			comm.CommandType,
			fmt.Sprintf("%d", comm.Length),
			comm.RawHex,
			comm.DecodedASCII,
			comm.Notes,
		})
	}

	// Generate a text report
	reportPath := filepath.Join(reportsDir, "dm32uv_write_communications_report.txt")
	reportFile, err := os.Create(reportPath)
	if err != nil {
		log.Printf("Error creating report file: %v\n", err)
		return ""
	}
	defer reportFile.Close()

	// Write report header
	reportFile.WriteString("Baofeng DM-32UV Write Communications Analysis\n")
	reportFile.WriteString("=============================================\n\n")
	reportFile.WriteString(fmt.Sprintf("Total communications: %d\n", len(comms)))
	reportFile.WriteString(fmt.Sprintf("Command-response pairs: %d\n\n", len(cmdResps)))

	// Command statistics
	cmdTypes := make(map[string]int)
	for _, cr := range cmdResps {
		cmdTypes[cr.Command.CommandType]++
	}

	reportFile.WriteString("Command Types:\n")
	var cmdTypesSorted []string
	for cmdType := range cmdTypes {
		cmdTypesSorted = append(cmdTypesSorted, cmdType)
	}
	sort.Strings(cmdTypesSorted)

	for _, cmdType := range cmdTypesSorted {
		reportFile.WriteString(fmt.Sprintf("  %s: %d\n", cmdType, cmdTypes[cmdType]))
	}
	reportFile.WriteString("\n")

	// Detailed command-response analysis
	reportFile.WriteString("Command-Response Analysis:\n")
	for i, cr := range cmdResps {
		reportFile.WriteString(fmt.Sprintf("\n[%d] Command: %s\n", i+1, cr.Command.CommandType))
		reportFile.WriteString(fmt.Sprintf("    Time: %s\n", cr.Command.Timestamp))
		reportFile.WriteString(fmt.Sprintf("    Hex: %s\n", cr.Command.RawHex))
		reportFile.WriteString(fmt.Sprintf("    ASCII: %s\n", cr.Command.DecodedASCII))

		if len(cr.Responses) > 0 {
			reportFile.WriteString(fmt.Sprintf("    Response Time: %s (delta: %s)\n", cr.Responses[0].Timestamp, cr.TimeDelta))
			reportFile.WriteString(fmt.Sprintf("    Response Count: %d\n", len(cr.Responses)))

			for j, resp := range cr.Responses {
				reportFile.WriteString(fmt.Sprintf("      [%d] Type: %s\n", j+1, resp.CommandType))
				reportFile.WriteString(fmt.Sprintf("          Hex: %s\n", resp.RawHex))
				reportFile.WriteString(fmt.Sprintf("          ASCII: %s\n", resp.DecodedASCII))
			}
		} else {
			reportFile.WriteString("    No Response\n")
		}
	}

	return reportPath
}

// generateHTMLReport creates an HTML report for visualization
func (a *DM32UVWriteAnalyzer) generateHTMLReport(reportPath string) {
	// You would implement HTML report generation here
	// This could use templates to create a more interactive or visually appealing report
	reportsDir := filepath.Join("reports", "protocol", "write", "baofeng", "dm32uv")
	htmlPath := filepath.Join(reportsDir, "dm32uv_write_analysis.html")

	// Here you would generate HTML content and write it to the file
	// For now, we'll just create a simple placeholder
	htmlContent := `<!DOCTYPE html>
<html>
<head>
    <title>Baofeng DM-32UV Write Protocol Analysis</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 20px; }
        h1 { color: #333366; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #dddddd; text-align: left; padding: 8px; }
        th { background-color: #f2f2f2; }
        .pc-to-radio { background-color: #e6f7ff; }
        .radio-to-pc { background-color: #f0f0f0; }
    </style>
</head>
<body>
    <h1>Baofeng DM-32UV Write Protocol Analysis</h1>
    <p>This report provides an analysis of the write protocol communications with the Baofeng DM-32UV radio.</p>
    
    <h2>Summary</h2>
    <p>Total communications: ` + strconv.Itoa(len(comms)) + `</p>
    <p>Command-response pairs: ` + strconv.Itoa(len(cmdResps)) + `</p>
    
    <h2>Command Types</h2>
    <table>
        <tr>
            <th>Command Type</th>
            <th>Count</th>
        </tr>`
	for cmdType, count := range cmdTypes {
		htmlContent += `<tr>
            <td>` + cmdType + `</td>
            <td>` + strconv.Itoa(count) + `</td>
        </tr>`
	}
	htmlContent += `</table>
    
    <h2>Detailed Analysis</h2>`
	for i, cr := range cmdResps {
		htmlContent += `<h3>Command ` + strconv.Itoa(i+1) + `: ` + cr.Command.CommandType + `</h3>
        <p><strong>Time:</strong> ` + cr.Command.Timestamp + `</p>
        <p><strong>Hex:</strong> ` + cr.Command.RawHex + `</p>
        <p><strong>ASCII:</strong> ` + cr.Command.DecodedASCII + `</p>`
		if len(cr.Responses) > 0 {
			htmlContent += `<p><strong>Response Time:</strong> ` + cr.Responses[0].Timestamp + ` (delta: ` + cr.TimeDelta.String() + `)</p>
            <p><strong>Response Count:</strong> ` + strconv.Itoa(len(cr.Responses)) + `</p>
            <ul>`
			for _, resp := range cr.Responses {
				htmlContent += `<li>` + resp.RawHex + ` (` + resp.DecodedASCII + `)</li>`
			}
			htmlContent += `</ul>`
		} else {
			htmlContent += `<p>No Response</p>`
		}
	}

	htmlContent += `</body>
</html>`

	// Write the HTML content to file
	if err := os.WriteFile(htmlPath, []byte(htmlContent), 0644); err != nil {
		fmt.Printf("Error writing HTML report: %v\n", err)
	} else {
		fmt.Printf("HTML report generated: %s\n", htmlPath)
	}
}

// convertToProtocolAPICommands converts internal command representation to protocol API format
func (a *DM32UVWriteAnalyzer) convertToProtocolAPICommands(cmdResps []CommandResponse) []protocol.APICommand {
	var apiCommands []protocol.APICommand

	for _, cr := range cmdResps {
		// Skip unidentified or standard protocol commands
		if strings.Contains(cr.Command.CommandType, "Unknown") ||
			strings.Contains(cr.Command.CommandType, "ACK") ||
			strings.Contains(cr.Command.CommandType, "NAK") {
			continue
		}

		// Create an API command from this command-response pair
		cmdData, _ := hex.DecodeString(cr.Command.RawHex)

		// Try to get details from our command database
		var description, format, parameters string
		if cmd, found := write_commands.GetCommandDetails(cr.Command.CommandType); found {
			description = cmd.Description
			format = cmd.Format
			parameters = cmd.Parameters
		} else {
			description = "Write command for DM-32UV"
			format = utils.FormatHexBytes(cmdData)
			parameters = "See format"
		}

		apiCmd := protocol.APICommand{
			Name:        cr.Command.CommandType,
			Description: description,
			Format:      format,
			Parameters:  parameters,
			Direction:   "PC to Radio (Write)",
			Example:     cr.Command.RawHex,
			Notes:       "",
		}

		// Add response information if available
		if len(cr.Responses) > 0 {
			respExamples := make([]string, 0, len(cr.Responses))
			for _, resp := range cr.Responses {
				respExamples = append(respExamples, resp.RawHex)
			}
			apiCmd.ResponseExample = strings.Join(respExamples, ", ")
			apiCmd.ResponseFormat = utils.FormatHexBytes(cr.Responses[0].ResponseBytes)
		} else {
			apiCmd.ResponseExample = "None"
			apiCmd.ResponseFormat = "None"
		}

		apiCommands = append(apiCommands, apiCmd)
	}

	return apiCommands
}

// generateCommandAPIDocumentation creates API documentation for the commands
func (a *DM32UVWriteAnalyzer) generateCommandAPIDocumentation(apiCommands []protocol.APICommand) {
	reportsDir := filepath.Join("reports", "api", "baofeng", "dm32uv")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		fmt.Printf("Error creating API reports directory: %v\n", err)
		return
	}

	htmlPath := filepath.Join(reportsDir, "dm32uv_write_api_docs.html")

	// Here you would generate HTML API documentation
	// For now, we'll just create a simple placeholder
	htmlContent := `<!DOCTYPE html>
<html>
<head>
    <title>Baofeng DM-32UV Write Command API</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 20px; }
        h1 { color: #333366; }
        h2 { color: #666699; border-bottom: 1px solid #cccccc; padding-bottom: 5px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #dddddd; text-align: left; padding: 8px; }
        th { background-color: #f2f2f2; }
        pre { background-color: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>Baofeng DM-32UV Write Command API</h1>
    <p>This documentation describes the commands used in writing to the Baofeng DM-32UV radio.</p>
    
    <h2>Command Summary</h2>
    <p>Number of documented commands: ` + fmt.Sprintf("%d", len(apiCommands)) + `</p>
    
    <h2>Commands</h2>
    <!-- Command details would be inserted here by template processing -->
</body>
</html>`

	// Write the HTML content to file
	if err := os.WriteFile(htmlPath, []byte(htmlContent), 0644); err != nil {
		fmt.Printf("Error writing API documentation: %v\n", err)
	} else {
		fmt.Printf("API documentation generated: %s\n", htmlPath)
	}
}

// identifyCommand determines the command type based on the data
func (a *DM32UVWriteAnalyzer) identifyCommand(data []byte) string {
	// For now, let's just use the first byte to identify the command
	// This will be specific to the DM-32UV and should be expanded with real command parsing logic
	if len(data) == 0 {
		return "Unknown Command"
	}

	switch data[0] {
	case 0x57:
		return "Write Command"
	case 0x53:
		return "Status Command"
	}

	// If we get here, it's an unknown command
	return "Unknown Command"
}

// analyzeCommunications analyzes the communications and produces a structured result
func (a *DM32UVWriteAnalyzer) analyzeCommunications(comms []localCommunication) *protocol.AnalysisResult {
	result := &protocol.AnalysisResult{
		AnalyzerName:   "Baofeng DM-32UV Write Protocol Analyzer",
		TimeStamp:      time.Now().Format(time.RFC3339),
		Communications: []protocol.Communication{},
		Summary: protocol.Summary{
			TotalCommands: 0,
			SuccessCount:  0,
			ErrorCount:    0,
			CommandTypes:  make(map[string]int),
		},
	}

	// Convert local communications to protocol.Communication
	for _, comm := range comms {
		protocolComm := protocol.Communication{
			Timestamp:    comm.Timestamp,
			Direction:    comm.Direction,
			FileDesc:     comm.FileDesc,
			RawHex:       comm.RawHex,
			DecodedASCII: comm.DecodedASCII,
			Length:       comm.Length,
			CommandType:  comm.CommandType,
			Notes:        comm.Notes,
		}

		result.Communications = append(result.Communications, protocolComm)

		// Update summary statistics
		if comm.Direction == "WRITE" {
			result.Summary.TotalCommands++
			result.Summary.CommandTypes[comm.CommandType]++
		} else if comm.Direction == "READ" {
			if strings.Contains(comm.CommandType, "ACK") {
				result.Summary.SuccessCount++
			} else if strings.Contains(comm.CommandType, "NAK") {
				result.Summary.ErrorCount++
			}
		}
	}

	return result
}

// generateAnalysisReport creates a detailed report of the analysis
func (a *DM32UVWriteAnalyzer) generateAnalysisReport(result *protocol.AnalysisResult) string {
	var report strings.Builder

	report.WriteString("# Baofeng DM-32UV Write Protocol Analysis Report\n\n")
	report.WriteString(fmt.Sprintf("Analysis Time: %s\n\n", result.TimeStamp))

	report.WriteString("## Summary\n\n")
	report.WriteString(fmt.Sprintf("- Total Write Commands: %d\n", result.Summary.TotalCommands))
	report.WriteString(fmt.Sprintf("- Successful Commands: %d\n", result.Summary.SuccessCount))
	report.WriteString(fmt.Sprintf("- Failed Commands: %d\n", result.Summary.ErrorCount))

	report.WriteString("\n## Command Types\n\n")
	for cmdType, count := range result.Summary.CommandTypes {
		report.WriteString(fmt.Sprintf("- %s: %d\n", cmdType, count))
	}

	report.WriteString("\n## Detailed Communication Log\n\n")
	for i, comm := range result.Communications {
		report.WriteString(fmt.Sprintf("### Communication %d\n\n", i+1))
		report.WriteString(fmt.Sprintf("- Time: %s\n", comm.Timestamp))
		report.WriteString(fmt.Sprintf("- Direction: %s\n", comm.Direction))
		report.WriteString(fmt.Sprintf("- Command Type: %s\n", comm.CommandType))
		report.WriteString(fmt.Sprintf("- Raw Hex: %s\n", comm.RawHex))
		report.WriteString(fmt.Sprintf("- ASCII: %s\n", comm.DecodedASCII))
		if comm.Notes != "" {
			report.WriteString(fmt.Sprintf("- Notes: %s\n", comm.Notes))
		}
		report.WriteString("\n")
	}

	return report.String()
}

// generateHTMLReport creates an HTML version of the analysis report
func (a *DM32UVWriteAnalyzer) generateHTMLReport(result *protocol.AnalysisResult) string {
	var report strings.Builder

	// HTML header
	report.WriteString("<!DOCTYPE html>\n<html>\n<head>\n")
	report.WriteString("<title>Baofeng DM-32UV Write Protocol Analysis</title>\n")
	report.WriteString("<style>\n")
	report.WriteString("body { font-family: Arial, sans-serif; margin: 20px; }\n")
	report.WriteString("h1, h2, h3 { color: #333; }\n")
	report.WriteString("table { border-collapse: collapse; width: 100%; }\n")
	report.WriteString("th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n")
	report.WriteString("th { background-color: #f2f2f2; }\n")
	report.WriteString("tr:nth-child(even) { background-color: #f9f9f9; }\n")
	report.WriteString(".write { background-color: #e6f7ff; }\n")
	report.WriteString(".read { background-color: #f0fff0; }\n")
	report.WriteString("</style>\n</head>\n<body>\n")

	// Report header
	report.WriteString("<h1>Baofeng DM-32UV Write Protocol Analysis Report</h1>\n")
	report.WriteString(fmt.Sprintf("<p>Analysis Time: %s</p>\n", result.TimeStamp))

	// Summary section
	report.WriteString("<h2>Summary</h2>\n")
	report.WriteString("<ul>\n")
	report.WriteString(fmt.Sprintf("<li>Total Write Commands: %d</li>\n", result.Summary.TotalCommands))
	report.WriteString(fmt.Sprintf("<li>Successful Commands: %d</li>\n", result.Summary.SuccessCount))
	report.WriteString(fmt.Sprintf("<li>Failed Commands: %d</li>\n", result.Summary.ErrorCount))
	report.WriteString("</ul>\n")

	// Command types
	report.WriteString("<h2>Command Types</h2>\n")
	report.WriteString("<ul>\n")
	for cmdType, count := range result.Summary.CommandTypes {
		report.WriteString(fmt.Sprintf("<li>%s: %d</li>\n", cmdType, count))
	}
	report.WriteString("</ul>\n")

	// Communications table
	report.WriteString("<h2>Detailed Communication Log</h2>\n")
	report.WriteString("<table>\n")
	report.WriteString("<tr><th>#</th><th>Time</th><th>Direction</th><th>Command Type</th><th>Raw Hex</th><th>ASCII</th><th>Notes</th></tr>\n")

	for i, comm := range result.Communications {
		cssClass := "read"
		if comm.Direction == "WRITE" {
			cssClass = "write"
		}

		report.WriteString(fmt.Sprintf("<tr class=\"%s\">\n", cssClass))
		report.WriteString(fmt.Sprintf("<td>%d</td>\n", i+1))
		report.WriteString(fmt.Sprintf("<td>%s</td>\n", comm.Timestamp))
		report.WriteString(fmt.Sprintf("<td>%s</td>\n", comm.Direction))
		report.WriteString(fmt.Sprintf("<td>%s</td>\n", comm.CommandType))
		report.WriteString(fmt.Sprintf("<td>%s</td>\n", comm.RawHex))
		report.WriteString(fmt.Sprintf("<td>%s</td>\n", comm.DecodedASCII))
		report.WriteString(fmt.Sprintf("<td>%s</td>\n", comm.Notes))
		report.WriteString("</tr>\n")
	}

	report.WriteString("</table>\n")
	report.WriteString("</body>\n</html>\n")

	return report.String()
}

// FormatHexBytes formats a byte slice as a readable hex string
func FormatHexBytes(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	var builder strings.Builder
	for i, b := range data {
		if i > 0 {
			builder.WriteString(" ")
		}
		builder.WriteString(fmt.Sprintf("%02X", b))
	}
	return builder.String()
}
