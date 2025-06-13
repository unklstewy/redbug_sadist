package read

import (
	"fmt"
	"strings"

	"github.com/unklstewy/redbug_sadist/pkg/protocol"
	"github.com/unklstewy/redbug_sadist/pkg/protocol/analyzer"
	"github.com/unklstewy/redbug_sadist/pkg/protocol/baofeng/dm32uv/dm32uv_commands/read_commands"
	"github.com/unklstewy/redbug_sadist/pkg/protocol/reporting"
)

// DM32UVReadAnalyzer is the analyzer for Baofeng DM-32UV read operations
type DM32UVReadAnalyzer struct {
	baseAnalyzer analyzer.BaseAnalyzer
	reportGen    *reporting.ReportGenerator
}

// NewDM32UVReadAnalyzer creates a new analyzer for the DM-32UV radio
func NewDM32UVReadAnalyzer() *DM32UVReadAnalyzer {
	return &DM32UVReadAnalyzer{
		baseAnalyzer: analyzer.BaseAnalyzer{
			Vendor: "baofeng",
			Model:  "dm32uv",
			Mode:   "read",
		},
		reportGen: reporting.NewReportGenerator(""),
	}
}

// Initialize the analyzer by registering it
func init() {
	analyzer.RegisterAnalyzer(NewDM32UVReadAnalyzer())
}

// GetInfo returns metadata about this analyzer
func (a *DM32UVReadAnalyzer) GetInfo() analyzer.AnalyzerInfo {
	return analyzer.AnalyzerInfo{
		Vendor: a.baseAnalyzer.Vendor,
		Model:  a.baseAnalyzer.Model,
		Modes:  a.baseAnalyzer.Mode,
	}
}

// Analyze performs the full analysis workflow on a trace file
func (a *DM32UVReadAnalyzer) Analyze(filename string) (*protocol.AnalysisResult, error) {
	fmt.Printf("Analyzing file: %s with DM32UVReadAnalyzer\n", filename)

	// Parse the strace file to extract communications
	comms, err := a.baseAnalyzer.ParseStraceFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to parse strace file: %w", err)
	}

	// Identify command types
	for i := range comms {
		comms[i].CommandType = a.identifyCommandType([]byte(comms[i].RawHex))
	}

	// Pair commands with their responses
	cmdResps := a.baseAnalyzer.PairCommandsWithResponses(comms)

	// Add read-specific information
	for i := range cmdResps {
		// Set handshake flag and description
		cmdResps[i].IsHandshake = a.isHandshakeSequence(cmdResps[i].Command, cmdResps[i].Response)
		cmdResps[i].Description = a.generateDescription(cmdResps[i].Command, cmdResps[i].Response)

		// Set data category
		if cmdResps[i].IsHandshake {
			cmdResps[i].DataCategory = "Handshake"
		} else if a.isDataTransfer(cmdResps[i].Command, cmdResps[i].Response) {
			cmdResps[i].DataCategory = "Data Transfer"
		} else {
			cmdResps[i].DataCategory = "Command"
		}
	}

	// Create analysis result
	result := a.baseAnalyzer.CreateBasicAnalysisResult(comms, cmdResps)

	// Generate reports
	a.generateAllReports(result)

	return result, nil
}

// generateAllReports generates all report formats
func (a *DM32UVReadAnalyzer) generateAllReports(result *protocol.AnalysisResult) {
	_, err := a.reportGen.GenerateTextReport(result)
	if err != nil {
		fmt.Printf("Warning: failed to generate text report: %v\n", err)
	}

	_, err = a.reportGen.GenerateCSVReport(result)
	if err != nil {
		fmt.Printf("Warning: failed to generate CSV report: %v\n", err)
	}

	htmlPath, err := a.reportGen.GenerateHTMLReport(result)
	if err != nil {
		fmt.Printf("Warning: failed to generate HTML report: %v\n", err)
	} else {
		fmt.Printf("Generated HTML report: %s\n", htmlPath)
	}
}

// identifyCommandType determines the type of command based on the data
func (a *DM32UVReadAnalyzer) identifyCommandType(data []byte) string {
	// First try to identify using the command database
	if cmdName, found := read_commands.FindMatchingCommand(data); found {
		return cmdName
	}

	// Generic identification based on first byte
	if len(data) == 0 {
		return "Empty"
	}

	firstByte := data[0]

	switch firstByte {
	case protocol.STX:
		return "STX (Start of Text)"
	case protocol.ACK:
		return "ACK (Acknowledge)"
	case protocol.NAK:
		return "NAK (Negative Acknowledge)"
	case 0x52: // 'R'
		return "Read Request"
	case 0x57: // 'W'
		return "Write Request"
	case 0x50: // 'P'
		return "Program Command"
	case protocol.SOH:
		return "SOH (Start of Header)"
	case protocol.ETX:
		return "ETX (End of Text)"
	case protocol.EOT:
		return "EOT (End of Transmission)"
	case 0x7E:
		return "Packet Frame (~)"
	default:
		if firstByte >= 0x20 && firstByte <= 0x7E {
			return fmt.Sprintf("ASCII Command (%c)", firstByte)
		}
		return fmt.Sprintf("Unknown (0x%02X)", firstByte)
	}
}

// isHandshakeSequence determines if a command-response pair is part of a handshake
func (a *DM32UVReadAnalyzer) isHandshakeSequence(cmd, resp protocol.Communication) bool {
	// Simple handshake detection logic
	if cmd.CommandType == "Read Request" && resp.CommandType == "ACK (Acknowledge)" {
		return true
	}
	return false
}

// isDataTransfer determines if the command-response pair is a data transfer
func (a *DM32UVReadAnalyzer) isDataTransfer(cmd, resp protocol.Communication) bool {
	// Detect data transfer patterns
	return strings.Contains(cmd.CommandType, "Data") || strings.Contains(resp.CommandType, "Data")
}

// generateDescription creates a human-readable description of the command-response pair
func (a *DM32UVReadAnalyzer) generateDescription(cmd, resp protocol.Communication) string {
	if a.isHandshakeSequence(cmd, resp) {
		return "Handshake: " + cmd.CommandType + " → " + resp.CommandType
	}

	// Generate specific descriptions based on command type
	if strings.Contains(cmd.CommandType, "Read") {
		if strings.Contains(resp.CommandType, "ACK") {
			return "Read Operation: Command acknowledged"
		} else if strings.Contains(resp.CommandType, "Data") {
			return "Read Operation: Data received from radio"
		}
	}

	// Default description
	return cmd.CommandType + " → " + resp.CommandType
}
