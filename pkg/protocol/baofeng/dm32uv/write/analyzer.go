package write

import (
	"fmt"

	"github.com/unklstewy/redbug_sadist/pkg/protocol"
	"github.com/unklstewy/redbug_sadist/pkg/protocol/analyzer"
	"github.com/unklstewy/redbug_sadist/pkg/protocol/baofeng/dm32uv/dm32uv_commands/write_commands"
	"github.com/unklstewy/redbug_sadist/pkg/protocol/reporting"
)

// DM32UVWriteAnalyzer is the analyzer for Baofeng DM-32UV write operations
type DM32UVWriteAnalyzer struct {
	baseAnalyzer analyzer.BaseAnalyzer
	reportGen    *reporting.ReportGenerator
	config       Config
}

// Config defines configuration options for the analyzer
type Config struct {
	Debug     bool
	OutputDir string
}

// NewDM32UVWriteAnalyzer creates a new analyzer for the DM-32UV radio write operations
func NewDM32UVWriteAnalyzer() *DM32UVWriteAnalyzer {
	return &DM32UVWriteAnalyzer{
		baseAnalyzer: analyzer.BaseAnalyzer{
			Vendor: "baofeng",
			Model:  "dm32uv",
			Mode:   "write",
		},
		reportGen: reporting.NewReportGenerator(""),
		config: Config{
			Debug:     false,
			OutputDir: "",
		},
	}
}

// Initialize the analyzer by registering it
func init() {
	analyzer.RegisterAnalyzer(NewDM32UVWriteAnalyzer())
}

// GetInfo returns metadata about this analyzer
func (a *DM32UVWriteAnalyzer) GetInfo() analyzer.AnalyzerInfo {
	return analyzer.AnalyzerInfo{
		Vendor: a.baseAnalyzer.Vendor,
		Model:  a.baseAnalyzer.Model,
		Modes:  a.baseAnalyzer.Mode,
	}
}

// Analyze performs the full analysis workflow on a trace file
func (a *DM32UVWriteAnalyzer) Analyze(filename string) (*protocol.AnalysisResult, error) {
	fmt.Printf("Analyzing file: %s with DM32UVWriteAnalyzer\n", filename)

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

	// Add write-specific information
	for i := range cmdResps {
		// Set handshake flag and description
		cmdResps[i].IsHandshake = a.isHandshakeSequence(cmdResps[i].Command, cmdResps[i].Response)
		cmdResps[i].Description = a.generateDescription(cmdResps[i].Command, cmdResps[i].Response)

		// Set data category - Write operations have different categories
		cmdResps[i].DataCategory = a.categorizeWriteData(cmdResps[i].Command)
	}

	// Create analysis result
	result := a.baseAnalyzer.CreateBasicAnalysisResult(comms, cmdResps)

	// Generate reports
	a.generateAllReports(result)

	return result, nil
}

// generateAllReports generates all report formats
func (a *DM32UVWriteAnalyzer) generateAllReports(result *protocol.AnalysisResult) {
	// Similar to read analyzer but with write-specific customizations
}

// identifyCommandType determines the type of command based on the data
func (a *DM32UVWriteAnalyzer) identifyCommandType(data []byte) string {
	if len(data) == 0 {
		return "Empty"
	}

	// First try to identify using our command database
	if cmdName := a.identifyCommand(data); cmdName != "Unknown Command" {
		return cmdName
	}

	// Fall back to generic identification based on first byte
	firstByte := data[0]

	// Common DMR/Baofeng command patterns
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

// identifyCommand identifies the command based on the binary data
func (a *DM32UVWriteAnalyzer) identifyCommand(data []byte) string {
	// Check if it's a known command from the write commands package
	if len(data) > 0 {
		// For write commands, typically they start with 0x57 (ASCII 'W')
		if len(data) > 0 && data[0] == 0x57 {
			// Try to find a matching command in our defined commands
			cmdName, found := write_commands.FindMatchingCommand(data)
			if found {
				return cmdName
			}

			// If not found, but still looks like a write command, return a generic name
			return fmt.Sprintf("Write Command 0x%02X", data[1])
		}
	}

	// Return unknown if we couldn't identify it
	return "Unknown Write Command"
}

// Note: The following methods are implemented in analyzer_impl.go:
// - identifyResponseType
// - analyzeCommandResponses
// - generateAnalysisReport
// - generateHTMLReport
// - convertToProtocolAPICommands
// - generateCommandAPIDocumentation
