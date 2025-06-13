package write

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/unklstewy/redbug_sadist/pkg/protocol"
	"github.com/unklstewy/redbug_sadist/pkg/protocol/analyzer"
	"github.com/unklstewy/redbug_sadist/pkg/protocol/baofeng/dm32uv/common"
	"github.com/unklstewy/redbug_sadist/pkg/protocol/baofeng/dm32uv/dm32uv_commands/write_commands"
	"github.com/unklstewy/redbug_sadist/pkg/utils"
)

// NewDM32UVWriteAnalyzer creates a new analyzer for the DM-32UV radio write operations
func NewDM32UVWriteAnalyzer(config Config) *DM32UVWriteAnalyzer {
	return &DM32UVWriteAnalyzer{
		Config: config,
	}
}

// Initialize the analyzer by registering it
func init() {
	// Create a default configuration
	defaultConfig := Config{
		Debug:     false,
		OutputDir: "",
	}
	// Create and register the analyzer with default config
	analyzer.RegisterAnalyzer(NewDM32UVWriteAnalyzer(defaultConfig))
}

// GetInfo returns metadata about this analyzer
func (a *DM32UVWriteAnalyzer) GetInfo() analyzer.AnalyzerInfo {
	return analyzer.AnalyzerInfo{
		Vendor: "baofeng",
		Model:  "dm32uv",
		Modes:  "write",
	}
}

// Analyze performs the full analysis workflow on a trace file
func (a *DM32UVWriteAnalyzer) Analyze(filename string) (*protocol.AnalysisResult, error) {
	log.Printf("Analyzing file: %s with DM32UVWriteAnalyzer", filename)

	// Parse the strace file to extract communications
	comms, err := a.parseStraceFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to parse strace file: %w", err)
	}

	// Process and analyze the communications
	result := a.analyzeCommandResponses(comms)

	return result, nil
}

// parseStraceFile parses a strace log file and extracts communications
func (a *DM32UVWriteAnalyzer) parseStraceFile(filename string) ([]common.Communication, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	var communications []common.Communication
	scanner := bufio.NewScanner(file)

	// A single regex to match both read/write lines with optional "..." and capturing the entire string:
	logRegex := regexp.MustCompile(`(?i)^(\d+)\s+(\d{2}:\d{2}:\d{2}\.\d{6})\s+(read|write)\((\d+),\s*"([^"]*)(?:\.\.\.)?",\s*(\d+)\)\s*=\s*(\d+)`)

	for scanner.Scan() {
		line := scanner.Text()

		// Skip hex dumps
		if strings.HasPrefix(line, " | ") {
			continue
		}

		matches := logRegex.FindStringSubmatch(line)
		if len(matches) == 8 {
			pid := matches[1]
			timestamp := matches[2]
			op := matches[3] // "read" or "write"
			fileDesc := matches[4]
			dataStr := matches[5] // captured content in quotes
			//lengthStr := matches[6]
			_ = matches[7] // actual bytes read/written

			data := utils.UnescapeString(dataStr)
			if op == "write" {
				comm := common.Communication{
					Timestamp:    timestamp,
					Direction:    "PC→Radio",
					FileDesc:     fileDesc,
					RawHex:       hex.EncodeToString(data),
					DecodedASCII: utils.DecodeToASCII(data),
					Length:       len(data),
					CommandType:  a.identifyCommandType(data),
					Notes:        fmt.Sprintf("PID:%s", pid),
				}
				communications = append(communications, comm)
			} else {
				comm := common.Communication{
					Timestamp:    timestamp,
					Direction:    "Radio→PC",
					FileDesc:     fileDesc,
					RawHex:       hex.EncodeToString(data),
					DecodedASCII: utils.DecodeToASCII(data),
					Length:       len(data),
					CommandType:  a.identifyResponseType(data),
					Notes:        fmt.Sprintf("PID:%s", pid),
				}
				communications = append(communications, comm)
			}
		} else {
			fmt.Printf("No match: %s\n", line)
		}
	}

	return communications, nil
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
