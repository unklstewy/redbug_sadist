package read

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
	"github.com/unklstewy/redbug_sadist/pkg/utils"
)

// This type can be used locally for parsing, then converted to protocol.Communication
type localCommunication struct {
	Timestamp    string
	Direction    string
	FileDesc     string
	RawHex       string
	DecodedASCII string
	Length       int
	CommandType  string
	Notes        string
}

// DM32UVReadAnalyzer implements the analyzer interface for Baofeng DM-32UV read operations
type DM32UVReadAnalyzer struct{}

// Initialize the analyzer by registering it
func init() {
	analyzer.RegisterAnalyzer(&DM32UVReadAnalyzer{})
}

// GetInfo returns metadata about this analyzer
func (a *DM32UVReadAnalyzer) GetInfo() analyzer.AnalyzerInfo {
	return analyzer.AnalyzerInfo{
		Vendor: "baofeng",
		Model:  "dm32uv",
		Modes:  "read",
	}
}

// Analyze performs the full analysis workflow on a trace file
func (a *DM32UVReadAnalyzer) Analyze(filename string) error {
	fmt.Printf("Baofeng DM-32UV Read Operation Protocol Analyzer\n")
	fmt.Printf("=============================================\n")
	fmt.Printf("Analyzing file: %s\n\n", filename)

	communications := a.parseStraceFile(filename)
	if len(communications) == 0 {
		return fmt.Errorf("no communications found in the strace file")
	}

	fmt.Printf("Found %d communications\n", len(communications))

	// Analyze command-response pairs
	cmdResponses := a.analyzeCommandResponses(communications)

	// Generate analysis report
	report := a.generateAnalysisReport(communications, cmdResponses)

	// Generate HTML report
	a.generateHTMLReport(report)

	// Generate API documentation
	apiCommands := a.convertToProtocolAPICommands(cmdResponses)
	a.generateCommandAPIDocumentation(apiCommands)

	fmt.Printf("\nAnalysis complete!\n")

	return nil
}

// parseStraceFile parses a strace log file and extracts communications
func (a *DM32UVReadAnalyzer) parseStraceFile(filename string) []localCommunication {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer file.Close()

	var communications []localCommunication
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
				comm := localCommunication{
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
				comm := localCommunication{
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

	return communications
}

// identifyCommandType determines the type of command based on the data
func (a *DM32UVReadAnalyzer) identifyCommandType(data []byte) string {
	if len(data) == 0 {
		return "Empty"
	}

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

// Note: The following methods are implemented in analyzer_impl.go:
// - identifyResponseType
// - analyzeCommandResponses
// - generateAnalysisReport
// - generateHTMLReport
// - convertToProtocolAPICommands
// - generateCommandAPIDocumentation
