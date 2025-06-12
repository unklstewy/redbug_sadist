package read

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"regexp"

	"github.com/unklstewy/redbug_pulitzer/pkg/reporting"
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

// Local CommandAPI type to be converted to protocol.CommandAPI
type CommandAPI struct {
	Command        string
	HexValue       string
	ASCIIValue     string
	Description    string
	ResponseType   string
	ResponseHex    string
	ResponseASCII  string
	FrequencyCount int
	TimingAverage  string
}

// AnalysisReport holds the complete analysis data
type AnalysisReport struct {
	TotalCommunications int
	CommandCount        int
	ResponseCount       int
	HandshakeSequences  []protocol.CommandResponse
	CommandResponses    []protocol.CommandResponse
	UniqueCommands      map[string]int
	FileDescriptors     map[string]string
	GeneratedAt         string
	Vendor              string
	Model               string
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

	// Define vendor and model
	vendor := "baofeng"
	model := "dm32uv"

	// Generate analysis report HTML
	reportFilename := "dm32uv_read_analysis.html"
	analysisReportPath := reporting.GetReportPath(vendor, model, reporting.ReportTypeReadAnalysis, reportFilename)
	a.generateHTMLReport(report, analysisReportPath)

	// Generate API documentation
	apiDocs := a.convertToProtocolAPICommands(a.generateCommandAPIDocumentation(cmdResponses))
	apiDocsFilename := "dm32uv_read_api_docs.html"
	apiDocsPath := reporting.GetReportPath(vendor, model, reporting.ReportTypeReadAPI, apiDocsFilename)
	reporting.GenerateAPIDocHTML(apiDocs, apiDocsFilename, reporting.ReadMode, vendor, model)

	fmt.Printf("\nAnalysis complete! Generated reports:\n")
	fmt.Printf("- Analysis report: %s\n", analysisReportPath)
	fmt.Printf("- API documentation: %s\n", apiDocsPath)

	return nil
}

// The rest of the implementation for parseStraceFile, analyzeCommandResponses, etc.
// continues with the existing methods from the original implementation...

// parseStraceFile parses a strace log file and extracts communications
func (a *DM32UVReadAnalyzer) parseStraceFile(filename string) []localCommunication {
	// Existing implementation from main.go
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer file.Close()

	var communications []localCommunication
	scanner := bufio.NewScanner(file)

	// Regex patterns for different types of communications
	writeRegex := regexp.MustCompile(`(\d{2}:\d{2}:\d{2}\.\d{6})\s+write\((\d+),\s*"([^"]*)"`)
	readRegex := regexp.MustCompile(`(\d{2}:\d{2}:\d{2}\.\d{6})\s+read\((\d+),\s*"([^"]*)"`)

	lineNum := 0
	for scanner.Scan() {
		line := scanner.Text()
		lineNum++

		// Check for write operations (PC → Radio commands)
		if matches := writeRegex.FindStringSubmatch(line); len(matches) >= 4 {
			data := utils.UnescapeString(matches[3])
			if len(data) > 0 {
				comm := localCommunication{
					Timestamp:    matches[1],
					Direction:    "PC→Radio",
					FileDesc:     matches[2],
					RawHex:       hex.EncodeToString(data),
					DecodedASCII: utils.DecodeToASCII(data),
					Length:       len(data),
					CommandType:  a.identifyCommandType(data),
				}
				communications = append(communications, comm)
			}
		}

		// Check for read operations (Radio → PC responses)
		if matches := readRegex.FindStringSubmatch(line); len(matches) >= 4 {
			data := utils.UnescapeString(matches[3])
			if len(data) > 0 {
				comm := localCommunication{
					Timestamp:    matches[1],
					Direction:    "Radio→PC",
					FileDesc:     matches[2],
					RawHex:       hex.EncodeToString(data),
					DecodedASCII: utils.DecodeToASCII(data),
					Length:       len(data),
					CommandType:  a.identifyResponseType(data),
				}
				communications = append(communications, comm)
			}
		}
	}

	return communications
}

// Add the rest of the method implementations from the original main.go,
// but modify them to be methods on DM32UVReadAnalyzer.
// Make sure to update any function calls to use the a. prefix for methods.

// Example:
func (a *DM32UVReadAnalyzer) identifyCommandType(data []byte) string {
	// Original implementation from main.go
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
			return fmt.Sprintf("ASCII Command '%c' (0x%02X)", firstByte, firstByte)
		}
		return fmt.Sprintf("Binary Command (0x%02X)", firstByte)
	}
}

// Continue with all the other methods similarly...
