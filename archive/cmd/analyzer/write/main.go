// ARCHIVED FILE - Original from: /home/sannis/REDBUG/redbug_sadist/cmd/analyzer/write/main.go
// Archived on: 2025-06-13
// This file was archived during project restructuring and kept for reference.
// The functionality has been migrated to new implementations.

package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/unklstewy/redbug_sadist/pkg/protocol"
	"github.com/unklstewy/redbug_pulitzer/pkg/reporting"
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
	DataCategory   string // Write-specific
	SuccessRate    string // Write-specific
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("DM-32UV Write Operation Protocol Analyzer")
		fmt.Println("=========================================")
		fmt.Println("")
		fmt.Println("Usage:")
		fmt.Println("  go run cmd/write_analyzer/main.go <strace_file>")
		fmt.Println("")
		fmt.Println("Examples:")
		fmt.Println("  go run cmd/write_analyzer/main.go dmr_cps_write_capture.log")
		fmt.Println("  go run cmd/write_analyzer/main.go trace_data.log")
		fmt.Println("")
		fmt.Println("Output:")
		fmt.Println("  - dm32uv_write_analysis.html (detailed HTML report)")
		os.Exit(1)
	}

	filename := os.Args[1]

	fmt.Printf("DM-32UV Write Operation Protocol Analyzer\n")
	fmt.Printf("==========================================\n")
	fmt.Printf("Analyzing file: %s\n\n", filename)

	communications := parseStraceFile(filename)
	if len(communications) == 0 {
		log.Fatal("No communications found in the strace file")
	}

	fmt.Printf("Found %d communications\n", len(communications))

	// Analyze command-response pairs
	cmdResponses := analyzeCommandResponses(communications)

	// Generate analysis report
	report := generateAnalysisReport(communications, cmdResponses)

	// Create HTML output
	generateHTMLReport(report, "dm32uv_write_analysis.html")

	// Generate API documentation
	apiDocs := convertToProtocolAPICommands(generateCommandAPIDocumentation(cmdResponses))
	reporting.GenerateAPIDocHTML(apiDocs, "dm32uv_write_api_docs.html", reporting.WriteMode)

	fmt.Printf("\nAnalysis complete! Generated dm32uv_write_analysis.html\n")
	fmt.Printf("API documentation generated: dm32uv_write_api_docs.html\n")
	fmt.Printf("Summary: %d commands, %d responses, %d handshakes, %d programming blocks\n",
		report.CommandCount, report.ResponseCount, len(report.HandshakeSequences), len(report.ProgrammingBlocks))
}

func parseStraceFile(filename string) []localCommunication {
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

		// Check for write operations (PC → Radio commands/data)
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
					CommandType:  identifyWriteCommandType(data),
				}
				communications = append(communications, comm)
			}
		}

		// Check for read operations (Radio → PC acknowledgments)
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
					CommandType:  identifyWriteResponseType(data),
				}
				communications = append(communications, comm)
			}
		}
	}

	return communications
}

// Convert the local communication type to the shared protocol.Communication type
func convertToProtocolCommunication(comm localCommunication) protocol.Communication {
	return protocol.Communication{
		Timestamp:    comm.Timestamp,
		Direction:    comm.Direction,
		FileDesc:     comm.FileDesc,
		RawHex:       comm.RawHex,
		DecodedASCII: comm.DecodedASCII,
		Length:       comm.Length,
		CommandType:  comm.CommandType,
		Notes:        comm.Notes,
	}
}

// Convert local CommandAPI to protocol.CommandAPI
func convertToProtocolAPICommands(apiDocs []CommandAPI) []protocol.CommandAPI {
	result := make([]protocol.CommandAPI, len(apiDocs))
	for i, doc := range apiDocs {
		result[i] = protocol.CommandAPI{
			Command:        doc.Command,
			HexValue:       doc.HexValue,
			ASCIIValue:     doc.ASCIIValue,
			Description:    doc.Description,
			ResponseType:   doc.ResponseType,
			ResponseHex:    doc.ResponseHex,
			ResponseASCII:  doc.ResponseASCII,
			FrequencyCount: doc.FrequencyCount,
			TimingAverage:  doc.TimingAverage,
			DataCategory:   doc.DataCategory,
			SuccessRate:    doc.SuccessRate,
		}
	}
	return result
}

func analyzeCommandResponses(communications []localCommunication) []protocol.CommandResponse {
	var cmdResponses []protocol.CommandResponse
	var pendingCommands []localCommunication

	sequenceID := 1

	for _, comm := range communications {
		if comm.Direction == "PC→Radio" {
			// This is a command/data, add to pending
			pendingCommands = append(pendingCommands, comm)
		} else if comm.Direction == "Radio→PC" {
			// This is a response, try to match with pending command
			if len(pendingCommands) > 0 {
				// Match with the most recent command
				cmd := pendingCommands[len(pendingCommands)-1]
				pendingCommands = pendingCommands[:len(pendingCommands)-1]

				// Calculate time delta
				timeDelta := calculateTimeDelta(cmd.Timestamp, comm.Timestamp)

				cmdResp := protocol.CommandResponse{
					SequenceID:   sequenceID,
					Command:      convertToProtocolCommunication(cmd),
					Response:     convertToProtocolCommunication(comm),
					TimeDelta:    timeDelta,
					IsHandshake:  isHandshakeSequence(cmd, comm),
					Description:  generateWriteDescription(cmd, comm),
					DataCategory: categorizeWriteData(cmd),
				}

				cmdResponses = append(cmdResponses, cmdResp)
				sequenceID++
			}
		}
	}

	return cmdResponses
}

func identifyWriteCommandType(data []byte) string {
	if len(data) == 0 {
		return "Empty"
	}

	firstByte := data[0]

	// Common DMR/Baofeng write command patterns
	switch firstByte {
	case 0x02:
		return "STX (Start Programming)"
	case 0x06:
		return "ACK (Acknowledge)"
	case 0x15:
		return "NAK (Negative Acknowledge)"
	case 0x57: // 'W'
		return "Write Command"
	case 0x50: // 'P'
		return "Program Initiate"
	case 0x01:
		return "SOH (Start of Header)"
	case 0x03:
		return "ETX (End of Block)"
	case 0x04:
		return "EOT (End Programming)"
	case 0x7E:
		return "Frame Start (~)"
	case 0x10:
		return "DLE (Data Link Escape)"
	default:
		// Analyze data patterns for write operations
		if len(data) > 16 {
			if containsChannelData(data) {
				return "Channel Data Block"
			} else if containsZoneData(data) {
				return "Zone Data Block"
			} else if containsContactData(data) {
				return "Contact Data Block"
			} else if containsConfigData(data) {
				return "Configuration Block"
			} else {
				return "Large Data Block"
			}
		} else if len(data) > 4 {
			return "Small Data Block"
		}

		if firstByte >= 0x20 && firstByte <= 0x7E {
			return fmt.Sprintf("ASCII Command '%c' (0x%02X)", firstByte, firstByte)
		}
		return fmt.Sprintf("Binary Command (0x%02X)", firstByte)
	}
}

func identifyWriteResponseType(data []byte) string {
	if len(data) == 0 {
		return "Empty ACK"
	}

	firstByte := data[0]

	switch firstByte {
	case 0x06:
		return "ACK (Data Accepted)"
	case 0x15:
		return "NAK (Data Rejected)"
	case 0x02:
		return "STX Response"
	case 0x01:
		return "SOH Response"
	case 0x03:
		return "ETX Response"
	case 0x04:
		return "EOT Response"
	default:
		if len(data) == 1 {
			return fmt.Sprintf("Single Byte Response (0x%02X)", firstByte)
		}
		return fmt.Sprintf("Multi-byte Response (0x%02X)", firstByte)
	}
}

func categorizeWriteData(cmd localCommunication) string {
	data, err := hex.DecodeString(cmd.RawHex)
	if err != nil || len(data) == 0 {
		return "Unknown"
	}

	if len(data) <= 4 {
		return "Control Command"
	} else if len(data) <= 16 {
		return "Short Data"
	} else if containsChannelData(data) {
		return "Channel Programming"
	} else if containsZoneData(data) {
		return "Zone Programming"
	} else if containsContactData(data) {
		return "Contact Programming"
	} else if containsConfigData(data) {
		return "System Configuration"
	} else {
		return "Bulk Data"
	}
}

func containsChannelData(data []byte) bool {
	// Look for patterns that suggest channel data
	// Check for frequency patterns, channel names, etc.
	if len(data) < 32 {
		return false
	}

	// Look for frequency-like patterns (common in channel data)
	freqPatterns := [][]byte{
		{0x43, 0x36}, // Common frequency prefix
		{0x44, 0x36}, // Another frequency pattern
	}

	for _, pattern := range freqPatterns {
		if containsPattern(data, pattern) {
			return true
		}
	}

	return false
}

func containsZoneData(data []byte) bool {
	// Zone data often contains channel lists
	if len(data) < 16 {
		return false
	}

	// Look for repeating patterns that suggest channel indices
	return hasRepeatingBytePattern(data)
}

func containsContactData(data []byte) bool {
	// Contact data often contains call signs or IDs
	if len(data) < 8 {
		return false
	}

	// Look for patterns that suggest DMR IDs or call signs
	return containsMostlyPrintable(data) && hasNumericPatterns(data)
}

func containsConfigData(data []byte) bool {
	// Configuration data often has specific headers
	if len(data) < 4 {
		return false
	}

	// Look for common config patterns
	configPatterns := [][]byte{
		{0xFF, 0xFF}, // Common padding
		{0x00, 0x00}, // Zero padding
	}

	for _, pattern := range configPatterns {
		if containsPattern(data, pattern) {
			return true
		}
	}

	return false
}

func isHandshakeSequence(cmd, resp localCommunication) bool {
	// Common handshake patterns for write operations
	cmdFirst := []byte{}
	respFirst := []byte{}

	if cmd.RawHex != "" {
		if decoded, err := hex.DecodeString(cmd.RawHex); err == nil && len(decoded) > 0 {
			cmdFirst = decoded[:1]
		}
	}
	if resp.RawHex != "" {
		if decoded, err := hex.DecodeString(resp.RawHex); err == nil && len(decoded) > 0 {
			respFirst = decoded[:1]
		}
	}

	if len(cmdFirst) > 0 && len(respFirst) > 0 {
		// Common write handshake patterns
		if (cmdFirst[0] == 0x02 && respFirst[0] == 0x06) || // STX -> ACK
			(cmdFirst[0] == 0x01 && respFirst[0] == 0x06) || // SOH -> ACK
			(cmdFirst[0] == 0x04 && respFirst[0] == 0x06) || // EOT -> ACK
			(cmdFirst[0] == 0x50 && respFirst[0] == 0x06) { // Program -> ACK
			return true
		}
	}

	// Short command-response pairs are likely handshakes
	return cmd.Length <= 4 && resp.Length <= 4
}

func generateWriteDescription(cmd, resp localCommunication) string {
	if isHandshakeSequence(cmd, resp) {
		return "Handshake: " + cmd.CommandType + " → " + resp.CommandType
	}

	// Identify write-specific operations
	if strings.Contains(cmd.CommandType, "Program") {
		return "Programming: Initiating radio programming mode"
	}

	if strings.Contains(cmd.CommandType, "Channel") {
		return "Channel Programming: Writing channel configuration"
	}

	if strings.Contains(cmd.CommandType, "Zone") {
		return "Zone Programming: Writing zone configuration"
	}

	if strings.Contains(cmd.CommandType, "Contact") {
		return "Contact Programming: Writing contact list"
	}

	if strings.Contains(cmd.CommandType, "Data Block") {
		if strings.Contains(resp.CommandType, "ACK") {
			return "Data Transfer: Configuration data accepted by radio"
		} else if strings.Contains(resp.CommandType, "NAK") {
			return "Data Transfer: Configuration data rejected by radio"
		}
		return "Data Transfer: Sending configuration to radio"
	}

	return fmt.Sprintf("Write Operation: %s → %s", cmd.CommandType, resp.CommandType)
}

func generateAnalysisReport(communications []localCommunication, cmdResponses []protocol.CommandResponse) AnalysisReport {
	report := AnalysisReport{
		TotalCommunications: len(communications),
		UniqueCommands:      make(map[string]int),
		FileDescriptors:     make(map[string]string),
		DataCategories:      make(map[string]int),
		GeneratedAt:         time.Now().Format("2006-01-02 15:04:05"),
	}

	// Count commands and responses
	for _, comm := range communications {
		if comm.Direction == "PC→Radio" {
			report.CommandCount++
			report.UniqueCommands[comm.CommandType]++
			report.FileDescriptors[comm.FileDesc] = "Write (PC→Radio)"
		} else {
			report.ResponseCount++
			report.FileDescriptors[comm.FileDesc] = "Read (Radio→PC)"
		}
	}

	// Categorize command-responses
	for _, cmdResp := range cmdResponses {
		if cmdResp.IsHandshake {
			report.HandshakeSequences = append(report.HandshakeSequences, cmdResp)
		} else if strings.Contains(cmdResp.DataCategory, "Programming") {
			report.ProgrammingBlocks = append(report.ProgrammingBlocks, cmdResp)
		} else {
			report.CommandResponses = append(report.CommandResponses, cmdResp)
		}

		report.DataCategories[cmdResp.DataCategory]++
	}

	return report
}

func generateCommandAPIDocumentation(cmdResponses []protocol.CommandResponse) []CommandAPI {
	// Map to track unique commands
	uniqueCommands := make(map[string]CommandAPI)
	timingMap := make(map[string][]time.Duration)
	successMap := make(map[string]struct{ success, total int })

	// Process all command-response pairs
	for _, cr := range cmdResponses {
		// Create a unique key for this command based on its hex value
		cmdKey := cr.Command.RawHex

		// Parse timing for averaging
		timeDuration := parseTimeDelta(cr.TimeDelta)
		if timeDuration > 0 {
			timingMap[cmdKey] = append(timingMap[cmdKey], timeDuration)
		}

		// Track success rate (ACK responses indicate success)
		if _, exists := successMap[cmdKey]; !exists {
			successMap[cmdKey] = struct{ success, total int }{0, 0}
		}
		stats := successMap[cmdKey]
		stats.total++
		if strings.Contains(cr.Response.CommandType, "ACK") {
			stats.success++
		}
		successMap[cmdKey] = stats

		// If we've seen this command before, just increment its count
		if api, exists := uniqueCommands[cmdKey]; exists {
			api.FrequencyCount++
			uniqueCommands[cmdKey] = api
			continue
		}

		// Otherwise, create a new API entry
		apiEntry := CommandAPI{
			Command:        cr.Command.CommandType,
			HexValue:       cr.Command.RawHex,
			ASCIIValue:     cr.Command.DecodedASCII,
			Description:    cr.Description,
			ResponseType:   cr.Response.CommandType,
			ResponseHex:    cr.Response.RawHex,
			ResponseASCII:  cr.Response.DecodedASCII,
			FrequencyCount: 1,
			TimingAverage:  cr.TimeDelta, // Initial value, will be averaged later
			DataCategory:   cr.DataCategory,
			SuccessRate:    "100%", // Initial value, will be calculated later
		}

		uniqueCommands[cmdKey] = apiEntry
	}

	// Calculate average timing for each command
	for cmdKey, api := range uniqueCommands {
		// Update timing average
		if times, exists := timingMap[cmdKey]; exists && len(times) > 0 {
			var total time.Duration
			for _, t := range times {
				total += t
			}
			avg := total / time.Duration(len(times))

			if avg < time.Millisecond {
				api.TimingAverage = fmt.Sprintf("%.2f µs", float64(avg.Microseconds()))
			} else {
				api.TimingAverage = fmt.Sprintf("%.2f ms", float64(avg.Microseconds())/1000.0)
			}
		}

		// Update success rate
		if stats, exists := successMap[cmdKey]; exists && stats.total > 0 {
			successRate := float64(stats.success) / float64(stats.total) * 100
			api.SuccessRate = fmt.Sprintf("%.1f%%", successRate)
		}

		uniqueCommands[cmdKey] = api
	}

	// Convert map to slice for sorting
	var apiDocs []CommandAPI
	for _, api := range uniqueCommands {
		apiDocs = append(apiDocs, api)
	}

	// Sort by frequency (most common first)
	sort.Slice(apiDocs, func(i, j int) bool {
		return apiDocs[i].FrequencyCount > apiDocs[j].FrequencyCount
	})

	return apiDocs
}

func generateHTMLReport(report AnalysisReport, filename string) {
	htmlTemplate := `
<!DOCTYPE html>
<html>
<head>
    <title>DM-32UV Write Operation Analysis</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #c0392b; text-align: center; border-bottom: 3px solid #e74c3c; padding-bottom: 10px; }
        h2 { color: #a93226; margin-top: 30px; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; font-size: 12px; }
        th, td { border: 1px solid #ddd; padding: 6px; text-align: left; vertical-align: top; }
        th { background-color: #e74c3c; color: white; font-weight: bold; }
        .command { background-color: #fdf2e9; }
        .response { background-color: #ebf5fb; }
        .handshake { background-color: #fff5e6; }
        .programming { background-color: #e8f8e8; }
        .hex { font-family: 'Courier New', monospace; font-size: 11px; word-break: break-all; max-width: 200px; }
        .ascii { font-family: 'Courier New', monospace; font-size: 11px; color: #666; max-width: 150px; word-break: break-all; }
        .summary { background-color: #fadbd8; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .timestamp { font-size: 10px; color: #666; }
        .stats { display: flex; justify-content: space-around; margin: 20px 0; }
        .stat-box { text-align: center; padding: 15px; background-color: #e74c3c; color: white; border-radius: 5px; flex: 1; margin: 0 5px; }
        .command-type { font-weight: bold; color: #c0392b; }
        .description { font-style: italic; color: #7f8c8d; }
        .category { background-color: #f8f9fa; padding: 2px 6px; border-radius: 3px; font-size: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>📝 DM-32UV Write Operation Protocol Analysis</h1>
        
        <div class="summary">
            <h2>📊 Write Operation Summary</h2>
            <div class="stats">
                <div class="stat-box">
                    <div style="font-size: 24px; font-weight: bold;">{{.TotalCommunications}}</div>
                    <div>Total Communications</div>
                </div>
                <div class="stat-box">
                    <div style="font-size: 24px; font-weight: bold;">{{.CommandCount}}</div>
                    <div>PC→Radio Commands</div>
                </div>
                <div class="stat-box">
                    <div style="font-size: 24px; font-weight: bold;">{{.ResponseCount}}</div>
                    <div>Radio→PC ACKs</div>
                </div>
                <div class="stat-box">
                    <div style="font-size: 24px; font-weight: bold;">{{len .ProgrammingBlocks}}</div>
                    <div>Programming Blocks</div>
                </div>
            </div>
            <p><strong>Generated:</strong> {{.GeneratedAt}}</p>
        </div>

        <h2>🔌 File Descriptors Used</h2>
        <table>
            <tr><th>File Descriptor</th><th>Usage</th></tr>
            {{range $fd, $usage := .FileDescriptors}}
            <tr><td><strong>{{$fd}}</strong></td><td>{{$usage}}</td></tr>
            {{end}}
        </table>

        <h2>📋 Command Types Summary</h2>
        <table>
            <tr><th>Command Type</th><th>Frequency</th><th>Percentage</th></tr>
            {{range $cmd, $count := .UniqueCommands}}
            <tr><td class="command-type">{{$cmd}}</td><td>{{$count}}</td><td>{{percentage $count $.CommandCount}}%</td></tr>
            {{end}}
        </table>

        <h2>🗂️ Data Categories</h2>
        <table>
            <tr><th>Data Category</th><th>Count</th><th>Percentage</th></tr>
            {{range $cat, $count := .DataCategories}}
            <tr><td class="category">{{$cat}}</td><td>{{$count}}</td><td>{{percentage $count $.TotalCommunications}}%</td></tr>
            {{end}}
        </table>

        <h2>🤝 Handshake Sequences</h2>
        <table>
            <tr>
                <th width="5%">Seq</th>
                <th width="10%">Time</th>
                <th width="25%">Command (PC→Radio)</th>
                <th width="25%">Response (Radio→PC)</th>
                <th width="8%">Delta</th>
                <th width="27%">Description</th>
            </tr>
            {{range .HandshakeSequences}}
            <tr class="handshake">
                <td>{{.SequenceID}}</td>
                <td class="timestamp">{{.Command.Timestamp}}</td>
                <td class="command">
                    <div class="command-type">{{.Command.CommandType}}</div>
                    <div class="hex">{{.Command.RawHex}}</div>
                    <div class="ascii">{{.Command.DecodedASCII}}</div>
                </td>
                <td class="response">
                    <div class="command-type">{{.Response.CommandType}}</div>
                    <div class="hex">{{.Response.RawHex}}</div>
                    <div class="ascii">{{.Response.DecodedASCII}}</div>
                </td>
                <td>{{.TimeDelta}}</td>
                <td class="description">{{.Description}}</td>
            </tr>
            {{end}}
        </table>

        <h2>🔧 Programming Data Blocks</h2>
        <table>
            <tr>
                <th width="5%">Seq</th>
                <th width="8%">Category</th>
                <th width="10%">Time</th>
                <th width="25%">Data Block (PC→Radio)</th>
                <th width="20%">Response (Radio→PC)</th>
                <th width="8%">Delta</th>
                <th width="24%">Description</th>
            </tr>
            {{range .ProgrammingBlocks}}
            <tr class="programming">
                <td>{{.SequenceID}}</td>
                <td><span class="category">{{.DataCategory}}</span></td>
                <td class="timestamp">{{.Command.Timestamp}}</td>
                <td class="command">
                    <div class="command-type">{{.Command.CommandType}} ({{.Command.Length}} bytes)</div>
                    <div class="hex">{{.Command.RawHex}}</div>
                    <div class="ascii">{{.Command.DecodedASCII}}</div>
                </td>
                <td class="response">
                    <div class="command-type">{{.Response.CommandType}}</div>
                    <div class="hex">{{.Response.RawHex}}</div>
                    <div class="ascii">{{.Response.DecodedASCII}}</div>
                </td>
                <td>{{.TimeDelta}}</td>
                <td class="description">{{.Description}}</td>
            </tr>
            {{end}}
        </table>

        <h2>💬 Other Command-Response Pairs</h2>
        <table>
            <tr>
                <th width="5%">Seq</th>
                <th width="8%">Category</th>
                <th width="10%">Time</th>
                <th width="25%">Command (PC→Radio)</th>
                <th width="20%">Response (Radio→PC)</th>
                <th width="8%">Delta</th>
                <th width="24%">Description</th>
            </tr>
            {{range .CommandResponses}}
            <tr>
                <td>{{.SequenceID}}</td>
                <td><span class="category">{{.DataCategory}}</span></td>
                <td class="timestamp">{{.Command.Timestamp}}</td>
                <td class="command">
                    <div class="command-type">{{.Command.CommandType}} ({{.Command.Length}} bytes)</div>
                    <div class="hex">{{.Command.RawHex}}</div>
                    <div class="ascii">{{.Command.DecodedASCII}}</div>
                </td>
                <td class="response">
                    <div class="command-type">{{.Response.CommandType}}</div>
                    <div class="hex">{{.Response.RawHex}}</div>
                    <div class="ascii">{{.Response.DecodedASCII}}</div>
                </td>
                <td>{{.TimeDelta}}</td>
                <td class="description">{{.Description}}</td>
            </tr>
            {{end}}
        </table>

        <div style="margin-top: 50px; text-align: center; color: #7f8c8d; border-top: 1px solid #bdc3c7; padding-top: 20px;">
            <p>Generated by DM-32UV Write Protocol Analyzer | {{.GeneratedAt}}</p>
        </div>
    </div>
</body>
</html>
`

	// Add template functions for calculations
	funcMap := template.FuncMap{
		"percentage": func(count, total int) string {
			if total == 0 {
				return "0.0"
			}
			percent := float64(count) * 100.0 / float64(total)
			return fmt.Sprintf("%.1f", percent)
		},
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		log.Fatalf("Error parsing template: %v", err)
	}

	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Error creating HTML file: %v", err)
	}
	defer file.Close()

	err = tmpl.Execute(file, report)
	if err != nil {
		log.Fatalf("Error executing template: %v", err)
	}

	fmt.Printf("HTML report saved to: %s\n", filename)
}

// Utility functions
func decodeToASCII(data []byte) string {
	var result strings.Builder
	for _, b := range data {
		if b >= 32 && b <= 126 {
			result.WriteByte(b)
		} else {
			result.WriteString(fmt.Sprintf("\\x%02x", b))
		}
	}
	return result.String()
}

func containsMostlyPrintable(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	printable := 0
	for _, b := range data {
		if (b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13 {
			printable++
		}
	}
	return float64(printable)/float64(len(data)) > 0.7
}

func hasNumericPatterns(data []byte) bool {
	digits := 0
	for _, b := range data {
		if b >= '0' && b <= '9' {
			digits++
		}
	}
	return digits > len(data)/4 // At least 25% digits
}

func hasRepeatingBytePattern(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	// Look for repeating patterns
	for i := 0; i < len(data)-3; i++ {
		pattern := data[i : i+2]
		for j := i + 2; j < len(data)-1; j++ {
			if data[j] == pattern[0] && data[j+1] == pattern[1] {
				return true
			}
		}
	}
	return false
}

func containsPattern(data, pattern []byte) bool {
	if len(pattern) > len(data) {
		return false
	}

	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j := 0; j < len(pattern); j++ {
			if data[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func calculateTimeDelta(start, end string) string {
	// Parse the time format HH:MM:SS.microseconds
	startTime, err1 := time.Parse("15:04:05.000000", start)
	endTime, err2 := time.Parse("15:04:05.000000", end)

	if err1 != nil || err2 != nil {
		return "~μs"
	}

	delta := endTime.Sub(startTime)
	if delta.Microseconds() < 1000 {
		return fmt.Sprintf("%dμs", delta.Microseconds())
	} else if delta.Milliseconds() < 1000 {
		return fmt.Sprintf("%.1fms", float64(delta.Microseconds())/1000.0)
	} else {
		return fmt.Sprintf("%.2fs", delta.Seconds())
	}
}

func unescapeString(s string) []byte {
	var result []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'n':
				result = append(result, '\n')
				i++
			case 't':
				result = append(result, '\t')
				i++
			case 'r':
				result = append(result, '\r')
				i++
			case '\\':
				result = append(result, '\\')
				i++
			case 'x':
				if i+3 < len(s) {
					hexStr := s[i+2 : i+4]
					if b, err := hex.DecodeString(hexStr); err == nil {
						result = append(result, b[0])
						i += 3
					} else {
						result = append(result, s[i])
					}
				} else {
					result = append(result, s[i])
				}
			default:
				if i+3 < len(s) && s[i+1] >= '0' && s[i+1] <= '7' {
					octalStr := s[i+1 : i+4]
					if containsOnly(octalStr, "01234567") {
						var val byte
						for _, c := range octalStr {
							val = val*8 + byte(c-'0')
						}
						result = append(result, val)
						i += 3
					} else {
						result = append(result, s[i])
					}
				} else {
					result = append(result, s[i])
				}
			}
		} else {
			result = append(result, s[i])
		}
	}
	return result
}

func containsOnly(s, chars string) bool {
	for _, r := range s {
		if !strings.ContainsRune(chars, r) {
			return false
		}
	}
	return true
}

func parseTimeDelta(delta string) time.Duration {
	// Handle microsecond format
	if strings.HasSuffix(delta, "µs") {
		val, err := strconv.ParseFloat(strings.TrimSuffix(delta, "µs"), 64)
		if err == nil {
			return time.Duration(val) * time.Microsecond
		}
	}

	// Handle millisecond format
	if strings.HasSuffix(delta, "ms") {
		val, err := strconv.ParseFloat(strings.TrimSuffix(delta, "ms"), 64)
		if err == nil {
			return time.Duration(val*1000) * time.Microsecond
		}
	}

	// Handle second format
	if strings.HasSuffix(delta, "s") {
		val, err := strconv.ParseFloat(strings.TrimSuffix(delta, "s"), 64)
		if err == nil {
			return time.Duration(val*1000000) * time.Microsecond
		}
	}

	return 0
}

// Generate HTML documentation for the API
func generateAPIDocHTML(apiDocs []CommandAPI, filename string) {
	htmlTemplate := `
<!DOCTYPE html>
<html>
<head>
    <title>DM-32UV Write Protocol API Documentation</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f5f5f5; color: #333; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #c0392b; text-align: center; border-bottom: 3px solid #e74c3c; padding-bottom: 10px; }
        h2 { color: #a93226; margin-top: 30px; }
        
        /* Command Card Styling */
        .command-card { 
            border: 1px solid #ddd; 
            border-radius: 8px; 
            margin-bottom: 15px; 
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        .command-header { 
            background-color: #f8f8f8; 
            padding: 12px; 
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #eee;
        }
        .command-name { font-size: 18px; font-weight: bold; color: #c0392b; }
        .command-meta { display: flex; gap: 15px; font-size: 13px; color: #666; }
        .command-body { padding: 0 15px 15px; }
        
        /* Details & Summary Styling */
        details { margin: 10px 0; }
        details summary { 
            cursor: pointer; 
            padding: 8px; 
            background-color: #f9f9f9; 
            border-radius: 4px;
            font-weight: bold;
        }
        details[open] summary { margin-bottom: 10px; }
        
        /* Response Styling */
        .response-container { 
            background-color: #f9ebea; 
            padding: 10px; 
            border-left: 4px solid #e74c3c; 
            margin: 10px 0; 
            border-radius: 4px;
        }
        
        /* Data Formatting */
        .hex { 
            font-family: 'Courier New', monospace; 
            background-color: #f8f9fa; 
            padding: 4px 8px; 
            border-radius: 3px; 
            overflow-wrap: break-word;
            word-break: break-all;
        }
        .ascii { 
            font-family: 'Courier New', monospace; 
            color: #d35400; 
            overflow-wrap: break-word;
            word-break: break-all;
        }
        .description { color: #555; font-style: italic; }
        .field-label { font-weight: bold; color: #555; display: inline-block; width: 120px; }
        
        /* Stats and Metadata */
        .timing { color: #8e44ad; font-weight: bold; }
        .category { 
            display: inline-block; 
            background-color: #f8f9fa; 
            padding: 2px 6px; 
            border-radius: 3px; 
            font-size: 12px; 
            color: #7f8c8d; 
        }
        .success-rate { font-weight: bold; }
        .success-high { color: #27ae60; }
        .success-medium { color: #f39c12; }
        .success-low { color: #c0392b; }
        
        /* Search and Filter */
        .search-container {
            background-color: #fadbd8;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
            position: sticky;
            top: 0;
            z-index: 100;
        }
        .search-input {
            padding: 10px;
            width: 70%;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
        }
        .search-type {
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            margin-left: 10px;
        }
        .index-link {
            display: inline-block;
            margin-top: 10px;
            color: #c0392b;
            text-decoration: none;
            font-weight: bold;
        }
        .index-link:hover {
            text-decoration: underline;
        }
        #command-count {
            margin-left: 10px;
            font-weight: bold;
        }
        .no-results {
            padding: 20px;
            text-align: center;
            font-style: italic;
            color: #555;
            display: none;
        }
        
        /* Quick Navigation */
        .quick-nav {
            position: fixed;
            top: 100px;
            right: 20px;
            background: white;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 10px;
            max-width: 200px;
            max-height: 400px;
            overflow-y: auto;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .quick-nav h4 {
            margin-top: 0;
            border-bottom: 1px solid #eee;
            padding-bottom: 5px;
        }
        .quick-nav ul {
            list-style: none;
            padding: 0;
            margin: 0;
        }
        .quick-nav a {
            display: block;
            padding: 3px 0;
            text-decoration: none;
            color: #c0392b;
            font-size: 13px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .quick-nav a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>📝 DM-32UV Write Operation Protocol Analysis</h1>
        
        <div class="summary">
            <h2>📊 Write Operation Summary</h2>
            <div class="stats">
                <div class="stat-box">
                    <div style="font-size: 24px; font-weight: bold;">{{.TotalCommunications}}</div>
                    <div>Total Communications</div>
                </div>
                <div class="stat-box">
                    <div style="font-size: 24px; font-weight: bold;">{{.CommandCount}}</div>
                    <div>PC→Radio Commands</div>
                </div>
                <div class="stat-box">
                    <div style="font-size: 24px; font-weight: bold;">{{.ResponseCount}}</div>
                    <div>Radio→PC ACKs</div>
                </div>
                <div class="stat-box">
                    <div style="font-size: 24px; font-weight: bold;">{{len .ProgrammingBlocks}}</div>
                    <div>Programming Blocks</div>
                </div>
            </div>
            <p><strong>Generated:</strong> {{.GeneratedAt}}</p>
        </div>

        <h2>🔌 File Descriptors Used</h2>
        <table>
            <tr><th>File Descriptor</th><th>Usage</th></tr>
            {{range $fd, $usage := .FileDescriptors}}
            <tr><td><strong>{{$fd}}</strong></td><td>{{$usage}}</td></tr>
            {{end}}
        </table>

        <h2>📋 Command Types Summary</h2>
        <table>
            <tr><th>Command Type</th><th>Frequency</th><th>Percentage</th></tr>
            {{range $cmd, $count := .UniqueCommands}}
            <tr><td class="command-type">{{$cmd}}</td><td>{{$count}}</td><td>{{percentage $count $.CommandCount}}%</td></tr>
            {{end}}
        </table>

        <h2>🗂️ Data Categories</h2>
        <table>
            <tr><th>Data Category</th><th>Count</th><th>Percentage</th></tr>
            {{range $cat, $count := .DataCategories}}
            <tr><td class="category">{{$cat}}</td><td>{{$count}}</td><td>{{percentage $count $.TotalCommunications}}%</td></tr>
            {{end}}
        </table>

        <h2>🤝 Handshake Sequences</h2>
        <table>
            <tr>
                <th width="5%">Seq</th>
                <th width="10%">Time</th>
                <th width="25%">Command (PC→Radio)</th>
                <th width="25%">Response (Radio→PC)</th>
                <th width="8%">Delta</th>
                <th width="27%">Description</th>
            </tr>
            {{range .HandshakeSequences}}
            <tr class="handshake">
                <td>{{.SequenceID}}</td>
                <td class="timestamp">{{.Command.Timestamp}}</td>
                <td class="command">
                    <div class="command-type">{{.Command.CommandType}}</div>
                    <div class="hex">{{.Command.RawHex}}</div>
                    <div class="ascii">{{.Command.DecodedASCII}}</div>
                </td>
                <td class="response">
                    <div class="command-type">{{.Response.CommandType}}</div>
                    <div class="hex">{{.Response.RawHex}}</div>
                    <div class="ascii">{{.Response.DecodedASCII}}</div>
                </td>
                <td>{{.TimeDelta}}</td>
                <td class="description">{{.Description}}</td>
            </tr>
            {{end}}
        </table>

        <h2>🔧 Programming Data Blocks</h2>
        <table>
            <tr>
                <th width="5%">Seq</th>
                <th width="8%">Category</th>
                <th width="10%">Time</th>
                <th width="25%">Data Block (PC→Radio)</th>
                <th width="20%">Response (Radio→PC)</th>
                <th width="8%">Delta</th>
                <th width="24%">Description</th>
            </tr>
            {{range .ProgrammingBlocks}}
            <tr class="programming">
                <td>{{.SequenceID}}</td>
                <td><span class="category">{{.DataCategory}}</span></td>
                <td class="timestamp">{{.Command.Timestamp}}</td>
                <td class="command">
                    <div class="command-type">{{.Command.CommandType}} ({{.Command.Length}} bytes)</div>
                    <div class="hex">{{.Command.RawHex}}</div>
                    <div class="ascii">{{.Command.DecodedASCII}}</div>
                </td>
                <td class="response">
                    <div class="command-type">{{.Response.CommandType}}</div>
                    <div class="hex">{{.Response.RawHex}}</div>
                    <div class="ascii">{{.Response.DecodedASCII}}</div>
                </td>
                <td>{{.TimeDelta}}</td>
                <td class="description">{{.Description}}</td>
            </tr>
            {{end}}
        </table>

        <h2>💬 Other Command-Response Pairs</h2>
        <table>
            <tr>
                <th width="5%">Seq</th>
                <th width="8%">Category</th>
                <th width="10%">Time</th>
                <th width="25%">Command (PC→Radio)</th>
                <th width="20%">Response (Radio→PC)</th>
                <th width="8%">Delta</th>
                <th width="24%">Description</th>
            </tr>
            {{range .CommandResponses}}
            <tr>
                <td>{{.SequenceID}}</td>
                <td><span class="category">{{.DataCategory}}</span></td>
                <td class="timestamp">{{.Command.Timestamp}}</td>
                <td class="command">
                    <div class="command-type">{{.Command.CommandType}} ({{.Command.Length}} bytes)</div>
                    <div class="hex">{{.Command.RawHex}}</div>
                    <div class="ascii">{{.Command.DecodedASCII}}</div>
                </td>
                <td class="response">
                    <div class="command-type">{{.Response.CommandType}}</div>
                    <div class="hex">{{.Response.RawHex}}</div>
                    <div class="ascii">{{.Response.DecodedASCII}}</div>
                </td>
                <td>{{.TimeDelta}}</td>
                <td class="description">{{.Description}}</td>
            </tr>
            {{end}}
        </table>

        <div style="margin-top: 50px; text-align: center; color: #7f8c8d; border-top: 1px solid #bdc3c7; padding-top: 20px;">
            <p>Generated by DM-32UV Write Protocol Analyzer | {{.GeneratedAt}}</p>
        </div>
    </div>
</body>
</html>
`

	// Add template functions for calculations
	funcMap := template.FuncMap{
		"percentage": func(count, total int) string {
			if total == 0 {
				return "0.0"
			}
			percent := float64(count) * 100.0 / float64(total)
			return fmt.Sprintf("%.1f", percent)
		},
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		log.Fatalf("Error parsing template: %v", err)
	}

	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Error creating HTML file: %v", err)
	}
	defer file.Close()

	err = tmpl.Execute(file, report)
	if err != nil {
		log.Fatalf("Error executing template: %v", err)
	}

	fmt.Printf("HTML report saved to: %s\n", filename)
}

// Utility functions
func decodeToASCII(data []byte) string {
	var result strings.Builder
	for _, b := range data {
		if b >= 32 && b <= 126 {
			result.WriteByte(b)
		} else {
			result.WriteString(fmt.Sprintf("\\x%02x", b))
		}
	}
	return result.String()
}

func containsMostlyPrintable(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	printable := 0
	for _, b := range data {
		if (b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13 {
			printable++
		}
	}
	return float64(printable)/float64(len(data)) > 0.7
}

func hasNumericPatterns(data []byte) bool {
	digits := 0
	for _, b := range data {
		if b >= '0' && b <= '9' {
			digits++
		}
	}
	return digits > len(data)/4 // At least 25% digits
}

func hasRepeatingBytePattern(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	// Look for repeating patterns
	for i := 0; i < len(data)-3; i++ {
		pattern := data[i : i+2]
		for j := i + 2; j < len(data)-1; j++ {
			if data[j] == pattern[0] && data[j+1] == pattern[1] {
				return true
			}
		}
	}
	return false
}

func containsPattern(data, pattern []byte) bool {
	if len(pattern) > len(data) {
		return false
	}

	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j := 0; j < len(pattern); j++ {
			if data[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func calculateTimeDelta(start, end string) string {
	// Parse the time format HH:MM:SS.microseconds
	startTime, err1 := time.Parse("15:04:05.000000", start)
	endTime, err2 := time.Parse("15:04:05.000000", end)

	if err1 != nil || err2 != nil {
		return "~μs"
	}

	delta := endTime.Sub(startTime)
	if delta.Microseconds() < 1000 {
		return fmt.Sprintf("%dμs", delta.Microseconds())
	} else if delta.Milliseconds() < 1000 {
		return fmt.Sprintf("%.1fms", float64(delta.Microseconds())/1000.0)
	} else {
		return fmt.Sprintf("%.2fs", delta.Seconds())
	}
}

func unescapeString(s string) []byte {
	var result []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'n':
				result = append(result, '\n')
				i++
			case 't':
				result = append(result, '\t')
				i++
			case 'r':
				result = append(result, '\r')
				i++
			case '\\':
				result = append(result, '\\')
				i++
			case 'x':
				if i+3 < len(s) {
					hexStr := s[i+2 : i+4]
					if b, err := hex.DecodeString(hexStr); err == nil {
						result = append(result, b[0])
						i += 3
					} else {
						result = append(result, s[i])
					}
				} else {
					result = append(result, s[i])
				}
			default:
				if i+3 < len(s) && s[i+1] >= '0' && s[i+1] <= '7' {
					octalStr := s[i+1 : i+4]
					if containsOnly(octalStr, "01234567") {
						var val byte
						for _, c := range octalStr {
							val = val*8 + byte(c-'0')
						}
						result = append(result, val)
						i += 3
					} else {
						result = append(result, s[i])
					}
				} else {
					result = append(result, s[i])
				}
			}
		} else {
			result = append(result, s[i])
		}
	}
	return result
}

func containsOnly(s, chars string) bool {
	for _, r := range s {
		if !strings.ContainsRune(chars, r) {
			return false
		}
	}
	return true
}

func parseTimeDelta(delta string) time.Duration {
	// Handle microsecond format
	if strings.HasSuffix(delta, "µs") {
		val, err := strconv.ParseFloat(strings.TrimSuffix(delta, "µs"), 64)
		if err == nil {
			return time.Duration(val) * time.Microsecond
		}
	}

	// Handle millisecond format
	if strings.HasSuffix(delta, "ms") {
		val, err := strconv.ParseFloat(strings.TrimSuffix(delta, "ms"), 64)
		if err == nil {
			return time.Duration(val*1000) * time.Microsecond
		}
	}

	// Handle second format
	if strings.HasSuffix(delta, "s") {
		val, err := strconv.ParseFloat(strings.TrimSuffix(delta, "s"), 64)
		if err == nil {
			return time.Duration(val*1000000) * time.Microsecond
		}
	}

	return 0
}

// Generate HTML documentation for the API
func generateAPIDocHTML(apiDocs []CommandAPI, filename string) {
	htmlTemplate := `
<!DOCTYPE html>
<html>
<head>
    <title>DM-32UV Write Protocol API Documentation</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f5f5f5; color: #333; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #c0392b; text-align: center; border-bottom: 3px solid #e74c3c; padding-bottom: 10px; }
        h2 { color: #a93226; margin-top: 30px; }
        
        /* Command Card Styling */
        .command-card { 
            border: 1px solid #ddd; 
            border-radius: 8px; 
            margin-bottom: 15px; 
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        .command-header { 
            background-color: #f8f8f8; 
            padding: 12px; 
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #eee;
        }
        .command-name { font-size: 18px; font-weight: bold; color: #c0392b; }
        .command-meta { display: flex; gap: 15px; font-size: 13px; color: #666; }
        .command-body { padding: 0 15px 15px; }
        
        /* Details & Summary Styling */
        details { margin: 10px 0; }
        details summary { 
            cursor: pointer; 
            padding: 8px; 
            background-color: #f9f9f9; 
            border-radius: 4px;
            font-weight: bold;
        }
        details[open] summary { margin-bottom: 10px; }
        
        /* Response Styling */
        .response-container { 
            background-color: #f9ebea; 
            padding: 10px; 
            border-left: 4px solid #e74c3c; 
            margin: 10px 0; 
            border-radius: 4px;
        }
        
        /* Data Formatting */
        .hex { 
            font-family: 'Courier New', monospace; 
            background-color: #f8f9fa; 
            padding: 4px 8px; 
            border-radius: 3px; 
            overflow-wrap: break-word;
            word-break: break-all;
        }
        .ascii { 
            font-family: 'Courier New', monospace; 
            color: #d35400; 
            overflow-wrap: break-word;
            word-break: break-all;
        }
        .description { color: #555; font-style: italic; }
        .field-label { font-weight: bold; color: #555; display: inline-block; width: 120px; }
        
        /* Stats and Metadata */
        .timing { color: #8e44ad; font-weight: bold; }
        .category { 
            display: inline-block; 
            background-color: #f8f9fa; 
            padding: 2px 6px; 
            border-radius: 3px; 
            font-size: 12px; 
            color: #7f8c8d; 
        }
        .success-rate { font-weight: bold; }
        .success-high { color: #27ae60; }
        .success-medium { color: #f39c12; }
        .success-low { color: #c0392b; }
        
        /* Search and Filter */
        .search-container {
            background-color: #fadbd8;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
            position: sticky;
            top: 0;
            z-index: 100;
        }
        .search-input {
            padding: 10px;
            width: 70%;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
        }
        .search-type {
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            margin-left: 10px;
        }
        .index-link {
            display: inline-block;
            margin-top: 10px;
            color: #c0392b;
            text-decoration: none;
            font-weight: bold;
        }
        .index-link:hover {
            text-decoration: underline;
        }
        #command-count {
            margin-left: 10px;
            font-weight: bold;
        }
        .no-results {
            padding: 20px;
            text-align: center;
            font-style: italic;
            color: #555;
            display: none;
        }
        
        /* Quick Navigation */
        .quick-nav {
            position: fixed;
            top: 100px;
            right: 20px;
            background: white;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 10px;
            max-width: 200px;
            max-height: 400px;
            overflow-y: auto;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .quick-nav h4 {
            margin-top: 0;
            border-bottom: 1px solid #eee;
            padding-bottom: 5px;
        }
        .quick-nav ul {
            list-style: none;
            padding: 0;
            margin: 0;
        }
        .quick-nav a {
            display: block;
            padding: 3px 0;
            text-decoration: none;
            color: #c0392b;
            font-size: 13px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .quick-nav a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>📝 DM-32UV Write Operation Protocol Analysis</h1>
        
        <div class="summary">
            <h2>📊 Write Operation Summary</h2>
            <div class="stats">
                <div class="stat-box">
                    <div style="font-size: 24px; font-weight: bold;">{{.TotalCommunications}}</div>
                    <div>Total Communications</div>
                </div>
                <div class="stat-box">
                    <div style="font-size: 24px; font-weight: bold;">{{.CommandCount}}</div>
                    <div>PC→Radio Commands</div>
                </div>
                <div class="stat-box">
                    <div style="font-size: 24px; font-weight: bold;">{{.ResponseCount}}</div>
                    <div>Radio→PC ACKs</div>
                </div>
                <div class="stat-box">
                    <div style="font-size: 24px; font-weight: bold;">{{len .ProgrammingBlocks}}</div>
                    <div>Programming Blocks</div>
                </div>
            </div>
            <p><strong>Generated:</strong> {{.GeneratedAt}}</p>
        </div>

        <h2>🔌 File Descriptors Used</h2>
        <table>
            <tr><th>File Descriptor</th><th>Usage</th></tr>
            {{range $fd, $usage := .FileDescriptors}}
            <tr><td><strong>{{$fd}}</strong></td><td>{{$usage}}</td></tr>
            {{end}}
        </table>

        <h2>📋 Command Types Summary</h2>
        <table>
            <tr><th>Command Type</th><th>Frequency</th><th>Percentage</th></tr>
            {{range $cmd, $count := .UniqueCommands}}
            <tr><td class="command-type">{{$cmd}}</td><td>{{$count}}</td><td>{{percentage $count $.CommandCount}}%</td></tr>
            {{end}}
        </table>

        <h2>🗂️ Data Categories</h2>
        <table>
            <tr><th>Data Category</th><th>Count</th><th>Percentage</th></tr>
            {{range $cat, $count := .DataCategories}}
            <tr><td class="category">{{$cat}}</td><td>{{$count}}</td><td>{{percentage $count $.TotalCommunications}}%</td></tr>
            {{end}}
        </table>

        <h2>🤝 Handshake Sequences</h2>
        <table>
            <tr>
                <th width="5%">Seq</th>
                <th width="10%">Time</th>
                <th width="25%">Command (PC→Radio)</th>
                <th width="25%">Response (Radio→PC)</th>
                <th width="8%">Delta</th>
                <th width="27%">Description</th>
            </tr>
            {{range .HandshakeSequences}}
            <tr class="handshake">
                <td>{{.SequenceID}}</td>
                <td class="timestamp">{{.Command.Timestamp}}</td>
                <td class="command">
                    <div class="command-type">{{.Command.CommandType}}</div>
                    <div class="hex">{{.Command.RawHex}}</div>
                    <div class="ascii">{{.Command.DecodedASCII}}</div>
                </td>
                <td class="response">
                    <div class="command-type">{{.Response.CommandType}}</div>
                    <div class="hex">{{.Response.RawHex}}</div>
                    <div class="ascii">{{.Response.DecodedASCII}}</div>
                </td>
                <td>{{.TimeDelta}}</td>
                <td class="description">{{.Description}}</td>
            </tr>
            {{end}}
        </table>

        <h2>🔧 Programming Data Blocks</h2>
        <table>
            <tr>
                <th width="5%">Seq</th>
                <th width="8%">Category</th>
                <th width="10%">Time</th>
                <th width="25%">Data Block (PC→Radio)</th>
                <th width="20%">Response (Radio→PC)</th>
                <th width="8%">Delta</th>
                <th width="24%">Description</th>
            </tr>
            {{range .ProgrammingBlocks}}
            <tr class="programming">
                <td>{{.SequenceID}}</td>
                <td><span class="category">{{.DataCategory}}</span></td>
                <td class="timestamp">{{.Command.Timestamp}}</td>
                <td class="command">
                    <div class="command-type">{{.Command.CommandType}} ({{.Command.Length}} bytes)</div>
                    <div class="hex">{{.Command.RawHex}}</div>
                    <div class="ascii">{{.Command.DecodedASCII}}</div>
                </td>
                <td class="response">
                    <div class="command-type">{{.Response.CommandType}}</div>
                    <div class="hex">{{.Response.RawHex}}</div>
                    <div class="ascii">{{.Response.DecodedASCII}}</div>
                </td>
                <td>{{.TimeDelta}}</td>
                <td class="description">{{.Description}}</td>
            </tr>
            {{end}}
        </table>

        <h2>💬 Other Command-Response Pairs</h2>
        <table>
            <tr>
                <th width="5%">Seq</th>
                <th width="8%">Category</th>
                <th width="10%">Time</th>
                <th width="25%">Command (PC→Radio)</th>
                <th width="20%">Response (Radio→PC)</th>
                <th width="8%">Delta</th>
                <th width="24%">Description</th>
            </tr>
            {{range .CommandResponses}}
            <tr>
                <td>{{.SequenceID}}</td>
                <td><span class="category">{{.DataCategory}}</span></td>
                <td class="timestamp">{{.Command.Timestamp}}</td>
                <td class="command">
                    <div class="command-type">{{.Command.CommandType}} ({{.Command.Length}} bytes)</div>
                    <div class="hex">{{.Command.RawHex}}</div>
                    <div class="ascii">{{.Command.DecodedASCII}}</div>
                </td>
                <td class="response">
                    <div class="command-type">{{.Response.CommandType}}</div>
                    <div class="hex">{{.Response.RawHex}}</div>
                    <div class="ascii">{{.Response.DecodedASCII}}</div>
                </td>
                <td>{{.TimeDelta}}</td>
                <td class="description">{{.Description}}</td>
            </tr>
            {{end}}
        </table>

        <div style="margin-top: 50px; text-align: center; color: #7f8c8d; border-top: 1px solid #bdc3c7; padding-top: 20px;">
            <p>Generated by DM-32UV Write Protocol Analyzer | {{.GeneratedAt}}</p>
        </div>
    </div>
</body>
</html>
`

	// Add template functions for calculations
	funcMap := template.FuncMap{
		"percentage": func(count, total int) string {
			if total == 0 {
				return "0.0"
			}
			percent := float64(count) * 100.0 / float64(total)
			return fmt.Sprintf("%.1f", percent)
		},
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		log.Fatalf("Error parsing template: %v", err)
	}

	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Error creating HTML file: %v", err)
	}
	defer file.Close()

	err = tmpl.Execute(file, report)
	if err != nil {
		log.Fatalf("Error executing template: %v", err)
	}

	fmt.Printf("HTML report saved to: %s\n", filename)
}

// Utility functions
func decodeToASCII(data []byte) string {
	var result strings.Builder
	for _, b := range data {
		if b >= 32 && b <= 126 {
			result.WriteByte(b)
		} else {
			result.WriteString(fmt.Sprintf("\\x%02x", b))
		}
	}
	return result.String()
}

func containsMostlyPrintable(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	printable := 0
	for _, b := range data {
		if (b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13 {
			printable++
		}
	}
	return float64(printable)/float64(len(data)) > 0.7
}

func hasNumericPatterns(data []byte) bool {
	digits := 0
	for _, b := range data {
		if b >= '0' && b <= '9' {
			digits++
		}
	}
	return digits > len(data)/4 // At least 25% digits
}

func hasRepeatingBytePattern(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	// Look for repeating patterns
	for i := 0; i < len(data)-3; i++ {
		pattern := data[i : i+2]
		for j := i + 2; j < len(data)-1; j++ {
			if data[j] == pattern[0] && data[j+1] == pattern[1] {
				return true
			}
		}
	}
	return false
}

func containsPattern(data, pattern []byte) bool {
	if len(pattern) > len(data) {
		return false
	}

	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j := 0; j < len(pattern); j++ {
			if data[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func calculateTimeDelta(start, end string) string {
	// Parse the time format HH:MM:SS.microseconds
	startTime, err1 := time.Parse("15:04:05.000000", start)
	endTime, err2 := time.Parse("15:04:05.000000", end)

	if err1 != nil || err2 != nil {
		return "~μs"
	}

	delta := endTime.Sub(startTime)
	if delta.Microseconds() < 1000 {
		return fmt.Sprintf("%dμs", delta.Microseconds())
	} else if delta.Milliseconds() < 1000 {
		return fmt.Sprintf("%.1fms", float64(delta.Microseconds())/1000.0)
	} else {
		return fmt.Sprintf("%.2fs", delta.Seconds())
	}
}

func unescapeString(s string) []byte {
	var result []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case 'n':
				result = append(result, '\n')
				i++
			case 't':
				result = append(result, '\t')
				i++
			case 'r':
				result = append(result, '\r')
				i++
			case '\\':
				result = append(result, '\\')
				i++
			case 'x':
				if i+3 < len(s) {
					hexStr := s[i+2 : i+4]
					if b, err := hex.DecodeString(hexStr); err == nil {
						result = append(result, b[0])
						i += 3
					} else {
						result = append(result, s[i])
					}
				} else {
					result = append(result, s[i])
				}
			default:
				if i+3 < len(s) && s[i+1] >= '0' && s[i+1] <= '7' {
					octalStr := s[i+1 : i+4]
					if containsOnly(octalStr, "01234567") {
						var val byte
						for _, c := range octalStr {
							val = val*8 + byte(c-'0')
						}
						result = append(result, val)
						i += 3
					} else {
						result = append(result, s[i])
					}
				} else {
					result = append(result, s[i])
				}
			}
		} else {
			result = append(result, s[i])
		}
	}
	return result
}

func containsOnly(s, chars string) bool {
	for _, r := range s {
		if !strings.ContainsRune(chars, r) {
			return false
		}
	}
	return true
}

func parseTimeDelta(delta string) time.Duration {
	// Handle microsecond format
	if strings.HasSuffix(delta, "µs") {
		val, err := strconv.ParseFloat(strings.TrimSuffix(delta, "µs"), 64)
		if err == nil {
			return time.Duration(val) * time.Microsecond
		}
	}

	// Handle millisecond format
	if strings.HasSuffix(delta, "ms") {
		val, err := strconv.ParseFloat(strings.TrimSuffix(delta, "ms"), 64)
		if err == nil {
			return time.Duration(val*1000) * time.Microsecond
		}
	}

	// Handle second format
	if strings.HasSuffix(delta, "s") {
		val, err := strconv.ParseFloat(strings.TrimSuffix(delta, "s"), 64)
		if err == nil {
			return time.Duration(val*1000000) * time.Microsecond
		}
	}

	return 0
}

// Generate HTML documentation for the API
func generateAPIDocHTML(apiDocs []CommandAPI, filename string) {
	htmlTemplate := `
<!DOCTYPE html>
<html>
<head>
    <title>DM-32UV Write Protocol API Documentation</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f5f5f5; color: #333; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #c0392b; text-align: center; border-bottom: 3px solid #e74c3c; padding-bottom: 10px; }
        h2 { color: #a93226; margin-top: 30px; }
        
        /* Command Card Styling */
        .command-card { 
            border: 1px solid #ddd; 
            border-radius: 8px; 
            margin-bottom: 15px; 
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        .command-header { 
            background-color: #f8f8f8; 
            padding: 12px; 
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #eee;
        }
        .command-name { font-size: 18px; font-weight: bold; color: #c0392b; }
        .command-meta { display: flex; gap: 15px; font-size: 13px; color: #666; }
        .command-body { padding: 0 15px 15px; }
        
        /* Details & Summary Styling */
        details { margin: 10px 0; }
        details summary { 
            cursor: pointer; 
            padding: 8px; 
            background-color: #f9f9f9; 
            border-radius: 4px;
            font-weight: bold;
        }
        details[open] summary { margin-bottom: 10px; }
        
        /* Response Styling */
        .response-container { 
            background-color: #f9ebea; 
            padding: 10px; 
            border-left: 4px solid #e74c3c; 
            margin: 10px 0; 
            border-radius: 4px;
        }
        
        /* Data Formatting */
        .hex { 
            font-family: 'Courier New', monospace; 
            background-color: #f8f9fa; 
            padding: 4px 8px; 
            border-radius: 3px; 
            overflow-wrap: break-word;
            word-break: break-all;
        }
        .ascii { 
            font-family: 'Courier New', monospace; 
            color: #d35400; 
            overflow-wrap: break-word;
            word-break: break-all;
        }
        .description { color: #555; font-style: italic; }
        .field-label { font-weight: bold; color: #555; display: inline-block; width: 120px; }
        
        /* Stats and Metadata */
        .timing { color: #8e44ad; font-weight: bold; }
        .category { 
            display: inline-block; 
            background-color: #f8f9fa; 
            padding: 2px 6px; 
            border-radius: 3px; 
            font-size: 12px; 
            color: #7f8c8d; 
        }
        .success-rate { font-weight: bold; }
        .success-high { color: #27ae60; }
        .success-medium { color: #f39c12; }
        .success-low { color: #c0392b; }
        
        /* Search and Filter */
        .search-container {
            background-color: #fadbd8;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
            position: sticky;
            top: 0;
            z-index: 100;
        }
        .search-input {
            padding: 10px;
            width: 70%;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
        }
        .search-type {
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            margin-left: 10px;
        }
        .index-link {
            display: inline-block;
            margin-top: 10px;
            color: #c0392b;
            text-decoration: none;
            font-weight: bold;
        }
        .index-link:hover {
            text-decoration: underline;
        }
        #command-count {
            margin-left: 10px;
            font-weight: bold;
        }
        .no-results {
            padding: 20px;
            text-align: center;
            font-style: italic;
            color: #555;
            display: none;
        }
        
        /* Quick Navigation */
        .quick-nav {
            position: fixed;
            top: 100px;
            right: 20px;
            background: white;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 10px;
            max-width: 200px;
            max-height: 400px;
            overflow-y: auto;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .quick-nav h4 {
            margin-top: 0;
            border-bottom: 1px solid #eee;
            padding-bottom: 5px;
        }
        .quick-nav ul {
            list-style: none;
            padding: 0;
            margin: 0;
        }
        .quick-nav a {
            display: block;
            padding: 3px 0;
            text-decoration: none;
            color: #c0392b;
            font-size: 13px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .quick-nav a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>📝 DM-32UV Write Protocol API Documentation</h1>
        
        <div class="search-container">
            <input type="text" id="search-input" class="search-input" placeholder="Search commands...">
            <select id="search-type" class="search-type">
                <option value="all">All Fields</option>
                <option value="command">Command Name</option>
                <option value="hex">HEX Value</option>
                <option value="ascii">ASCII Value</option>
                <option value="category">Category</option>
            </select>
            <span id="command-count">Showing {{len .}} commands</span>
            <br>
            <a href="/index.html" class="index-link">← Back to Index</a>
        </div>
        
        <div class="quick-nav" id="quick-nav">
            <h4>Quick Navigation</h4>
            <ul id="nav-list">
                {{range $index, $cmd := .}}
                <li><a href="#cmd-{{$index}}">{{$cmd.Command}}</a></li>
                {{end}}
            </ul>
        </div>

        <div id="command-list">
            {{range $index, $cmd := .}}
            <div class="command-card" id="cmd-{{$index}}" data-command="{{$cmd.Command}}" data-hex="{{$cmd.HexValue}}" data-ascii="{{$cmd.ASCIIValue}}" data-category="{{$cmd.DataCategory}}">
                <div class="command-header" onclick="toggleCommandDetails(this)">
                    <div class="command-name">{{$cmd.Command}}</div>
                    <div class="command-meta">
                        <span class="category">{{$cmd.DataCategory}}</span>
                        <span class="success-rate {{successRateClass $cmd.SuccessRate}}">{{$cmd.SuccessRate}}</span>
                        <span class="timing">{{$cmd.TimingAverage}}</span>
                        <span class="frequency">{{$cmd.FrequencyCount}}×</span>
                    </div>
                </div>
                
                <div class="command-body" style="display:none;">
                    <details>
                        <summary>Command Details</summary>
                        <div>
                            <p><span class="field-label">Description:</span> <span class="description">{{$cmd.Description}}</span></p>
                            <p><span class="field-label">HEX:</span> <span class="hex">{{$cmd.HexValue}}</span></p>
                            <p><span class="field-label">ASCII:</span> <span class="ascii">{{$cmd.ASCIIValue}}</span></p>
                        </div>
                    </details>
                    
                    <details>
                        <summary>Response Details</summary>
                        <div class="response-container">
                            <p><strong>{{$cmd.ResponseType}}</strong></p>
                            <p><span class="field-label">HEX:</span> <span class="hex">{{$cmd.ResponseHex}}</span></p>
                            <p><span class="field-label">ASCII:</span> <span class="ascii">{{$cmd.ResponseASCII}}</span></p>
                        </div>
                    </details>
                    
                    <details>
                        <summary>Performance Metrics</summary>
                        <p><span class="field-label">Success Rate:</span> <span class="success-rate {{successRateClass $cmd.SuccessRate}}">{{$cmd.SuccessRate}}</span></p>
                        <p><span class="field-label">Average Time:</span> <span class="timing">{{$cmd.TimingAverage}}</span></p>
                        <p><span class="field-label">Usage Count:</span> <span class="frequency">{{$cmd.FrequencyCount}} times</span></p>
                    </details>
                </div>
            </div>
            {{end}}
            
            <div class="no-results" id="no-results">
                No commands match your search.
            </div>
        </div>
        
        <div style="margin-top: 50px; text-align: center; color: #7f8c8d; border-top: 1px solid #bdc3c7; padding-top: 20px;">
            <p>Generated by DM-32UV Protocol Analyzer | Write API Documentation</p>
        </div>
    </div>

    <script>
        // Toggle command details when clicking on header
        function toggleCommandDetails(header) {
            const body = header.nextElementSibling;
            body.style.display = body.style.display === 'none' ? 'block' : 'none';
        }
        
        // Search functionality
        const searchInput = document.getElementById('search-input');
        const searchType = document.getElementById('search-type');
        const commandList = document.getElementById('command-list');
        const commandCount = document.getElementById('command-count');
        const noResults = document.getElementById('no-results');
        
        function performSearch() {
            const searchTerm = searchInput.value.toLowerCase();
            const searchField = searchType.value;
            let visibleCount = 0;
            
            const commandCards = document.querySelectorAll('.command-card');
            commandCards.forEach(card => {
                let match = false;
                
                if (searchTerm === '') {
                    match = true;
                } else {
                    switch(searchField) {
                        case 'command':
                            match = card.dataset.command.toLowerCase().includes(searchTerm);
                            break;
                        case 'hex':
                            match = card.dataset.hex.toLowerCase().includes(searchTerm);
                            break;
                        case 'ascii':
                            match = card.dataset.ascii.toLowerCase().includes(searchTerm);
                            break;
                        case 'category':
                            match = card.dataset.category.toLowerCase().includes(searchTerm);
                            break;
                        case 'all':
                        default:
                            match = card.dataset.command.toLowerCase().includes(searchTerm) ||
                                   card.dataset.hex.toLowerCase().includes(searchTerm) ||
                                   card.dataset.ascii.toLowerCase().includes(searchTerm) ||
                                   card.dataset.category.toLowerCase().includes(searchTerm);
                            break;
                    }
                }
                
                card.style.display = match ? 'block' : 'none';
                if (match) visibleCount++;
            });
            
            commandCount.textContent = 'Showing ' + visibleCount + ' of {{len .}} commands';
            noResults.style.display = visibleCount === 0 ? 'block' : 'none';
            
            // Update quick nav
            updateQuickNav();
        }
        
        // Update quick navigation based on visible commands
        function updateQuickNav() {
            const navList = document.getElementById('nav-list');
            navList.innerHTML = '';
            
            const visibleCommands = document.querySelectorAll('.command-card[style="display: block"]');
            visibleCommands.forEach(cmd => {
                const id = cmd.id;
                const name = cmd.querySelector('.command-name').textContent;
                
                const li = document.createElement('li');
                const a = document.createElement('a');
                a.href = '#' + id;
                a.textContent = name;
                li.appendChild(a);
                navList.appendChild(li);
            });
        }
        
        searchInput.addEventListener('input', performSearch);
        searchType.addEventListener('change', performSearch);
        
        // Initialize on page load
        document.addEventListener('DOMContentLoaded', function() {
            // Open the first command by default
            const firstCommand = document.querySelector('.command-card');
            if (firstCommand) {
                const header = firstCommand.querySelector('.command-header');
                const body = header.nextElementSibling;
                body.style.display = 'block';
            }
        });
    </script>
</body>
</html>
`

	// Define template functions
	funcMap := template.FuncMap{
		"successRateClass": func(rate string) string {
			// Parse the percentage value
			rate = strings.TrimSuffix(rate, "%")
			value, err := strconv.ParseFloat(rate, 64)
			if err != nil {
				return ""
			}

			if value >= 95 {
				return "success-high"
			} else if value >= 80 {
				return "success-medium"
			} else {
				return "success-low"
			}
		},
	}

	tmpl, err := template.New("api").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		log.Fatalf("Error parsing template: %v", err)
	}

	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Error creating HTML file: %v", err)
	}
	defer file.Close()

	err = tmpl.Execute(file, apiDocs)
	if err != nil {
		log.Fatalf("Error executing template: %v", err)
	}

	fmt.Printf("Write API documentation saved to: %s\n", filename)

	// Update the index page whenever we generate a new report
	updateIndexPage()
}

// Add this function for index page generation

func updateIndexPage() {
	// Path to the index file
	indexPath := "/home/sannis/REDBUG/index.html"

	// Find all generated reports
	reports := findReports()

	// Generate the index HTML
	htmlTemplate := `
<!DOCTYPE html>
<html>
<head>
    <title>DM-32UV Protocol Analysis Dashboard</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 0; 
            padding: 0; 
            background-color: #f5f5f5; 
            color: #333; 
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            background-color: white; 
            padding: 20px; 
            box-shadow: 0 0 10px rgba(0,0,0,0.1); 
        }
        h1 { 
            color: #34495e; 
            text-align: center; 
            border-bottom: 3px solid #3498db; 
            padding-bottom: 10px; 
        }
        h2 { 
            color: #2c3e50; 
            margin-top: 30px; 
            padding-bottom: 5px;
            border-bottom: 1px solid #eee;
        }
        .report-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .report-card {
            border: 1px solid #ddd;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .report-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }
        .report-header {
            padding: 15px;
            border-bottom: 1px solid #eee;
        }
        .read-report .report-header {
            background-color: #eaf2f8;
            border-left: 5px solid #3498db;
        }
        .write-report .report-header {
            background-color: #f9ebea;
            border-left: 5px solid #e74c3c;
        }
        .api-doc .report-header {
            background-color: #eafaf1;
            border-left: 5px solid #2ecc71;
        }
        .report-body {
            padding: 15px;
        }
        .report-title {
            margin: 0;
            font-size: 18px;
            font-weight: bold;
        }
        .read-report .report-title {
            color: #2980b9;
        }
        .write-report .report-title {
            color: #c0392b;
        }
        .api-doc .report-title {
            color: #27ae60;
        }
        .report-meta {
            color: #7f8c8d;
            font-size: 13px;
            margin-top: 5px;
        }
        .report-desc {
            margin-top: 10px;
            color: #555;
            font-size: 14px;
        }
        .report-link {
            display: inline-block;
            margin-top: 10px;
            padding: 8px 15px;
            background-color: #f8f9fa;
            color: #333;
            text-decoration: none;
            border-radius: 4px;
            font-weight: bold;
            border: 1px solid #ddd;
            transition: background-color 0.2s;
        }
        .report-link:hover {
            background-color: #e9ecef;
        }
        .read-report .report-link:hover {
            color: #2980b9;
        }
        .write-report .report-link:hover {
            color: #c0392b;
        }
        .api-doc .report-link:hover {
            color: #27ae60;
        }
        .report-timestamp {
            font-size: 12px;
            color: #aaa;
            margin-top: 10px;
            text-align: right;
        }
        .no-reports {
            padding: 30px;
            text-align: center;
            font-style: italic;
            color: #7f8c8d;
            background-color: #f8f9fa;
            border-radius: 8px;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 DM-32UV Radio Protocol Analysis Dashboard</h1>
        
        <p>This dashboard provides access to all protocol analysis reports and API documentation generated from the captured communications between the PC software and the DM-32UV radio.</p>
        
        {{if .ReadReports}}
        <h2>📥 Read Operation Analysis</h2>
        <div class="report-grid">
            {{range .ReadReports}}
            <div class="report-card read-report">
                <div class="report-header">
                    <h3 class="report-title">{{.Title}}</h3>
                    <div class="report-meta">{{.Type}} | {{.Size}}</div>
                </div>
                <div class="report-body">
                    <p class="report-desc">{{.Description}}</p>
                    <a href="{{.Path}}" class="report-link">View Report</a>
                    <div class="report-timestamp">{{.Timestamp}}</div>
                </div>
            </div>
            {{end}}
        </div>
        {{end}}
        
        {{if .WriteReports}}
        <h2>📤 Write Operation Analysis</h2>
        <div class="report-grid">
            {{range .WriteReports}}
            <div class="report-card write-report">
                <div class="report-header">
                    <h3 class="report-title">{{.Title}}</h3>
                    <div class="report-meta">{{.Type}} | {{.Size}}</div>
                </div>
                <div class="report-body">
                    <p class="report-desc">{{.Description}}</p>
                    <a href="{{.Path}}" class="report-link">View Report</a>
                    <div class="report-timestamp">{{.Timestamp}}</div>
                </div>
            </div>
            {{end}}
        </div>
        {{end}}
        
        {{if .ApiDocs}}
        <h2>📚 API Documentation</h2>
        <div class="report-grid">
            {{range .ApiDocs}}
            <div class="report-card api-doc">
                <div class="report-header">
                    <h3 class="report-title">{{.Title}}</h3>
                    <div class="report-meta">{{.Type}} | {{.Size}}</div>
                </div>
                <div class="report-body">
                    <p class="report-desc">{{.Description}}</p>
                    <a href="{{.Path}}" class="report-link">View Documentation</a>
                    <div class="report-timestamp">{{.Timestamp}}</div>
                </div>
            </div>
            {{end}}
        </div>
        {{end}}
        
        {{if not .ReadReports}}{{if not .WriteReports}}{{if not .ApiDocs}}
        <div class="no-reports">
            <p>No reports have been generated yet. Run the analyzers to create reports.</p>
        </div>
        {{end}}{{end}}{{end}}
        
        <div style="margin-top: 50px; text-align: center; color: #7f8c8d; border-top: 1px solid #bdc3c7; padding-top: 20px;">
            <p>DM-32UV Protocol Analyzer | Dashboard automatically updated: {{.GeneratedAt}}</p>
        </div>
    </div>
</body>
</html>
`

	// Create a struct for the template data
	type Report struct {
		Title       string
		Type        string
		Path        string
		Size        string
		Description string
		Timestamp   string
	}

	type IndexData struct {
		ReadReports  []Report
		WriteReports []Report
		ApiDocs      []Report
		GeneratedAt  string
	}

	data := IndexData{
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
	}

	// Categorize reports
	for _, r := range reports {
		report := Report{
			Path:      r.Path,
			Size:      formatFileSize(r.Size),
			Timestamp: r.ModTime.Format("2006-01-02 15:04:05"),
		}

		switch {
		case strings.Contains(r.Path, "read") && strings.Contains(r.Path, "api"):
			report.Title = "Read Protocol API"
			report.Type = "API Documentation"
			report.Description = "Detailed documentation of all commands used during read operations"
			data.ApiDocs = append(data.ApiDocs, report)

		case strings.Contains(r.Path, "write") && strings.Contains(r.Path, "api"):
			report.Title = "Write Protocol API"
			report.Type = "API Documentation"
			report.Description = "Detailed documentation of all commands used during write operations"
			data.ApiDocs = append(data.ApiDocs, report)

		case strings.Contains(r.Path, "read_analysis"):
			report.Title = "Read Operation Analysis"
			report.Type = "Full Analysis"
			report.Description = "Complete analysis of radio read operations and data transfers"
			data.ReadReports = append(data.ReadReports, report)

		case strings.Contains(r.Path, "write_analysis"):
			report.Title = "Write Operation Analysis"
			report.Type = "Full Analysis"
			report.Description = "Complete analysis of radio write operations and programming sequences"
			data.WriteReports = append(data.WriteReports, report)
		}
	}

	// Sort reports by modification time (newest first)
	sort.Slice(data.ReadReports, func(i, j int) bool {
		return data.ReadReports[i].Timestamp > data.ReadReports[j].Timestamp
	})
	sort.Slice(data.WriteReports, func(i, j int) bool {
		return data.WriteReports[i].Timestamp > data.WriteReports[j].Timestamp
	})
	sort.Slice(data.ApiDocs, func(i, j int) bool {
		return data.ApiDocs[i].Timestamp > data.ApiDocs[j].Timestamp
	})

	// Create the template
	tmpl, err := template.New("index").Parse(htmlTemplate)
	if err != nil {
		log.Printf("Error parsing index template: %v", err)
		return
	}

	// Create or open the file
	file, err := os.Create(indexPath)
	if err != nil {
		log.Printf("Error creating index file: %v", err)
		return
	}
	defer file.Close()

	// Execute the template
	err = tmpl.Execute(file, data)
	if err != nil {
		log.Printf("Error executing index template: %v", err)
		return
	}

	fmt.Println("Index page updated at: /home/sannis/REDBUG/index.html")
}

// Helper function to find all report files
func findReports() []ReportInfo {
	var reports []ReportInfo

	// Search patterns for report files
	patterns := []string{
		"dm32uv_read_analysis.html",
		"dm32uv_write_analysis.html",
		"dm32uv_read_api_docs.html",
		"dm32uv_write_api_docs.html",
		"dm32uv_write_api_documentation.html",
		"dm32uv_api_docs.html",
	}

	// Search in common locations
	searchDirs := []string{
		"/home/sannis/REDBUG",
		"/home/sannis/REDBUG/cmd/read_analyzer",
		"/home/sannis/REDBUG/cmd/write_analyzer",
	}

	for _, dir := range searchDirs {
		for _, pattern := range patterns {
			path := filepath.Join(dir, pattern)
			info, err := os.Stat(path)
			if err == nil {
				reports = append(reports, ReportInfo{
					Path:    path,
					Size:    info.Size(),
					ModTime: info.ModTime(),
				})
			}
		}
	}

	return reports
}

// Helper function to format file size
func formatFileSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}
