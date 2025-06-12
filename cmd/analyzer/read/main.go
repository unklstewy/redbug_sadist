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
	"strings"
	"time"

	"github.com/unklstewy/redbug_pulitzer/pkg/reporting"
	"github.com/unklstewy/redbug_sadist/pkg/protocol"
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

func main() {
	if len(os.Args) < 2 {
		fmt.Println("DM-32UV Read Operation Protocol Analyzer")
		fmt.Println("========================================")
		fmt.Println("")
		fmt.Println("Usage:")
		fmt.Println("  go run cmd/read_analyzer/main.go <strace_file>")
		fmt.Println("")
		fmt.Println("Examples:")
		fmt.Println("  go run cmd/read_analyzer/main.go dmr_cps_read_capture.log")
		fmt.Println("  go run cmd/read_analyzer/main.go trace_data.log")
		fmt.Println("")
		fmt.Println("Output:")
		fmt.Println("  - dm32uv_read_analysis.html (detailed HTML report)")
		os.Exit(1)
	}

	filename := os.Args[1]

	fmt.Printf("DM-32UV Read Operation Protocol Analyzer\n")
	fmt.Printf("=========================================\n")
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
	generateHTMLReport(report, "dm32uv_read_analysis.html")

	vendor := "baofeng"
	model := "dm32uv"

	// Generate analysis report
	analysisReportPath := reporting.GetReportPath(vendor, model, reporting.ReportTypeReadAnalysis, "dm32uv_read_analysis.html")

	// Generate API documentation
	apiDocs := convertToProtocolAPICommands(generateCommandAPIDocumentation(cmdResponses))
	apiDocsPath := reporting.GetReportPath(vendor, model, reporting.ReportTypeReadAPI, "dm32uv_read_api_docs.html")
	reporting.GenerateAPIDocHTML(apiDocs, "dm32uv_read_api_docs.html", reporting.ReadMode, vendor, model)

	fmt.Printf("\nAnalysis complete! Generated dm32uv_read_analysis.html\n")
	fmt.Printf("API documentation generated: dm32uv_read_api_docs.html\n")
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
					CommandType:  identifyCommandType(data),
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
					CommandType:  identifyResponseType(data),
				}
				communications = append(communications, comm)
			}
		}
	}

	return communications
}

func analyzeCommandResponses(communications []localCommunication) []protocol.CommandResponse {
	var cmdResponses []protocol.CommandResponse
	var pendingCommands []localCommunication

	sequenceID := 1

	for _, comm := range communications {
		if comm.Direction == "PC→Radio" {
			// This is a command, add to pending
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
					SequenceID:  sequenceID,
					Command:     convertToProtocolCommunication(cmd),
					Response:    convertToProtocolCommunication(comm),
					TimeDelta:   timeDelta,
					IsHandshake: isHandshakeSequence(cmd, comm),
					Description: generateDescription(cmd, comm),
				}

				cmdResponses = append(cmdResponses, cmdResp)
				sequenceID++
			}
		}
	}

	return cmdResponses
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
			// These fields are not in the local CommandAPI but are in protocol.CommandAPI
			// Adding default values
			DataCategory: "",
			SuccessRate:  "",
		}
	}
	return result
}

func identifyCommandType(data []byte) string {
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

func identifyResponseType(data []byte) string {
	if len(data) == 0 {
		return "Empty Response"
	}

	firstByte := data[0]

	switch firstByte {
	case protocol.STX:
		return "STX Response"
	case protocol.ACK:
		return "ACK Response"
	case protocol.NAK:
		return "NAK Response"
	case protocol.SOH:
		return "SOH Response"
	case protocol.ETX:
		return "ETX Response"
	case protocol.EOT:
		return "EOT Response"
	case 0x7E:
		return "Packet Frame Response"
	default:
		// Check if it looks like configuration data
		if len(data) > 8 && utils.IsASCIIPrintable(string(data)) {
			return "Configuration Data"
		} else if len(data) > 16 {
			return "Binary Data Block"
		} else if firstByte >= 0x20 && firstByte <= 0x7E {
			return fmt.Sprintf("ASCII Response '%c' (0x%02X)", firstByte, firstByte)
		}
		return fmt.Sprintf("Binary Response (0x%02X)", firstByte)
	}
}

func isHandshakeSequence(cmd, resp localCommunication) bool {
	// Common handshake patterns
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
		// Common handshake patterns
		if (cmdFirst[0] == protocol.STX && respFirst[0] == protocol.ACK) || // STX -> ACK
			(cmdFirst[0] == protocol.SOH && respFirst[0] == protocol.ACK) || // SOH -> ACK
			(cmdFirst[0] == protocol.EOT && respFirst[0] == protocol.ACK) { // EOT -> ACK
			return true
		}
	}

	// Short command-response pairs are likely handshakes
	return cmd.Length <= 4 && resp.Length <= 4
}

func generateDescription(cmd, resp localCommunication) string {
	if isHandshakeSequence(cmd, resp) {
		return "Handshake: " + cmd.CommandType + " → " + resp.CommandType
	}

	// Try to identify specific operations
	if strings.Contains(cmd.CommandType, "Read") {
		return "Read Operation: Requesting data from radio"
	}

	if strings.Contains(resp.CommandType, "Config") || resp.Length > 32 {
		return "Data Transfer: Radio sending configuration data"
	}

	if strings.Contains(cmd.CommandType, "Program") {
		return "Programming Command: Initiating radio programming"
	}

	return fmt.Sprintf("Command Exchange: %s → %s", cmd.CommandType, resp.CommandType)
}

// Keep the rest of the code below as it is, but update any references to use the shared packages
// where appropriate...

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

func generateCommandAPIDocumentation(cmdResponses []protocol.CommandResponse) []CommandAPI {
	// Map to track unique commands
	uniqueCommands := make(map[string]CommandAPI)
	timingMap := make(map[string][]time.Duration)

	// Process all command-response pairs
	for _, cr := range cmdResponses {
		// Create a unique key for this command based on its hex value
		cmdKey := cr.Command.RawHex

		// Parse timing for averaging
		timeDuration := utils.ParseTimeDelta(cr.TimeDelta)
		if timeDuration > 0 {
			timingMap[cmdKey] = append(timingMap[cmdKey], timeDuration)
		}

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
		}

		uniqueCommands[cmdKey] = apiEntry
	}

	// Calculate average timing for each command
	for cmdKey, api := range uniqueCommands {
		if times, exists := timingMap[cmdKey]; exists && len(times) > 0 {
			var total time.Duration
			for _, t := range times {
				total += t
			}
			avgTime := total / time.Duration(len(times))

			// Format the time nicely
			var timeStr string
			if avgTime.Microseconds() < 1000 {
				timeStr = fmt.Sprintf("%dμs", avgTime.Microseconds())
			} else if avgTime.Milliseconds() < 1000 {
				timeStr = fmt.Sprintf("%.1fms", float64(avgTime.Microseconds())/1000.0)
			} else {
				timeStr = fmt.Sprintf("%.2fs", avgTime.Seconds())
			}

			api.TimingAverage = timeStr
			uniqueCommands[cmdKey] = api
		}
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

// Keep the existing report generation code since it's specific to the read analyzer
// ...

type AnalysisReport struct {
	TotalCommunications int
	CommandCount        int
	ResponseCount       int
	HandshakeSequences  []protocol.CommandResponse
	CommandResponses    []protocol.CommandResponse
	UniqueCommands      map[string]int
	FileDescriptors     map[string]string
	GeneratedAt         string
}

func generateAnalysisReport(communications []localCommunication, cmdResponses []protocol.CommandResponse) AnalysisReport {
	report := AnalysisReport{
		TotalCommunications: len(communications),
		UniqueCommands:      make(map[string]int),
		FileDescriptors:     make(map[string]string),
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

	// Separate handshakes from regular command-responses
	for _, cmdResp := range cmdResponses {
		if cmdResp.IsHandshake {
			report.HandshakeSequences = append(report.HandshakeSequences, cmdResp)
		} else {
			report.CommandResponses = append(report.CommandResponses, cmdResp)
		}
	}

	return report
}

// Keep the HTML report generation as-is since it's specific to the read analyzer
func generateHTMLReport(report AnalysisReport, filename string) {
	htmlTemplate := `
<!DOCTYPE html>
<html>
<head>
    <title>DM-32UV Read Operation Analysis</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; text-align: center; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; font-size: 12px; }
        th, td { border: 1px solid #ddd; padding: 6px; text-align: left; vertical-align: top; }
        th { background-color: #3498db; color: white; font-weight: bold; }
        .command { background-color: #e8f5e8; }
        .response { background-color: #e8f0ff; }
        .handshake { background-color: #fff5e6; }
        .hex { font-family: 'Courier New', monospace; font-size: 11px; word-break: break-all; max-width: 200px; }
        .ascii { font-family: 'Courier New', monospace; font-size: 11px; color: #666; max-width: 150px; word-break: break-all; }
        .summary { background-color: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .timestamp { font-size: 10px; color: #666; }
        .stats { display: flex; justify-content: space-around; margin: 20px 0; }
        .stat-box { text-align: center; padding: 15px; background-color: #3498db; color: white; border-radius: 5px; flex: 1; margin: 0 5px; }
        .command-type { font-weight: bold; color: #2c3e50; }
        .description { font-style: italic; color: #7f8c8d; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 DM-32UV Read Operation Protocol Analysis</h1>
        
        <div class="summary">
            <h2>📊 Analysis Summary</h2>
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
                    <div>Radio→PC Responses</div>
                </div>
                <div class="stat-box">
                    <div style="font-size: 24px; font-weight: bold;">{{len .HandshakeSequences}}</div>
                    <div>Handshake Sequences</div>
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

        <h2>💬 Command-Response Pairs (Data Exchanges)</h2>
        <table>
            <tr>
                <th width="5%">Seq</th>
                <th width="10%">Time</th>
                <th width="25%">Command (PC→Radio)</th>
                <th width="25%">Response (Radio→PC)</th>
                <th width="8%">Delta</th>
                <th width="27%">Description</th>
            </tr>
            {{range .CommandResponses}}
            <tr>
                <td>{{.SequenceID}}</td>
                <td class="timestamp">{{.Command.Timestamp}}</td>
                <td class="command">
                    <div class="command-type">{{.Command.CommandType}} ({{.Command.Length}} bytes)</div>
                    <div class="hex">{{.Command.RawHex}}</div>
                    <div class="ascii">{{.Command.DecodedASCII}}</div>
                </td>
                <td class="response">
                    <div class="command-type">{{.Response.CommandType}} ({{.Response.Length}} bytes)</div>
                    <div class="hex">{{.Response.RawHex}}</div>
                    <div class="ascii">{{.Response.DecodedASCII}}</div>
                </td>
                <td>{{.TimeDelta}}</td>
                <td class="description">{{.Description}}</td>
            </tr>
            {{end}}
        </table>

        <div style="margin-top: 50px; text-align: center; color: #7f8c8d; border-top: 1px solid #bdc3c7; padding-top: 20px;">
            <p>Generated by DM-32UV Protocol Analyzer | {{.GeneratedAt}}</p>
        </div>
    </div>
</body>
</html>
`

	// Add template functions for calculations - Fixed the percentage calculation
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
