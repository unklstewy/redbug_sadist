package analyzer

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/unklstewy/redbug_sadist/pkg/protocol"
	"github.com/unklstewy/redbug_sadist/pkg/utils"
)

// BaseAnalyzer provides common functionality for all analyzers
type BaseAnalyzer struct {
	Vendor string
	Model  string
	Mode   string
	Debug  bool
}

// ParseStraceFile parses a strace log file and extracts communications
func (a *BaseAnalyzer) ParseStraceFile(filename string) ([]protocol.Communication, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	var communications []protocol.Communication
	scanner := bufio.NewScanner(file)

	// A single regex to match both read/write lines with optional "..." and capturing the entire string
	logRegex := regexp.MustCompile(`(?i)^(\d+)\s+(\d{2}:\d{2}:\d{2}\.\d{6})\s+(read|write)\((\d+),\s*"([^"]*)(?:\.\.\.)?",\s*(\d+)\)\s*=\s*(\d+)`)

	for scanner.Scan() {
		line := scanner.Text()

		// Skip hex dumps
		if strings.HasPrefix(line, " | ") {
			continue
		}

		matches := logRegex.FindStringSubmatch(line)
		if len(matches) == 8 {
			// pid := matches[1]
			timestamp := matches[2]
			op := strings.ToLower(matches[3]) // "read" or "write"
			fileDesc := matches[4]
			dataStr := matches[5] // captured content in quotes
			// lengthStr := matches[6]
			// bytesTransferred := matches[7]

			data := utils.UnescapeString(dataStr)
			if len(data) == 0 {
				continue
			}

			direction := ""
			if op == "write" {
				direction = "PC→Radio"
			} else {
				direction = "Radio→PC"
			}

			// Create a new communication
			comm := protocol.Communication{
				Timestamp:    timestamp,
				Direction:    direction,
				FileDesc:     fileDesc,
				RawHex:       fmt.Sprintf("%x", data),
				DecodedASCII: utils.DecodeToASCII(data),
				Length:       len(data),
				Notes:        "",
			}

			communications = append(communications, comm)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}

	return communications, nil
}

// PairCommandsWithResponses pairs commands with their responses
func (a *BaseAnalyzer) PairCommandsWithResponses(comms []protocol.Communication) []protocol.CommandResponse {
	var cmdResponses []protocol.CommandResponse
	sequenceID := 1

	for i := 0; i < len(comms)-1; i++ {
		// Look for PC→Radio followed by Radio→PC
		if comms[i].Direction == "PC→Radio" && i+1 < len(comms) && comms[i+1].Direction == "Radio→PC" {
			// Calculate time delta between command and response
			startTime, _ := time.Parse("15:04:05.000000", comms[i].Timestamp)
			endTime, _ := time.Parse("15:04:05.000000", comms[i+1].Timestamp)
			delta := endTime.Sub(startTime)

			// Create command-response pair
			cmdResp := protocol.CommandResponse{
				SequenceID: sequenceID,
				Command:    comms[i],
				Response:   comms[i+1],
				TimeDelta:  formatTimeDelta(delta),
			}

			cmdResponses = append(cmdResponses, cmdResp)
			sequenceID++

			// Skip the response in the next iteration
			i++
		}
	}

	return cmdResponses
}

// Helper function to format time delta
func formatTimeDelta(delta time.Duration) string {
	if delta < time.Millisecond {
		return fmt.Sprintf("%.3f µs", float64(delta.Microseconds()))
	} else if delta < time.Second {
		return fmt.Sprintf("%.3f ms", float64(delta.Microseconds())/1000.0)
	} else {
		return fmt.Sprintf("%.3f s", delta.Seconds())
	}
}

// CreateBasicAnalysisResult creates a basic analysis result structure
func (a *BaseAnalyzer) CreateBasicAnalysisResult(comms []protocol.Communication, cmdResps []protocol.CommandResponse) *protocol.AnalysisResult {
	result := &protocol.AnalysisResult{
		AnalyzerName:     fmt.Sprintf("%s %s %s Protocol Analyzer", a.Vendor, a.Model, a.Mode),
		TimeStamp:        time.Now().Format(time.RFC3339),
		Vendor:           a.Vendor,
		Model:            a.Model,
		Mode:             a.Mode,
		Communications:   comms,
		CommandResponses: cmdResps,
		Summary: protocol.Summary{
			TotalCommands:  0,
			SuccessCount:   0,
			ErrorCount:     0,
			CommandTypes:   make(map[string]int),
			DataCategories: make(map[string]int),
		},
	}

	// Update summary statistics
	for _, comm := range comms {
		if comm.Direction == "PC→Radio" {
			result.Summary.TotalCommands++
			result.Summary.CommandTypes[comm.CommandType]++
		} else if comm.Direction == "Radio→PC" {
			if strings.Contains(comm.CommandType, "ACK") {
				result.Summary.SuccessCount++
			} else if strings.Contains(comm.CommandType, "NAK") {
				result.Summary.ErrorCount++
			}
		}
	}

	// Track data categories if specified
	for _, cr := range cmdResps {
		if cr.DataCategory != "" {
			result.Summary.DataCategories[cr.DataCategory]++
		}
	}

	return result
}
