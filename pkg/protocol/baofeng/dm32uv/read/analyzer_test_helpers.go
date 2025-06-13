package read

import (
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"
	//"time"
)

// // Command represents a command sent to the radio
// type Command struct {
// 	Data      []byte
// 	Timestamp time.Time
// }

// // Response represents a response received from the radio
// type Response struct {
// 	Data      []byte
// 	Timestamp time.Time
// }

// // CommandResponsePair represents a command and its associated responses
// type CommandResponsePair struct {
// 	Command   Command
// 	Responses []Response
// }

// ParseLogFileForTesting parses a log file and returns command-response pairs for testing
func (a *DM32UVReadAnalyzer) ParseLogFileForTesting(filename string) ([]CommandResponsePair, error) {
	// Read the file
	fileData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read log file: %w", err)
	}

	// Split into lines
	lines := strings.Split(string(fileData), "\n")

	// Detect the log format
	format := detectLogFormat(lines)
	fmt.Printf("Detected log format: %s\n", format)

	// Parse based on the detected format
	var pairs []CommandResponsePair
	var parseErr error

	switch format {
	case "strace":
		pairs, parseErr = a.parseStraceFormat(lines)
	case "cmdrsp":
		pairs, parseErr = a.parseCmdRspFormat(lines)
	default:
		return nil, fmt.Errorf("unsupported log format")
	}

	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse log file: %w", parseErr)
	}

	fmt.Printf("Parsed %d command-response pairs\n", len(pairs))

	// Enhance the parsing with command identification
	for i := range pairs {
		// Try to identify the command using dm32uv_commands
		cmdHex := hex.EncodeToString(pairs[i].Command.Data)
		fmt.Printf("Looking up command: %s\n", cmdHex)

		// Add additional debug information
		if len(pairs[i].Command.Data) > 0 {
			firstByte := pairs[i].Command.Data[0]
			fmt.Printf("Command first byte: 0x%02X\n", firstByte)
		}
	}

	return pairs, nil
}

// detectLogFormat determines the format of the log file
func detectLogFormat(lines []string) string {
	// Check for strace format (look for write/read syscalls)
	stracePattern := regexp.MustCompile(`\d+\s+\d{2}:\d{2}:\d{2}\.\d+\s+(write|read)\(`)

	// Check for CMD/RSP format
	cmdRspPattern := regexp.MustCompile(`^(CMD|RSP):`)

	for _, line := range lines {
		if stracePattern.MatchString(line) {
			return "strace"
		}
		if cmdRspPattern.MatchString(line) {
			return "cmdrsp"
		}
	}

	// Default to strace if we can't determine
	return "strace"
}
