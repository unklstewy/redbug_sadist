package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// Operation represents a single write or read operation
type Operation struct {
	Type      string // "write" or "read"
	Timestamp string // timestamp from log
	FD        string // file descriptor
	HexData   []byte // binary data
	HexString string // hex representation
	LineNum   int    // line number in file
	PacketNum int    // sequential packet number
	PacketHex string // hexadecimal packet number
}

// CommandResponsePair represents a matched command and response
type CommandResponsePair struct {
	Command  Operation
	Response Operation
}

// ProtocolCommand represents a recognized protocol command with its expected responses
type ProtocolCommand struct {
	CommandHex      string   `json:"commandHex"`      // Hex representation of command
	CommandBytes    []byte   `json:"-"`               // Binary representation (not included in JSON)
	Description     string   `json:"description"`     // Auto-generated description
	ResponsePattern string   `json:"responsePattern"` // Common response pattern
	ResponseBytes   []byte   `json:"-"`               // Binary representation (not included in JSON)
	ResponseHex     string   `json:"responseHex"`     // Hex representation of typical response
	Occurrences     int      `json:"occurrences"`     // Number of times this pattern occurs
	TimestampFirst  string   `json:"timestampFirst"`  // First occurrence timestamp
	TimestampLast   string   `json:"timestampLast"`   // Last occurrence timestamp
	LineNumbers     []int    `json:"lineNumbers"`     // Line numbers where this occurs
	IsHandshake     bool     `json:"isHandshake"`     // Whether this appears to be a handshake
	ResponseTypes   []string `json:"responseTypes"`   // Types of responses seen
	PacketNumbers   []string `json:"packetNumbers"`   // Hexadecimal packet numbers where this occurs
}

func main() {
	// Parse command line arguments
	logFile := flag.String("file", "", "Path to the strace log file")
	outputFile := flag.String("output", "protocol_commands.json", "Path to output the structured commands")
	flag.Parse()

	if *logFile == "" {
		fmt.Println("Please provide a log file with -file=path/to/logfile")
		os.Exit(1)
	}

	// Open the log file
	file, err := os.Open(*logFile)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	// Regular expressions for identifying operations and hex dumps
	writeRegex := regexp.MustCompile(`(\d+)\s+(\d{2}:\d{2}:\d{2}\.\d+)\s+write\((\d+),.*\)\s*=\s*(\d+)`)
	readRegex := regexp.MustCompile(`(\d+)\s+(\d{2}:\d{2}:\d{2}\.\d+)\s+read\((\d+),.*\)\s*=\s*(\d+)`)
	hexDumpRegex := regexp.MustCompile(`\|\s+[0-9a-f]+\s+((?:[0-9a-f]{2}\s+)+).*\|`)

	// Arrays to store operations
	var operations []Operation
	var currentOp *Operation

	// Read the file line by line
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Check if this is a write operation
		if matches := writeRegex.FindStringSubmatch(line); len(matches) >= 4 {
			// If we were collecting data for a previous operation, save it
			if currentOp != nil && len(currentOp.HexData) > 0 {
				operations = append(operations, *currentOp)
				currentOp = nil
			}

			// Start a new write operation
			currentOp = &Operation{
				Type:      "write",
				Timestamp: matches[2],
				FD:        matches[3],
				LineNum:   lineNum,
			}
			continue
		}

		// Check if this is a read operation
		if matches := readRegex.FindStringSubmatch(line); len(matches) >= 4 {
			// If we were collecting data for a previous operation, save it
			if currentOp != nil && len(currentOp.HexData) > 0 {
				operations = append(operations, *currentOp)
				currentOp = nil
			}

			// Start a new read operation
			currentOp = &Operation{
				Type:      "read",
				Timestamp: matches[2],
				FD:        matches[3],
				LineNum:   lineNum,
			}
			continue
		}

		// Check if this is a hex dump line
		if currentOp != nil && hexDumpRegex.MatchString(line) {
			matches := hexDumpRegex.FindStringSubmatch(line)
			if len(matches) >= 2 {
				hexBytes := matches[1]
				// Clean up the hex string
				hexBytes = strings.ReplaceAll(hexBytes, " ", "")

				// Convert to bytes
				lineBytes, err := hex.DecodeString(hexBytes)
				if err == nil {
					currentOp.HexData = append(currentOp.HexData, lineBytes...)
					currentOp.HexString = hex.EncodeToString(currentOp.HexData)
				}
			}
			continue
		}

		// If we reach a non-hex-dump line and we were collecting data, save the operation
		if currentOp != nil && len(currentOp.HexData) > 0 {
			operations = append(operations, *currentOp)
			currentOp = nil
		}
	}

	// Save the last operation if there is one
	if currentOp != nil && len(currentOp.HexData) > 0 {
		operations = append(operations, *currentOp)
	}

	// Check for scanner errors
	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		os.Exit(1)
	}

	// Now analyze the operations to find command-response pairs
	fmt.Printf("Found %d operations (%d writes, %d reads)\n",
		len(operations),
		countByType(operations, "write"),
		countByType(operations, "read"))

	// Group into command-response pairs
	pairs := buildCommandResponsePairs(operations)
	fmt.Printf("Identified %d command-response pairs\n", len(pairs))

	// Analyze the command-response patterns
	protocolCommands := identifyProtocolCommands(pairs)
	fmt.Printf("Extracted %d distinct protocol commands\n", len(protocolCommands))

	// Output the protocol commands to JSON file
	outputProtocolCommands(protocolCommands, *outputFile)

	// Generate a Go struct file for direct import
	generateGoStructFile(protocolCommands, strings.Replace(*outputFile, ".json", ".go", 1))
}

// Count operations by type
func countByType(operations []Operation, opType string) int {
	count := 0
	for _, op := range operations {
		if op.Type == opType {
			count++
		}
	}
	return count
}

// buildCommandResponsePairs groups operations into command-response pairs
func buildCommandResponsePairs(operations []Operation) []CommandResponsePair {
	var pairs []CommandResponsePair

	// Enhanced approach: try to match writes with reads more intelligently
	for i := 0; i < len(operations); i++ {
		if operations[i].Type != "write" || len(operations[i].HexData) == 0 {
			continue
		}

		// Found a write, look for the next read
		for j := i + 1; j < len(operations) && j < i+5; j++ { // Look ahead a few operations
			if operations[j].Type == "read" && len(operations[j].HexData) > 0 {
				// Found a matching read
				pairs = append(pairs, CommandResponsePair{
					Command:  operations[i],
					Response: operations[j],
				})
				break
			}
		}
	}

	return pairs
}

// identifyProtocolCommands analyzes pairs to identify distinct protocol commands
func identifyProtocolCommands(pairs []CommandResponsePair) []ProtocolCommand {
	// Map to track unique command patterns
	commandMap := make(map[string]*ProtocolCommand)

	for _, pair := range pairs {
		cmdHex := pair.Command.HexString
		respHex := pair.Response.HexString

		// Skip empty commands or responses
		if cmdHex == "" || respHex == "" {
			continue
		}

		// Check if we've seen this command pattern before
		if cmd, exists := commandMap[cmdHex]; exists {
			// Update existing command
			cmd.Occurrences++
			cmd.TimestampLast = pair.Command.Timestamp
			cmd.LineNumbers = append(cmd.LineNumbers, pair.Command.LineNum)

			// Check if this is a new response pattern
			isNewResponse := true
			for _, respType := range cmd.ResponseTypes {
				if respType == respHex {
					isNewResponse = false
					break
				}
			}

			if isNewResponse {
				cmd.ResponseTypes = append(cmd.ResponseTypes, respHex)
			}
		} else {
			// Create a new command pattern
			responseType := categorizeResponse(pair.Response.HexData)

			cmd := &ProtocolCommand{
				CommandHex:      cmdHex,
				CommandBytes:    pair.Command.HexData,
				Description:     generateCommandDescription(pair.Command.HexData),
				ResponsePattern: responseType,
				ResponseBytes:   pair.Response.HexData,
				ResponseHex:     respHex,
				Occurrences:     1,
				TimestampFirst:  pair.Command.Timestamp,
				TimestampLast:   pair.Command.Timestamp,
				LineNumbers:     []int{pair.Command.LineNum},
				IsHandshake:     isHandshakeCommand(pair.Command.HexData, pair.Response.HexData),
				ResponseTypes:   []string{respHex},
			}

			commandMap[cmdHex] = cmd
		}
	}

	// Convert map to slice
	var commands []ProtocolCommand
	for _, cmd := range commandMap {
		commands = append(commands, *cmd)
	}

	// Sort by occurrence count (most frequent first)
	for i := 0; i < len(commands); i++ {
		for j := i + 1; j < len(commands); j++ {
			if commands[i].Occurrences < commands[j].Occurrences {
				commands[i], commands[j] = commands[j], commands[i]
			}
		}
	}

	return commands
}

// categorizeResponse tries to determine the type of response
func categorizeResponse(data []byte) string {
	if len(data) == 0 {
		return "Empty"
	}

	// Check for common response types - this should be expanded based on protocol knowledge
	switch data[0] {
	case 0x06: // Common ACK byte
		return "ACK"
	case 0x15: // Common NAK byte
		return "NAK"
	case 0x02: // Common STX (start of text) byte
		return "DATA"
	default:
		if len(data) == 1 {
			return fmt.Sprintf("SINGLE_BYTE_0x%02X", data[0])
		} else if len(data) <= 4 {
			return "SHORT_RESPONSE"
		} else {
			return "DATA_PACKET"
		}
	}
}

// generateCommandDescription creates a descriptive name for a command
func generateCommandDescription(data []byte) string {
	if len(data) == 0 {
		return "Empty Command"
	}

	// Examine first byte for command type
	cmdType := ""
	switch data[0] {
	case 0x50, 0x51, 0x52: // Removed 0x53 from here
		cmdType = "GET_DATA"
	case 0x57, 0x58, 0x59:
		cmdType = "SET_DATA"
	case 0x45:
		cmdType = "ERASE"
	case 0x49:
		cmdType = "INITIALIZE"
	case 0x43:
		cmdType = "CONTROL"
	case 0x53: // This is now the only case for 0x53
		cmdType = "STATUS"
	default:
		cmdType = fmt.Sprintf("CMD_0x%02X", data[0])
	}

	// Add length info
	return fmt.Sprintf("%s (%d bytes)", cmdType, len(data))
}

// isHandshakeCommand checks if a command-response pair appears to be a handshake
func isHandshakeCommand(cmdData, respData []byte) bool {
	// Simple handshake detection - typically short commands with short responses
	if len(cmdData) <= 4 && len(respData) <= 4 {
		return true
	}

	// If the response is a single ACK or NAK byte
	if len(respData) == 1 && (respData[0] == 0x06 || respData[0] == 0x15) {
		return true
	}

	return false
}

// outputProtocolCommands writes the protocol commands to a JSON file
func outputProtocolCommands(commands []ProtocolCommand, filename string) {
	// Create a serializable structure
	type SerializableCommand struct {
		CommandHex      string   `json:"commandHex"`
		Description     string   `json:"description"`
		ResponsePattern string   `json:"responsePattern"`
		ResponseHex     string   `json:"responseHex"`
		Occurrences     int      `json:"occurrences"`
		TimestampFirst  string   `json:"timestampFirst"`
		TimestampLast   string   `json:"timestampLast"`
		LineNumbers     []int    `json:"lineNumbers"`
		IsHandshake     bool     `json:"isHandshake"`
		ResponseTypes   []string `json:"responseTypes"`
	}

	var serializableCommands []SerializableCommand
	for _, cmd := range commands {
		serializableCommands = append(serializableCommands, SerializableCommand{
			CommandHex:      cmd.CommandHex,
			Description:     cmd.Description,
			ResponsePattern: cmd.ResponsePattern,
			ResponseHex:     cmd.ResponseHex,
			Occurrences:     cmd.Occurrences,
			TimestampFirst:  cmd.TimestampFirst,
			TimestampLast:   cmd.TimestampLast,
			LineNumbers:     cmd.LineNumbers,
			IsHandshake:     cmd.IsHandshake,
			ResponseTypes:   cmd.ResponseTypes,
		})
	}

	// Marshal to JSON
	jsonData, err := json.MarshalIndent(serializableCommands, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling to JSON: %v\n", err)
		return
	}

	// Write to file
	err = os.WriteFile(filename, jsonData, 0644)
	if err != nil {
		fmt.Printf("Error writing to file: %v\n", err)
		return
	}

	fmt.Printf("Protocol commands written to %s\n", filename)
}

// generateGoStructFile creates a Go file with command constants
func generateGoStructFile(commands []ProtocolCommand, filename string) {
	// Create the file
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("Error creating file: %v\n", err)
		return
	}
	defer file.Close()

	// Write package declaration
	file.WriteString("// Code generated from log analysis. DO NOT EDIT.\n")
	file.WriteString(fmt.Sprintf("// Generated on %s\n\n", time.Now().Format(time.RFC3339)))
	file.WriteString("package read\n\n")

	// Import necessary packages
	file.WriteString("import (\n")
	file.WriteString("\t\"encoding/hex\"\n")
	file.WriteString("\t\"time\"\n")
	file.WriteString(")\n\n")

	// Write ProtocolCommand struct
	file.WriteString("// DM32UVCommand represents a recognized command in the DM-32UV protocol\n")
	file.WriteString("type DM32UVCommand struct {\n")
	file.WriteString("\tCommandHex      string\n")
	file.WriteString("\tCommandBytes    []byte\n")
	file.WriteString("\tDescription     string\n")
	file.WriteString("\tResponsePattern string\n")
	file.WriteString("\tResponseBytes   []byte\n")
	file.WriteString("\tResponseHex     string\n")
	file.WriteString("\tIsHandshake     bool\n")
	file.WriteString("\tOriginalName    string\n") // Added to store the original command name
	file.WriteString("}\n\n")

	// Create a map of DM32UVCommands
	file.WriteString("// DM32UVCommands is a map of all recognized DM-32UV protocol commands\n")
	file.WriteString("var DM32UVCommands = map[string]DM32UVCommand{\n")

	// Add each command to the map with sequential hex packet numbers
	for i, cmd := range commands {
		// Create a command name with incremental hex number
		cmdName := fmt.Sprintf("CMDPKT_%04X", i+1) // Use hex numbering starting from 0001

		// Store the original command name for reference
		originalName := fmt.Sprintf("CMD_%s", sanitizeForVarName(cmd.CommandHex[:min(8, len(cmd.CommandHex))]))

		file.WriteString(fmt.Sprintf("\t\"%s\": {\n", cmdName))
		file.WriteString(fmt.Sprintf("\t\tCommandHex:      \"%s\",\n", cmd.CommandHex))
		file.WriteString(fmt.Sprintf("\t\tCommandBytes:    hexMustDecode(\"%s\"),\n", cmd.CommandHex))
		file.WriteString(fmt.Sprintf("\t\tDescription:     \"%s\",\n", cmd.Description))
		file.WriteString(fmt.Sprintf("\t\tResponsePattern: \"%s\",\n", cmd.ResponsePattern))
		file.WriteString(fmt.Sprintf("\t\tResponseBytes:   hexMustDecode(\"%s\"),\n", cmd.ResponseHex))
		file.WriteString(fmt.Sprintf("\t\tResponseHex:     \"%s\",\n", cmd.ResponseHex))
		file.WriteString(fmt.Sprintf("\t\tIsHandshake:     %v,\n", cmd.IsHandshake))
		file.WriteString(fmt.Sprintf("\t\tOriginalName:    \"%s\",\n", originalName))
		file.WriteString("\t},\n")

		// Add a newline every 5 commands for readability
		if (i+1)%5 == 0 {
			file.WriteString("\n")
		}
	}

	file.WriteString("}\n\n")

	// Add helper functions
	file.WriteString("// hexMustDecode converts a hex string to bytes, panicking on error\n")
	file.WriteString("func hexMustDecode(s string) []byte {\n")
	file.WriteString("\tb, err := hex.DecodeString(s)\n")
	file.WriteString("\tif err != nil {\n")
	file.WriteString("\t\tpanic(err)\n")
	file.WriteString("\t}\n")
	file.WriteString("\treturn b\n")
	file.WriteString("}\n\n")

	// Add a CommandFinder function
	file.WriteString("// FindMatchingCommand finds a command that matches the given hex data\n")
	file.WriteString("func FindMatchingCommand(data []byte) (string, bool) {\n")
	file.WriteString("\thexStr := hex.EncodeToString(data)\n")
	file.WriteString("\tfor name, cmd := range DM32UVCommands {\n")
	file.WriteString("\t\tif cmd.CommandHex == hexStr {\n")
	file.WriteString("\t\t\treturn name, true\n")
	file.WriteString("\t\t}\n")
	file.WriteString("\t}\n")
	file.WriteString("\treturn \"\", false\n")
	file.WriteString("}\n")

	fmt.Printf("Go struct file written to %s\n", filename)
}

// sanitizeForVarName converts a hex string to a valid variable name
func sanitizeForVarName(s string) string {
	// Replace non-alphanumeric characters with underscores
	re := regexp.MustCompile(`[^a-zA-Z0-9]`)
	return re.ReplaceAllString(s, "_")
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
