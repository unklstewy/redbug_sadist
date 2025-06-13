package write

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/unklstewy/redbug_sadist/pkg/protocol/analyzer"
)

func TestDM32UVWriteAnalyzer(t *testing.T) {
	// Create temporary test file
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test_write.strace")

	// Sample strace content with write commands
	sampleContent := `12:34:56.789 write(3, "\x57\x01\x02\x03", 4) = 4
12:34:56.890 read(3, "\x06", 1) = 1
12:34:57.000 write(3, "\x57\x02\x04\x05\x06", 5) = 5
12:34:57.100 read(3, "\x15", 1) = 1
`

	// Write test content to file
	err := os.WriteFile(testFile, []byte(sampleContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Create and initialize analyzer
	config := analyzer.Config{
		VerboseOutput: true,
	}
	a := NewDM32UVWriteAnalyzer(config)

	// Run analysis
	result, err := a.Analyze(testFile)
	if err != nil {
		t.Fatalf("Analyzer failed: %v", err)
	}

	// Verify results
	if result == nil {
		t.Fatal("Expected analysis result, got nil")
	}

	// Check if we found the expected communications
	expectedComms := 4 // 2 writes and 2 reads
	if len(result.Communications) != expectedComms {
		t.Errorf("Expected %d communications, got %d", expectedComms, len(result.Communications))
	}

	// Check summary statistics
	if result.Summary.TotalCommands != 2 {
		t.Errorf("Expected 2 commands, got %d", result.Summary.TotalCommands)
	}

	if result.Summary.SuccessCount != 1 {
		t.Errorf("Expected 1 success, got %d", result.Summary.SuccessCount)
	}

	if result.Summary.ErrorCount != 1 {
		t.Errorf("Expected 1 error, got %d", result.Summary.ErrorCount)
	}
}

func TestDM32UVWriteAnalyzer_GetInfo(t *testing.T) {
	analyzer := NewDM32UVWriteAnalyzer()
	info := analyzer.GetInfo()

	if info.Vendor != "baofeng" {
		t.Errorf("Expected vendor to be 'baofeng', got '%s'", info.Vendor)
	}

	if info.Model != "dm32uv" {
		t.Errorf("Expected model to be 'dm32uv', got '%s'", info.Model)
	}

	if info.Modes != "write" {
		t.Errorf("Expected modes to be 'write', got '%s'", info.Modes)
	}
}

func TestDM32UVWriteAnalyzer_IdentifyCommandType(t *testing.T) {
	analyzer := NewDM32UVWriteAnalyzer()

	testCases := []struct {
		name     string
		data     []byte
		expected string
	}{
		{"Empty", []byte{}, "Empty"},
		{"STX", []byte{0x02}, "STX (Start of Text)"},
		{"ACK", []byte{0x06}, "ACK (Acknowledge)"},
		{"NAK", []byte{0x15}, "NAK (Negative Acknowledge)"},
		{"Write Request", []byte{0x57, 0x01, 0x02}, "Write Request"},
		{"Program Command", []byte{0x50, 0x01, 0x02}, "Program Command"},
		{"ASCII", []byte{0x41, 0x42, 0x43}, "ASCII Command (A)"},
		{"Unknown", []byte{0xF0, 0xF1, 0xF2}, "Unknown (0xF0)"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := analyzer.identifyCommandType(tc.data)
			if result != tc.expected {
				t.Errorf("Expected '%s', got '%s'", tc.expected, result)
			}
		})
	}
}

func TestDM32UVWriteAnalyzer_IdentifyResponseType(t *testing.T) {
	analyzer := NewDM32UVWriteAnalyzer()

	testCases := []struct {
		name     string
		data     []byte
		expected string
	}{
		{"Empty", []byte{}, "Empty"},
		{"ACK", []byte{0x06}, "ACK (Acknowledge)"},
		{"NAK", []byte{0x15}, "NAK (Negative Acknowledge)"},
		{"Write Success", []byte{0x57, 0x00}, "Write Success"},
		{"Write Error", []byte{0x57, 0x01}, "Write Error (0x01)"},
		{"Program Success", []byte{0x50, 0x00}, "Program Success"},
		{"Program Error", []byte{0x50, 0x01}, "Program Error (0x01)"},
		{"ASCII Response", []byte{0x41, 0x42, 0x43}, "Response (A)"},
		{"Unknown Response", []byte{0xF0, 0xF1, 0xF2}, "Response (0xF0)"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := analyzer.identifyResponseType(tc.data)
			if result != tc.expected {
				t.Errorf("Expected '%s', got '%s'", tc.expected, result)
			}
		})
	}
}

func TestDM32UVWriteAnalyzer_ParseStraceFile(t *testing.T) {
	// Skip if we don't have test data available
	testDataPath := filepath.Join("testdata", "sample_write.strace")
	if _, err := os.Stat(testDataPath); os.IsNotExist(err) {
		t.Skip("Test data file not available, skipping test")
	}

	analyzer := NewDM32UVWriteAnalyzer()
	comms := analyzer.parseStraceFile(testDataPath)

	if len(comms) == 0 {
		t.Error("Expected to parse some communications, got none")
	}

	// Check if we have both directions in the parsed data
	hasPC2Radio := false
	hasRadio2PC := false

	for _, comm := range comms {
		if comm.Direction == "PC→Radio" {
			hasPC2Radio = true
		}
		if comm.Direction == "Radio→PC" {
			hasRadio2PC = true
		}
	}

	if !hasPC2Radio {
		t.Error("No PC→Radio communications found")
	}

	if !hasRadio2PC {
		t.Error("No Radio→PC communications found")
	}
}

func TestDM32UVWriteAnalyzer_AnalyzeCommandResponses(t *testing.T) {
	analyzer := NewDM32UVWriteAnalyzer()

	// Create some test communications
	comms := []localCommunication{
		{
			Timestamp:   "12:00:00.000000",
			Direction:   "PC→Radio",
			RawHex:      "570102",
			CommandType: "Write Request",
		},
		{
			Timestamp:   "12:00:00.100000",
			Direction:   "Radio→PC",
			RawHex:      "5700",
			CommandType: "Write Success",
		},
		{
			Timestamp:   "12:00:01.000000",
			Direction:   "PC→Radio",
			RawHex:      "500102",
			CommandType: "Program Command",
		},
		{
			Timestamp:   "12:00:01.100000",
			Direction:   "Radio→PC",
			RawHex:      "5000",
			CommandType: "Program Success",
		},
	}

	cmdResps := analyzer.analyzeCommandResponses(comms)

	if len(cmdResps) != 2 {
		t.Errorf("Expected 2 command-response pairs, got %d", len(cmdResps))
	}

	if len(cmdResps[0].Responses) != 1 {
		t.Errorf("Expected 1 response for first command, got %d", len(cmdResps[0].Responses))
	}

	if cmdResps[0].Command.CommandType != "Write Request" {
		t.Errorf("Expected 'Write Request', got '%s'", cmdResps[0].Command.CommandType)
	}

	if cmdResps[0].Responses[0].CommandType != "Write Success" {
		t.Errorf("Expected 'Write Success', got '%s'", cmdResps[0].Responses[0].CommandType)
	}
}

func TestIdentifyCommand(t *testing.T) {
	a := &DM32UVWriteAnalyzer{}

	testCases := []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "Empty data",
			data:     []byte{},
			expected: "Unknown Write Command",
		},
		{
			name:     "Generic write command",
			data:     []byte{0x57, 0x01, 0x02, 0x03},
			expected: "Write Command 0x01",
		},
		// Add more test cases as needed
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := a.identifyCommand(tc.data)
			if result != tc.expected {
				t.Errorf("Expected '%s', got '%s'", tc.expected, result)
			}
		})
	}
}

func TestIdentifyResponseType(t *testing.T) {
	a := &DM32UVWriteAnalyzer{}

	testCases := []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "Empty response",
			data:     []byte{},
			expected: "Empty Response",
		},
		{
			name:     "ACK response",
			data:     []byte{0x06},
			expected: "ACK (Acknowledged)",
		},
		{
			name:     "NAK response",
			data:     []byte{0x15},
			expected: "NAK (Not Acknowledged)",
		},
		{
			name:     "Status response",
			data:     []byte{0x53, 0x01, 0x02},
			expected: "Status Response",
		},
		// Add more test cases as needed
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := a.identifyResponseType(tc.data)
			if result != tc.expected {
				t.Errorf("Expected '%s', got '%s'", tc.expected, result)
			}
		})
	}
}

// Additional tests for report generation can be added as needed
