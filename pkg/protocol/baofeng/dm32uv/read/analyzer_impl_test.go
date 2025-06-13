// filepath: /home/sannis/REDBUG/redbug_sadist/pkg/protocol/baofeng/dm32uv/read/analyzer_impl_test.go
package read

import (
	"strings"
	"testing"

	"github.com/unklstewy/redbug_sadist/pkg/protocol"
)

func TestDM32UVReadAnalyzer_IdentifyResponseType(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "ACK response",
			input:    []byte{protocol.ACK},
			expected: "ACK (Acknowledge)",
		},
		{
			name:     "NAK response",
			input:    []byte{protocol.NAK},
			expected: "NAK (Negative Acknowledge)",
		},
		{
			name:     "STX response",
			input:    []byte{protocol.STX},
			expected: "Data Packet",
		},
		{
			name:     "Unknown response",
			input:    []byte{0xFF},
			expected: "Unknown Response",
		},
		{
			name:     "Empty input",
			input:    []byte{},
			expected: "Empty",
		},
	}

	analyzer := &DM32UVReadAnalyzer{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.identifyResponseType(tt.input)
			if got != tt.expected {
				t.Errorf("identifyResponseType() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDM32UVReadAnalyzer_AnalyzeCommandResponses(t *testing.T) {
	analyzer := &DM32UVReadAnalyzer{}

	// Create test communications: 2 command-response pairs
	communications := []localCommunication{
		{
			Timestamp:    "10:00:01.000",
			Direction:    "PC→Radio",
			RawHex:       "02",
			DecodedASCII: ".",
			Length:       1,
			CommandType:  "STX (Start of Text)",
			Notes:        "",
		},
		{
			Timestamp:    "10:00:01.100",
			Direction:    "Radio→PC",
			RawHex:       "06",
			DecodedASCII: ".",
			Length:       1,
			CommandType:  "ACK (Acknowledge)",
			Notes:        "",
		},
		{
			Timestamp:    "10:00:02.000",
			Direction:    "PC→Radio",
			RawHex:       "52010203", // 'R' followed by data
			DecodedASCII: "R...",
			Length:       4,
			CommandType:  "Read Request",
			Notes:        "",
		},
		{
			Timestamp:    "10:00:02.100",
			Direction:    "Radio→PC",
			RawHex:       "06",
			DecodedASCII: ".",
			Length:       1,
			CommandType:  "ACK (Acknowledge)",
			Notes:        "",
		},
	}

	cmdResponses := analyzer.analyzeCommandResponses(communications)

	if len(cmdResponses) != 2 {
		t.Errorf("Expected 2 command-response pairs, got %d", len(cmdResponses))
	}

	// Check first pair
	if cmdResponses[0].Command.CommandType != "STX (Start of Text)" {
		t.Errorf("Expected first command to be STX, got %s", cmdResponses[0].Command.CommandType)
	}

	if cmdResponses[0].Response.CommandType != "ACK (Acknowledge)" {
		t.Errorf("Expected first response to be ACK, got %s", cmdResponses[0].Response.CommandType)
	}

	// Check second pair
	if cmdResponses[1].Command.CommandType != "Read Request" {
		t.Errorf("Expected second command to be Read Request, got %s", cmdResponses[1].Command.CommandType)
	}

	if !cmdResponses[1].IsHandshake {
		t.Errorf("Expected second pair to be identified as handshake")
	}
}

func TestDM32UVReadAnalyzer_IsHandshakeSequence(t *testing.T) {
	analyzer := &DM32UVReadAnalyzer{}

	tests := []struct {
		name     string
		command  protocol.Communication
		response protocol.Communication
		expected bool
	}{
		{
			name: "Read Request + ACK (handshake)",
			command: protocol.Communication{
				CommandType: "Read Request",
			},
			response: protocol.Communication{
				CommandType: "ACK (Acknowledge)",
			},
			expected: true,
		},
		{
			name: "STX + ACK (not handshake)",
			command: protocol.Communication{
				CommandType: "STX (Start of Text)",
			},
			response: protocol.Communication{
				CommandType: "ACK (Acknowledge)",
			},
			expected: false,
		},
		{
			name: "Read Request + NAK (not handshake)",
			command: protocol.Communication{
				CommandType: "Read Request",
			},
			response: protocol.Communication{
				CommandType: "NAK (Negative Acknowledge)",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.isHandshakeSequence(tt.command, tt.response)
			if got != tt.expected {
				t.Errorf("isHandshakeSequence() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDM32UVReadAnalyzer_GenerateAnalysisReportImpl(t *testing.T) {
	analyzer := &DM32UVReadAnalyzer{}

	// Create test communications
	communications := []localCommunication{
		{
			Timestamp:   "10:00:01.000",
			Direction:   "PC→Radio",
			RawHex:      "02",
			Length:      1,
			CommandType: "STX (Start of Text)",
		},
		{
			Timestamp:   "10:00:01.100",
			Direction:   "Radio→PC",
			RawHex:      "06",
			Length:      1,
			CommandType: "ACK (Acknowledge)",
		},
		{
			Timestamp:   "10:00:02.000",
			Direction:   "PC→Radio",
			RawHex:      "1500", // NAK-like command
			Length:      2,
			CommandType: "NAK Command",
		},
		{
			Timestamp:   "10:00:02.100",
			Direction:   "Radio→PC",
			RawHex:      "15",
			Length:      1,
			CommandType: "NAK (Negative Acknowledge)",
		},
	}

	// Create command-response pairs
	cmdResp := []protocol.CommandResponse{
		{
			SequenceID: 1,
			Command: protocol.Communication{
				Direction:   "PC→Radio",
				CommandType: "STX (Start of Text)",
			},
			Response: protocol.Communication{
				Direction:   "Radio→PC",
				CommandType: "ACK (Acknowledge)",
			},
			IsHandshake: true,
			TimeDelta:   "100ms",
		},
		{
			SequenceID: 2,
			Command: protocol.Communication{
				Direction:   "PC→Radio",
				CommandType: "NAK Command",
			},
			Response: protocol.Communication{
				Direction:   "Radio→PC",
				CommandType: "NAK (Negative Acknowledge)",
			},
			IsHandshake: false,
			TimeDelta:   "100ms",
		},
	}

	report := analyzer.generateAnalysisReport(communications, cmdResp)

	// Test report values
	if report.TotalCommunications != 4 {
		t.Errorf("Expected TotalCommunications to be 4, got %d", report.TotalCommunications)
	}

	if report.CommandCount != 2 {
		t.Errorf("Expected CommandCount to be 2, got %d", report.CommandCount)
	}

	if report.ResponseCount != 2 {
		t.Errorf("Expected ResponseCount to be 2, got %d", report.ResponseCount)
	}

	if report.HandshakeCount != 1 {
		t.Errorf("Expected HandshakeCount to be 1, got %d", report.HandshakeCount)
	}

	if report.ErrorCount != 1 {
		t.Errorf("Expected ErrorCount to be 1, got %d", report.ErrorCount)
	}

	if report.TimestampStart != "10:00:01.000" {
		t.Errorf("Expected TimestampStart to be 10:00:01.000, got %s", report.TimestampStart)
	}

	if report.TimestampEnd != "10:00:02.100" {
		t.Errorf("Expected TimestampEnd to be 10:00:02.100, got %s", report.TimestampEnd)
	}
}

func TestDM32UVReadAnalyzer_ConvertToProtocolAPICommands(t *testing.T) {
	analyzer := &DM32UVReadAnalyzer{}

	// Create test command-response pairs
	cmdResponses := []protocol.CommandResponse{
		{
			SequenceID: 1,
			Command: protocol.Communication{
				RawHex:       "52010203", // 'R' followed by data
				DecodedASCII: "R...",
				CommandType:  "Read Request",
			},
			Response: protocol.Communication{
				RawHex:       "06",
				DecodedASCII: ".",
				CommandType:  "ACK (Acknowledge)",
			},
			IsHandshake: true, // This should be skipped
			TimeDelta:   "100ms",
		},
		{
			SequenceID: 2,
			Command: protocol.Communication{
				RawHex:       "57010203", // 'W' followed by data
				DecodedASCII: "W...",
				CommandType:  "Write Request",
			},
			Response: protocol.Communication{
				RawHex:       "06",
				DecodedASCII: ".",
				CommandType:  "ACK (Acknowledge)",
			},
			IsHandshake: false,
			TimeDelta:   "150ms",
		},
		{
			SequenceID: 3,
			Command: protocol.Communication{
				RawHex:       "57010203", // Same as sequence 2
				DecodedASCII: "W...",
				CommandType:  "Write Request",
			},
			Response: protocol.Communication{
				RawHex:       "06",
				DecodedASCII: ".",
				CommandType:  "ACK (Acknowledge)",
			},
			IsHandshake: false,
			TimeDelta:   "120ms",
		},
	}

	apiCommands := analyzer.convertToProtocolAPICommands(cmdResponses)

	// Only non-handshake commands should be included, and duplicates should be counted
	if len(apiCommands) != 1 {
		t.Errorf("Expected 1 API command (after combining), got %d", len(apiCommands))
	}

	if !strings.HasPrefix(apiCommands[0].Command, "CMD_5701") {
		t.Errorf("Expected command name to start with CMD_5701, got %s", apiCommands[0].Command)
	}

	if apiCommands[0].FrequencyCount != 2 {
		t.Errorf("Expected frequency count to be 2, got %d", apiCommands[0].FrequencyCount)
	}
}

func TestConvertToReportingCommandAPI(t *testing.T) {
	// Create test protocol API commands
	protocolCommands := []protocol.CommandAPI{
		{
			Command:        "CMD_TEST",
			HexValue:       "0102",
			ASCIIValue:     "..",
			Description:    "Test Command",
			ResponseType:   "ACK",
			ResponseHex:    "06",
			ResponseASCII:  ".",
			FrequencyCount: 3,
			TimingAverage:  "100ms",
			DataCategory:   "read",
			SuccessRate:    "100%",
		},
	}

	// Convert to reporting API commands
	reportingCommands := convertToReportingCommandAPI(protocolCommands)

	// Check that conversion was successful
	if len(reportingCommands) != 1 {
		t.Errorf("Expected 1 reporting command, got %d", len(reportingCommands))
	}

	if reportingCommands[0].Command != "CMD_TEST" {
		t.Errorf("Expected command name CMD_TEST, got %s", reportingCommands[0].Command)
	}

	if reportingCommands[0].HexValue != "0102" {
		t.Errorf("Expected hex value 0102, got %s", reportingCommands[0].HexValue)
	}

	if reportingCommands[0].FrequencyCount != 3 {
		t.Errorf("Expected frequency count 3, got %d", reportingCommands[0].FrequencyCount)
	}
}

func TestMin(t *testing.T) {
	tests := []struct {
		name     string
		a        int
		b        int
		expected int
	}{
		{
			name:     "a less than b",
			a:        5,
			b:        10,
			expected: 5,
		},
		{
			name:     "b less than a",
			a:        10,
			b:        5,
			expected: 5,
		},
		{
			name:     "equal values",
			a:        7,
			b:        7,
			expected: 7,
		},
		{
			name:     "zero values",
			a:        0,
			b:        0,
			expected: 0,
		},
		{
			name:     "negative values",
			a:        -5,
			b:        -3,
			expected: -5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := min(tt.a, tt.b)
			if got != tt.expected {
				t.Errorf("min(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}
