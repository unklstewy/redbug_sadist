package read

import (
	"testing"
)

func TestDM32UVReadAnalyzer_AnalyzeCommandResponses(t *testing.T) {
	analyzer := &DM32UVReadAnalyzer{}

	// Create sample communications
	communications := []localCommunication{
		{
			Timestamp:    "10:15:22.123456",
			Direction:    "PC→Radio",
			FileDesc:     "3",
			RawHex:       "5201020304",
			DecodedASCII: "R....",
			Length:       5,
			CommandType:  "Read Request",
		},
		{
			Timestamp:    "10:15:22.234567",
			Direction:    "Radio→PC",
			FileDesc:     "3",
			RawHex:       "06",
			DecodedASCII: ".",
			Length:       1,
			CommandType:  "ACK (Acknowledge)",
		},
		{
			Timestamp:    "10:15:22.345678",
			Direction:    "PC→Radio",
			FileDesc:     "3",
			RawHex:       "0253030405",
			DecodedASCII: ".S...",
			Length:       5,
			CommandType:  "STX (Start of Text)",
		},
		{
			Timestamp:    "10:15:22.456789",
			Direction:    "Radio→PC",
			FileDesc:     "3",
			RawHex:       "0244415441",
			DecodedASCII: ".DATA.",
			Length:       6,
			CommandType:  "STX (Start of Text)",
		},
	}

	// Analyze command-response pairs
	cmdResponses := analyzer.analyzeCommandResponses(communications)

	// Verify results
	if len(cmdResponses) != 2 {
		t.Errorf("Expected 2 command-response pairs, got %d", len(cmdResponses))
	}

	// Check first pair
	if cmdResponses[0].Command.RawHex != "5201020304" {
		t.Errorf("First command wrong: %s", cmdResponses[0].Command.RawHex)
	}

	if cmdResponses[0].Response.RawHex != "06" {
		t.Errorf("First response wrong: %s", cmdResponses[0].Response.RawHex)
	}

	// Check timing calculation
	if cmdResponses[0].TimeDelta == "" {
		t.Errorf("Expected time delta to be calculated")
	}
}
