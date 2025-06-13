package read

import (
	"testing"

	"github.com/unklstewy/redbug_sadist/pkg/protocol"
)

func TestDM32UVReadAnalyzer_GenerateAnalysisReport(t *testing.T) {
	analyzer := &DM32UVReadAnalyzer{}

	// Create sample communications
	communications := []localCommunication{
		{
			Timestamp:    "10:15:22.123456",
			Direction:    "PC→Radio",
			FileDesc:     "3",
			RawHex:       "5201020304", // Read request
			DecodedASCII: "R....",
			Length:       5,
			CommandType:  "Read Request",
		},
		{
			Timestamp:    "10:15:22.234567",
			Direction:    "Radio→PC",
			FileDesc:     "3",
			RawHex:       "06", // ACK
			DecodedASCII: ".",
			Length:       1,
			CommandType:  "ACK (Acknowledge)",
		},
	}

	// Create command-response pair
	cmdResponses := []protocol.CommandResponse{
		{
			SequenceID: 1,
			Command: protocol.Communication{
				Timestamp:    "10:15:22.123456",
				Direction:    "PC→Radio",
				RawHex:       "5201020304",
				DecodedASCII: "R....",
				Length:       5,
				CommandType:  "Read Request",
			},
			Response: protocol.Communication{
				Timestamp:    "10:15:22.234567",
				Direction:    "Radio→PC",
				RawHex:       "06",
				DecodedASCII: ".",
				Length:       1,
				CommandType:  "ACK (Acknowledge)",
			},
			TimeDelta:   "111.111ms",
			IsHandshake: false,
			Description: "Read Request - ACK",
		},
	}

	// Generate report
	report := analyzer.generateAnalysisReport(communications, cmdResponses)

	// Verify report contents
	if report.TotalCommunications != 2 {
		t.Errorf("Expected 2 communications in report, got %d", report.TotalCommunications)
	}

	if report.CommandCount != 1 {
		t.Errorf("Expected 1 command in report, got %d", report.CommandCount)
	}

	if report.ResponseCount != 1 {
		t.Errorf("Expected 1 response in report, got %d", report.ResponseCount)
	}

	if len(report.CommandResponses) != 1 {
		t.Errorf("Expected 1 command-response pair in report, got %d", len(report.CommandResponses))
	}

	if report.Vendor != "baofeng" || report.Model != "dm32uv" {
		t.Errorf("Expected vendor 'baofeng' and model 'dm32uv', got '%s' and '%s'",
			report.Vendor, report.Model)
	}
}
