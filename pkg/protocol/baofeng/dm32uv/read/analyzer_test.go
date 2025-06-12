package read

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/unklstewy/redbug_sadist/pkg/protocol/analyzer"
	protocoltest "github.com/unklstewy/redbug_sadist/pkg/protocol/testing"
)

func TestDM32UVReadAnalyzer_IdentifyCommandType(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "STX command",
			input:    []byte{0x02, 0x01, 0x02},
			expected: "STX (Start of Text)",
		},
		{
			name:     "ACK command",
			input:    []byte{0x06},
			expected: "ACK (Acknowledge)",
		},
		{
			name:     "NAK command",
			input:    []byte{0x15},
			expected: "NAK (Negative Acknowledge)",
		},
		{
			name:     "Read request",
			input:    []byte{0x52, 0x01, 0x02}, // 'R' followed by data
			expected: "Read Request",
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
			got := analyzer.identifyCommandType(tt.input)
			if got != tt.expected {
				t.Errorf("identifyCommandType() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDM32UVReadAnalyzer_Registration(t *testing.T) {
	// Test that the analyzer is properly registered
	a, err := analyzer.GetAnalyzer("baofeng", "dm32uv", "read")
	if err != nil {
		t.Fatalf("Failed to get analyzer: %v", err)
	}

	info := a.GetInfo()
	if info.Vendor != "baofeng" || info.Model != "dm32uv" || !strings.Contains(info.Modes, "read") {
		t.Errorf("Analyzer registration info mismatch: %+v", info)
	}
}

// Requires mock trace file in testdata
func TestDM32UVReadAnalyzer_ParseStraceFile(t *testing.T) {

	analyzer := &DM32UVReadAnalyzer{}
	traceFile := protocoltest.GetTestDataPath() + "/baofeng/dm32uv/read/sample_trace.log"

	communications := analyzer.parseStraceFile(traceFile)

	if len(communications) == 0 {
		t.Errorf("Expected to parse some communications, got none")
	}

	// Create and compare with golden file
	gotJSON, _ := json.MarshalIndent(communications, "", "  ")
	protocoltest.CompareWithGolden(
		t,
		gotJSON,
		"baofeng/dm32uv/read/sample_trace.log.golden",
		false,
	)
}
