package dm32uv

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/unklstewy/redbug_sadist/pkg/protocol/analyzer"
	protocoltest "github.com/unklstewy/redbug_sadist/pkg/protocol/testing"
)

func TestIntegrationDM32UVReadAnalyzer(t *testing.T) {
	// Skip this test in regular runs unless explicitly enabled
	if os.Getenv("RUN_INTEGRATION_TESTS") != "1" {
		t.Skip("Skipping integration test. Set RUN_INTEGRATION_TESTS=1 to enable.")
	}

	// Get the analyzer
	a, err := analyzer.GetAnalyzer("baofeng", "dm32uv", "read")
	if err != nil {
		t.Fatalf("Failed to get analyzer: %v", err)
	}

	// Set up a test output directory
	testOutputDir := filepath.Join(os.TempDir(), "redbug_test_output")
	os.MkdirAll(testOutputDir, 0755)
	defer os.RemoveAll(testOutputDir) // Clean up after the test

	// Path to test input file
	testFilePath := filepath.Join(protocoltest.GetTestDataPath(), "baofeng/dm32uv/read/minimal_trace.log")

	// Run the analyzer
	err = a.Analyze(testFilePath)
	if err != nil {
		t.Fatalf("Analyzer failed: %v", err)
	}

	// Verify that output files were created
	// This depends on your implementation details - adjust as needed
	expectedOutputs := []string{
		"reports/protocol/read/baofeng/dm32uv/dm32uv_read_analysis.html",
		"reports/api/baofeng/dm32uv/dm32uv_read_api_docs.html",
	}

	for _, path := range expectedOutputs {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("Expected output file %s not found", path)
		}
	}
}
