package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/unklstewy/redbug_sadist/pkg/protocol/baofeng/dm32uv/read"
)

// TestRealWorldLogAnalysis tests the analyzer with real-world log data
func TestRealWorldLogAnalysis(t *testing.T) {
	// Find test data relative to this module
	testDataDir := filepath.Join("..", "testdata", "logs")

	// Create test data directory if it doesn't exist
	if _, err := os.Stat(testDataDir); os.IsNotExist(err) {
		err := os.MkdirAll(testDataDir, 0755)
		if err != nil {
			t.Fatalf("Failed to create test data directory: %v", err)
		}
	}

	readLogPath := filepath.Join(testDataDir, "dmr_cps_read_capture.log")
	//writeLogPath := filepath.Join(testDataDir, "dmr_cps_write_capture.log")

	// Check if test data files exist
	if _, err := os.Stat(readLogPath); os.IsNotExist(err) {
		t.Skipf("Test data file not found: %s - skipping test", readLogPath)
		return
	}

	// Test read protocol analysis
	t.Run("Read Protocol Analysis", func(t *testing.T) {
		// Load test data
		data, err := os.ReadFile(readLogPath)
		if err != nil {
			t.Fatalf("Failed to read test data: %v", err)
		}

		// Create analyzer
		analyzer := read.NewDM32UVReadAnalyzer()

		// Parse the log file
		commandResponsePairs, err := analyzer.ParseLogFile(data)
		if err != nil {
			t.Fatalf("Failed to parse log file: %v", err)
		}

		// Verify we got some data
		if len(commandResponsePairs) == 0 {
			t.Error("Expected non-empty command-response pairs")
		} else {
			t.Logf("Found %d command-response pairs", len(commandResponsePairs))
		}
	})

	// Add similar test for write protocol
}

// findProjectRoot locates the root directory of the project
func findProjectRoot(t *testing.T) string {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	for {
		// Check if we've found the project root
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			// Double-check this is the main project, not a submodule
			content, err := os.ReadFile(filepath.Join(dir, "go.mod"))
			if err == nil && contains(string(content), "github.com/unklstewy/redbug") {
				return dir
			}
		}

		// Move up one directory
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached filesystem root without finding project root
			t.Fatalf("Could not find project root")
		}
		dir = parent
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[0:len(substr)] == substr
}

// Add a simple main function to make this a valid Go package
func main() {}
