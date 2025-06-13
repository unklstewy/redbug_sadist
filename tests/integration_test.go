package tests

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/unklstewy/redbug_sadist/pkg/protocol/baofeng/dm32uv/dm32uv_commands"
	"github.com/unklstewy/redbug_sadist/pkg/protocol/baofeng/dm32uv/read"
)

func TestRealWorldLogAnalysis(t *testing.T) {
	// Set up test cases with different log files
	tests := []struct {
		name     string
		logFile  string
		expected struct {
			minCommandResponsePairs int      // Minimum number of command-response pairs we expect to find
			expectedCommands        []string // Specific commands we expect to find
		}
	}{
		{
			name:    "Read Protocol Analysis",
			logFile: "testdata/dmr_cps_read_capture.log", // Update this path
			expected: struct {
				minCommandResponsePairs int
				expectedCommands        []string
			}{
				minCommandResponsePairs: 1,                                      // Expect at least one command-response pair
				expectedCommands:        []string{"CMDPKT_0001", "CMDPKT_0002"}, // Update with actual expected commands
			},
		},
		// Add the new test case for write operations
		{
			name:    "Write Protocol Analysis",
			logFile: "testdata/dmr_cps_write_capture.log", // Path to your write log file
			expected: struct {
				minCommandResponsePairs int
				expectedCommands        []string
			}{
				minCommandResponsePairs: 1,
				// Update with actual write commands you expect to find
				expectedCommands: []string{"CMDPKT_0003", "CMDPKT_0004"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Get absolute path to the test file
			absPath, err := filepath.Abs(tt.logFile)
			require.NoError(t, err, "Failed to get absolute path")

			// Verify the log file exists
			_, err = os.Stat(absPath)
			require.NoError(t, err, "Test log file does not exist: %s", absPath)

			// Create the analyzer
			rdAnalyzer := read.NewDM32UVReadAnalyzer()

			// Parse the file and get command-response pairs
			pairs, err := rdAnalyzer.ParseLogFileForTesting(absPath)
			require.NoError(t, err, "Failed to parse log file")

			// Verify we have command-response pairs
			assert.GreaterOrEqual(t, len(pairs), tt.expected.minCommandResponsePairs,
				"Expected at least %d command-response pairs, got %d",
				tt.expected.minCommandResponsePairs, len(pairs))

			if len(pairs) == 0 {
				t.Fatalf("Parsed 0 command-response pairs")
			}

			// Print details about the found pairs for debugging
			t.Logf("Found %d command-response pairs", len(pairs))

			// Create a map to check if we found the expected commands
			foundCommands := make(map[string]bool)

			// Process each pair and check against the dm32uv_commands
			for i, pair := range pairs {
				// Try to identify the command
				cmdHex := hex.EncodeToString(pair.Command.Data)
				cmdName, found := dm32uv_commands.FindMatchingCommand(pair.Command.Data)

				if found {
					foundCommands[cmdName] = true
					t.Logf("Pair %d: Command identified as %s", i, cmdName)
				} else {
					t.Logf("Pair %d: Command not identified in dm32uv_commands: %s", i, cmdHex)
				}

				// Verify the command has a non-empty response
				assert.Greater(t, len(pair.Responses), 0,
					"Command %d should have at least one response", i)

				// Log the response for debugging
				if len(pair.Responses) > 0 {
					respHex := hex.EncodeToString(pair.Responses[0].Data)
					t.Logf("Pair %d: Response: %s", i, respHex)
				}
			}

			// Check if we found all expected commands
			for _, expectedCmd := range tt.expected.expectedCommands {
				_, found := foundCommands[expectedCmd]
				assert.True(t, found, "Expected to find command %s but it was not identified", expectedCmd)
			}
		})
	}
}
