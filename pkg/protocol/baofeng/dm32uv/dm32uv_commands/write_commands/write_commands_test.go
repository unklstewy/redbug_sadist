package write_commands

import (
	"testing"
)

func TestFindMatchingCommand(t *testing.T) {
	testCases := []struct {
		name     string
		data     []byte
		expected string
		found    bool
	}{
		{"Empty", []byte{}, "", false},
		{"Too Short", []byte{0x57}, "Write Command", true},
		{"Write Channel Data", []byte{0x57, 0x02, 0x01, 0x02}, "Write Channel Data", true},
		{"Write General Settings", []byte{0x57, 0x00, 0x01, 0x02}, "Write General Settings", true},
		{"Write Contacts", []byte{0x57, 0x01, 0x01, 0x02}, "Write Contacts", true},
		{"Unknown Write Command", []byte{0x57, 0x99, 0x01, 0x02}, "Write Command (0x99)", true},
		{"Not a Write Command", []byte{0x52, 0x01, 0x02}, "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, found := FindMatchingCommand(tc.data)
			if found != tc.found {
				t.Errorf("Expected found=%v, got found=%v", tc.found, found)
			}
			if found && result != tc.expected {
				t.Errorf("Expected '%s', got '%s'", tc.expected, result)
			}
		})
	}
}

func TestGetCommandDetails(t *testing.T) {
	testCases := []struct {
		name         string
		commandName  string
		shouldFind   bool
		expectedDesc string
	}{
		{"Write Channel Data", "Write Channel Data", true, "Writes channel data to the radio"},
		{"Write General Settings", "Write General Settings", true, "Writes general radio settings"},
		{"Write Contacts", "Write Contacts", true, "Writes contact information to the radio"},
		{"Generic Write Command", "Write Command (0x99)", true, "Generic write command to radio"},
		{"Unknown Command", "Read Something", false, ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cmd, found := GetCommandDetails(tc.commandName)
			if found != tc.shouldFind {
				t.Errorf("Expected found=%v, got found=%v", tc.shouldFind, found)
			}
			if found && cmd.Description != tc.expectedDesc {
				t.Errorf("Expected description '%s', got '%s'", tc.expectedDesc, cmd.Description)
			}
		})
	}
}
