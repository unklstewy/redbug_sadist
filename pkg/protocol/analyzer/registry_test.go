package analyzer

import (
	"testing"
)

// MockAnalyzer implements the Analyzer interface for testing
type MockAnalyzer struct {
	vendor string
	model  string
	modes  string
}

func (a *MockAnalyzer) Analyze(filename string) error {
	return nil
}

func (a *MockAnalyzer) GetInfo() AnalyzerInfo {
	return AnalyzerInfo{
		Vendor: a.vendor,
		Model:  a.model,
		Modes:  a.modes,
	}
}

func TestRegisterAndGetAnalyzer(t *testing.T) {
	// Clear registry for testing
	registry = make(map[string]map[string]map[string]Analyzer)

	// Register test analyzers
	mockAnalyzer1 := &MockAnalyzer{vendor: "test", model: "model1", modes: "read,write"}
	mockAnalyzer2 := &MockAnalyzer{vendor: "test", model: "model2", modes: "read"}

	RegisterAnalyzer(mockAnalyzer1)
	RegisterAnalyzer(mockAnalyzer2)

	// Test retrieval
	tests := []struct {
		name        string
		vendor      string
		model       string
		mode        string
		expectError bool
	}{
		{
			name:        "Valid analyzer - read mode",
			vendor:      "test",
			model:       "model1",
			mode:        "read",
			expectError: false,
		},
		{
			name:        "Valid analyzer - write mode",
			vendor:      "test",
			model:       "model1",
			mode:        "write",
			expectError: false,
		},
		{
			name:        "Valid model, invalid mode",
			vendor:      "test",
			model:       "model2",
			mode:        "write",
			expectError: true,
		},
		{
			name:        "Invalid vendor",
			vendor:      "nonexistent",
			model:       "model1",
			mode:        "read",
			expectError: true,
		},
		{
			name:        "Valid vendor, invalid model",
			vendor:      "test",
			model:       "nonexistent",
			mode:        "read",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer, err := GetAnalyzer(tt.vendor, tt.model, tt.mode)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}

				if analyzer == nil {
					t.Errorf("Expected non-nil analyzer")
				}
			}
		})
	}
}

func TestListAvailableAnalyzers(t *testing.T) {
	// Clear registry for testing
	registry = make(map[string]map[string]map[string]Analyzer)

	// Register test analyzers
	mockAnalyzer1 := &MockAnalyzer{vendor: "test", model: "model1", modes: "read,write"}
	mockAnalyzer2 := &MockAnalyzer{vendor: "test", model: "model2", modes: "read"}
	mockAnalyzer3 := &MockAnalyzer{vendor: "other", model: "model3", modes: "write"}

	RegisterAnalyzer(mockAnalyzer1)
	RegisterAnalyzer(mockAnalyzer2)
	RegisterAnalyzer(mockAnalyzer3)

	// Test listing
	analyzers := ListAvailableAnalyzers()

	if len(analyzers) != 3 {
		t.Errorf("Expected 3 analyzers, got %d", len(analyzers))
	}

	// Check if all expected analyzers are in the list
	foundModel1 := false
	foundModel2 := false
	foundModel3 := false

	for _, a := range analyzers {
		if a.Vendor == "test" && a.Model == "model1" {
			foundModel1 = true
			if a.Modes != "read,write" && a.Modes != "write,read" {
				t.Errorf("Expected modes 'read,write' or 'write,read', got '%s'", a.Modes)
			}
		}
		if a.Vendor == "test" && a.Model == "model2" {
			foundModel2 = true
			if a.Modes != "read" {
				t.Errorf("Expected mode 'read', got '%s'", a.Modes)
			}
		}
		if a.Vendor == "other" && a.Model == "model3" {
			foundModel3 = true
			if a.Modes != "write" {
				t.Errorf("Expected mode 'write', got '%s'", a.Modes)
			}
		}
	}

	if !foundModel1 || !foundModel2 || !foundModel3 {
		t.Errorf("Not all analyzers were listed")
	}
}
