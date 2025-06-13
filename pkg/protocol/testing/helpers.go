package testing

import (
	"encoding/json"
	"io/ioutil"
	"path/filepath"
	"runtime"
	"testing"
)

// GetTestDataPath returns the absolute path to the testdata directory
func GetTestDataPath() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "testdata")
}

// LoadTestFile loads a test file from the testdata directory
func LoadTestFile(t *testing.T, relativePath string) []byte {
	t.Helper()

	path := filepath.Join(GetTestDataPath(), relativePath)
	data, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to load test file %s: %v", path, err)
	}
	return data
}

// LoadJSONFile loads and unmarshals a JSON test file
func LoadJSONFile(t *testing.T, relativePath string, v interface{}) {
	t.Helper()

	data := LoadTestFile(t, relativePath)
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("Failed to unmarshal JSON file %s: %v", relativePath, err)
	}
}

// CompareWithGolden compares the output with a golden file and updates it if requested
func CompareWithGolden(t *testing.T, got []byte, goldenPath string, update bool) {
	t.Helper()

	path := filepath.Join(GetTestDataPath(), goldenPath)

	if update {
		if err := ioutil.WriteFile(path, got, 0644); err != nil {
			t.Fatalf("Failed to update golden file %s: %v", path, err)
		}
		return
	}

	expected := LoadTestFile(t, goldenPath)
	if string(got) != string(expected) {
		t.Errorf("Output doesn't match golden file %s", goldenPath)
		// You can add more detailed diff here
	}
}
