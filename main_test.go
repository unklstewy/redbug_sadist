package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestMainHelp(t *testing.T) {
	if os.Getenv("RUN_MAIN_TEST") == "1" {
		// Run main when env var is set
		os.Args = []string{"redbug_sadist", "--help"}
		main()
		return
	}

	// Fork process to run main
	cmd := exec.Command(os.Args[0], "-test.run=TestMainHelp")
	cmd.Env = append(os.Environ(), "RUN_MAIN_TEST=1")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	err := cmd.Run()
	if err != nil {
		t.Fatalf("Command failed: %v", err)
	}

	// Check output
	output := stdout.String()
	expectedPhrases := []string{
		"Serial Protocol Analysis Tool",
		"analyze <vendor> <model> <mode>",
		"--list-radios",
	}

	for _, phrase := range expectedPhrases {
		if !strings.Contains(output, phrase) {
			t.Errorf("Expected output to contain '%s', but it doesn't", phrase)
		}
	}
}

func TestListRadios(t *testing.T) {
	if os.Getenv("RUN_MAIN_TEST") == "1" {
		// Run main when env var is set
		os.Args = []string{"redbug_sadist", "--list-radios"}
		main()
		return
	}

	// Fork process to run main
	cmd := exec.Command(os.Args[0], "-test.run=TestListRadios")
	cmd.Env = append(os.Environ(), "RUN_MAIN_TEST=1")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	err := cmd.Run()
	if err != nil {
		t.Fatalf("Command failed: %v", err)
	}

	// Check output
	output := stdout.String()
	expectedPhrases := []string{
		"Supported Radios",
		"Baofeng DM-32UV",
		"DMR",
	}

	for _, phrase := range expectedPhrases {
		if !strings.Contains(output, phrase) {
			t.Errorf("Expected output to contain '%s', but it doesn't", phrase)
		}
	}
}
