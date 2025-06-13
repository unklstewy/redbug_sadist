package analyzer

import "github.com/unklstewy/redbug_sadist/pkg/protocol"

// Analyzer defines the interface that all protocol analyzers must implement
type Analyzer interface {
	// Analyze performs analysis on the given file and returns structured results
	Analyze(filename string) (*protocol.AnalysisResult, error)

	// GetInfo returns metadata about this analyzer
	GetInfo() AnalyzerInfo
}

// AnalysisResult contains the complete analysis output
type AnalysisResult struct {
	AnalyzerName     string
	TimeStamp        string
	Communications   []protocol.Communication
	CommandResponses []protocol.CommandResponse
	Summary          protocol.Summary
	// Add any other fields needed for analysis output
}

// AnalyzerInfo contains metadata about a registered analyzer
type AnalyzerInfo struct {
	Vendor string
	Model  string
	Modes  string // Comma-separated list: "read,write"
}
