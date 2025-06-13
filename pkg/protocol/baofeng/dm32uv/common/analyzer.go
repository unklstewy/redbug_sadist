package common

import (
	"github.com/unklstewy/redbug_sadist/pkg/protocol"
)

// Analyzer defines the interface for all DM-32UV analyzers
type Analyzer interface {
	// Analyze communications and return structured results
	Analyze(comms []Communication) *protocol.AnalysisResult

	// Pair commands with their responses
	PairCommandsWithResponses(comms []Communication) []CommandResponse

	// Identify command types
	IdentifyCommand(data []byte) string
	// Generate reports
	GenerateDetailedReport(comms []Communication, cmdResps []CommandResponse) string
	GenerateHTMLReport(result *protocol.AnalysisResult) string
}

// BaseAnalyzer implements common functionality for both read and write analyzers
type BaseAnalyzer struct {
	Config        Config
	OperationType string // "read" or "write"
	DeviceType    string // "dm32uv"
}

// Common methods that can be shared between read and write analyzers
func (a *BaseAnalyzer) EnsureReportDirectory() (string, error) {
	return EnsureReportDirectory(a.DeviceType, a.OperationType)
}
