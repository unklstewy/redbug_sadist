package dm32uv

import (
	"github.com/unklstewy/redbug_sadist/pkg/protocol/analyzer"
)

// NewReadAnalyzer creates a new analyzer for read operations
func NewReadAnalyzer() analyzer.Analyzer {
	return &readAnalyzer{
		baseAnalyzer: analyzer.BaseAnalyzer{
			Vendor: "baofeng",
			Model:  "dm32uv",
			Mode:   "read",
		},
	}
}

// NewWriteAnalyzer creates a new analyzer for write operations
func NewWriteAnalyzer() analyzer.Analyzer {
	return &writeAnalyzer{
		baseAnalyzer: analyzer.BaseAnalyzer{
			Vendor: "baofeng",
			Model:  "dm32uv",
			Mode:   "write",
		},
	}
}

// readAnalyzer handles read operations
type readAnalyzer struct {
	baseAnalyzer analyzer.BaseAnalyzer
}

// writeAnalyzer handles write operations
type writeAnalyzer struct {
	baseAnalyzer analyzer.BaseAnalyzer
}

// Implement Analyzer interface methods for both analyzer types
