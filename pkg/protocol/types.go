package protocol

// Communication represents a single message between PC and radio
type Communication struct {
	Timestamp    string
	Direction    string
	RawHex       string
	DecodedASCII string
	Length       int
	CommandType  string
	Notes        string
	FileDesc     string // Added to support file descriptor tracking
}

// CommandResponse represents a command-response pair
type CommandResponse struct {
	SequenceID   int
	Command      Communication
	Response     Communication
	TimeDelta    string
	IsHandshake  bool
	Description  string
	DataCategory string // Added to categorize command types
}

// Summary contains analysis statistics
type Summary struct {
	TotalCommands  int
	SuccessCount   int
	ErrorCount     int
	CommandTypes   map[string]int
	DataCategories map[string]int // Added to summarize data categories
}

// AnalysisResult represents the complete output of an analysis
type AnalysisResult struct {
	AnalyzerName     string
	TimeStamp        string
	Vendor           string
	Model            string
	Mode             string // "read" or "write"
	Communications   []Communication
	CommandResponses []CommandResponse
	Summary          Summary
}
