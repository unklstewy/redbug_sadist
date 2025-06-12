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
}

// CommandResponse represents a command-response pair
type CommandResponse struct {
	SequenceID  int
	Command     Communication
	Response    Communication
	TimeDelta   string
	IsHandshake bool
	Description string
}

// CommandAPI represents a documented command for the API
type CommandAPI struct {
	Command        string
	HexValue       string
	ASCIIValue     string
	Description    string
	ResponseType   string
	ResponseHex    string
	ResponseASCII  string
	FrequencyCount int
	TimingAverage  string
	DataCategory   string // Add this field
	SuccessRate    string // Add this field
}

// AnalysisReport represents a complete protocol analysis
type AnalysisReport struct {
	// Basic information
	Vendor       string
	Model        string
	AnalysisType string

	// Communication statistics
	TotalCommunications int
	CommandCount        int
	ResponseCount       int
	HandshakeCount      int
	DataTransferCount   int
	ErrorCount          int

	// Timing information
	TimestampStart      string
	TimestampEnd        string
	AverageResponseTime string

	// Command response data
	CommandResponses []CommandResponse
}
