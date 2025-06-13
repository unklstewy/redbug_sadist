package common

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/unklstewy/redbug_sadist/pkg/protocol"
)

// Communication represents a single message in the protocol
type Communication struct {
	Timestamp    string
	Direction    string
	RawHex       string
	DecodedASCII string
	Length       int
	CommandType  string
	Notes        string
	FileDesc     string // Include if needed by either analyzer
}

// CommandResponse represents a command and its response
type CommandResponse struct {
	Command       Communication
	Responses     []Communication
	TimeDelta     time.Duration
	ResponseBytes []byte
}

// Config defines configuration options for analyzers
type Config struct {
	VerboseOutput   bool
	GenerateReports bool
}

// APICommand represents a documented API command for external use
type APICommand struct {
	Name            string
	Description     string
	Format          string
	Parameters      string
	Direction       string
	Example         string
	Notes           string
	ResponseExample string
	ResponseFormat  string
}

// FormatHexBytes formats a byte slice as a readable hex string
func FormatHexBytes(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	var builder strings.Builder
	for i, b := range data {
		if i > 0 {
			builder.WriteString(" ")
		}
		builder.WriteString(fmt.Sprintf("%02X", b))
	}
	return builder.String()
}

// ConvertToProtocolCommunication converts our internal representation to protocol.Communication
func ConvertToProtocolCommunication(comm Communication) protocol.Communication {
	return protocol.Communication{
		Timestamp:    comm.Timestamp,
		Direction:    comm.Direction,
		RawHex:       comm.RawHex,
		DecodedASCII: comm.DecodedASCII,
		Length:       comm.Length,
		CommandType:  comm.CommandType,
		Notes:        comm.Notes,
	}
}

// EnsureReportDirectory creates the directory for reports if it doesn't exist
func EnsureReportDirectory(deviceType string, operationType string) (string, error) {
	reportsDir := filepath.Join("reports", "protocol", operationType, "baofeng", deviceType)
	err := os.MkdirAll(reportsDir, 0755)
	return reportsDir, err
}
