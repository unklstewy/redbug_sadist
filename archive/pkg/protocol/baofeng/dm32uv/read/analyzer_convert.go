// ARCHIVED FILE - Original from: /home/sannis/REDBUG/redbug_sadist/pkg/protocol/baofeng/dm32uv/read/analyzer_convert.go
// Archived on: 2025-06-13
// This file was archived during project restructuring and kept for reference.
// The functionality has been migrated to new implementations.

package read

import (
	"github.com/unklstewy/redbug_pulitzer/pkg/reporting"
	"github.com/unklstewy/redbug_sadist/pkg/protocol"
)

// convertToReportingCommandAPI converts protocol.CommandAPI to reporting.CommandAPI
func convertToReportingCommandAPI(apiCommands []protocol.CommandAPI) []reporting.CommandAPI {
	result := make([]reporting.CommandAPI, len(apiCommands))
	for i, cmd := range apiCommands {
		result[i] = reporting.CommandAPI{
			Command:        cmd.Command,
			HexValue:       cmd.HexValue,
			ASCIIValue:     cmd.ASCIIValue,
			Description:    cmd.Description,
			ResponseType:   cmd.ResponseType,
			ResponseHex:    cmd.ResponseHex,
			ResponseASCII:  cmd.ResponseASCII,
			FrequencyCount: cmd.FrequencyCount,
			TimingAverage:  cmd.TimingAverage,
			DataCategory:   cmd.DataCategory,
			SuccessRate:    cmd.SuccessRate,
		}
	}
	return result
}
