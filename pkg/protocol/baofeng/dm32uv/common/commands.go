package common

import (
	"fmt"

	"github.com/unklstewy/redbug_sadist/pkg/protocol"
)

// IdentifyBaseCommandType identifies the basic command type based on first byte
func IdentifyBaseCommandType(data []byte) string {
	if len(data) == 0 {
		return "Empty"
	}

	firstByte := data[0]

	// Common control characters
	switch firstByte {
	case protocol.STX:
		return "STX (Start of Text)"
	case protocol.ACK:
		return "ACK (Acknowledge)"
	case protocol.NAK:
		return "NAK (Negative Acknowledge)"
	case protocol.SOH:
		return "SOH (Start of Header)"
	case protocol.ETX:
		return "ETX (End of Text)"
	case protocol.EOT:
		return "EOT (End of Transmission)"
	case 0x52: // 'R'
		return "Read Request"
	case 0x57: // 'W'
		return "Write Command"
	case 0x50: // 'P'
		return "Program Command"
	case 0x7E:
		return "Packet Frame (~)"
	default:
		if firstByte >= 0x20 && firstByte <= 0x7E {
			return fmt.Sprintf("ASCII Command (%c)", firstByte)
		}
		return fmt.Sprintf("Unknown (0x%02X)", firstByte)
	}
}
