package protocol

// Standard protocol bytes
const (
	SOH = 0x01 // Start of Header
	STX = 0x02 // Start of Text
	ETX = 0x03 // End of Text
	EOT = 0x04 // End of Transmission
	ENQ = 0x05 // Enquiry
	ACK = 0x06 // Acknowledge
	NAK = 0x15 // Negative Acknowledge
	SYN = 0x16 // Synchronous Idle
	ETB = 0x17 // End of Transmission Block
	CAN = 0x18 // Cancel
	EM  = 0x19 // End of Medium
	SUB = 0x1A // Substitute
	ESC = 0x1B // Escape
)
