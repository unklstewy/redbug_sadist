// ARCHIVED FILE - Original from: /home/sannis/REDBUG/redbug_sadist/pkg/protocol/baofeng/dm32uv/read/types.go
// Archived on: 2025-06-13
// This file was archived during project restructuring and kept for reference.
// The functionality has been migrated to new implementations.

package read

import "time"

// Any other non-duplicate types can remain here
// Public types for command and response
type Command struct {
	Data      []byte
	Timestamp time.Time
}

type Response struct {
	Data      []byte
	Timestamp time.Time
}

type CommandResponsePair struct {
	Command   Command
	Responses []Response
}
