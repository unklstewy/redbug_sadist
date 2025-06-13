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
