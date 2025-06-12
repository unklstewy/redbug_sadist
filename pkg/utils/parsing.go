package utils

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode"
)

// ParseTimeDelta converts a time delta string to a time.Duration
func ParseTimeDelta(delta string) time.Duration {
	duration, err := time.ParseDuration(delta)
	if err != nil {
		return 0
	}
	return duration
}

// FormatFileSize converts bytes to human-readable format
func FormatFileSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}

// DecodeToASCII converts binary data to printable ASCII representation
func DecodeToASCII(data []byte) string {
	var result strings.Builder
	for _, b := range data {
		if b >= 32 && b <= 126 { // Printable ASCII range
			result.WriteByte(b)
		} else {
			result.WriteString(".")
		}
	}
	return result.String()
}

// UnescapeString converts escaped string data to binary
func UnescapeString(s string) []byte {
	// Handle strings like "\\x02ABC\\x03" to convert to binary
	s = strings.ReplaceAll(s, "\\\\", "\\")
	s = strings.ReplaceAll(s, "\\x", "")
	s = strings.ReplaceAll(s, " ", "")
	data, err := hex.DecodeString(s)
	if err != nil {
		return []byte{}
	}
	return data
}

// IsASCIIPrintable checks if string contains only printable ASCII
func IsASCIIPrintable(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}
