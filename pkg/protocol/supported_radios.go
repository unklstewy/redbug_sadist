package protocol

// SupportedRadio defines metadata for a supported radio model
type SupportedRadio struct {
	Vendor       string
	Model        string
	DisplayName  string
	Type         string // DMR, Analog, D-STAR, etc.
	ReadSupport  bool
	WriteSupport bool
	Description  string
}

// GetSupportedRadios returns a list of all radios with analysis support
func GetSupportedRadios() []SupportedRadio {
	return []SupportedRadio{
		{
			Vendor:       "baofeng",
			Model:        "dm32uv",
			DisplayName:  "Baofeng DM-32UV",
			Type:         "DMR",
			ReadSupport:  true,
			WriteSupport: true,
			Description:  "Dual-band DMR/Analog radio with Tier I & II support",
		},
		{
			Vendor:       "tyt",
			Model:        "md380",
			DisplayName:  "TYT MD-380",
			Type:         "DMR",
			ReadSupport:  false, // Not implemented yet
			WriteSupport: false, // Not implemented yet
			Description:  "Popular DMR radio with good hackability",
		},
		// Add more radios as they are supported
	}
}
