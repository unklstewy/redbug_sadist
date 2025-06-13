package reporting

import (
	"encoding/csv"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/unklstewy/redbug_sadist/pkg/protocol"
)

// ReportGenerator handles various report formats for analysis results
type ReportGenerator struct {
	BasePath string
}

// NewReportGenerator creates a new report generator
func NewReportGenerator(basePath string) *ReportGenerator {
	if basePath == "" {
		basePath = "reports"
	}
	return &ReportGenerator{BasePath: basePath}
}

// GetReportPath returns the path for a report
func (rg *ReportGenerator) GetReportPath(vendor, model, mode, reportType, filename string) string {
	path := filepath.Join(rg.BasePath, "protocol", mode, vendor, model, reportType, filename)
	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	os.MkdirAll(dir, 0755)
	return path
}

// GenerateTextReport creates a text report from analysis results
func (rg *ReportGenerator) GenerateTextReport(result *protocol.AnalysisResult) (string, error) {
	reportPath := rg.GetReportPath(
		result.Vendor,
		result.Model,
		result.Mode,
		"text",
		fmt.Sprintf("%s_%s_analysis.txt", result.Model, result.Mode),
	)

	file, err := os.Create(reportPath)
	if err != nil {
		return "", fmt.Errorf("error creating text report: %v", err)
	}
	defer file.Close()

	// Write report header
	fmt.Fprintf(file, "%s %s %s Protocol Analysis Report\n",
		strings.Title(result.Vendor),
		strings.ToUpper(result.Model),
		strings.Title(result.Mode),
	)
	fmt.Fprintf(file, "%s\n\n", strings.Repeat("=", 50))
	fmt.Fprintf(file, "Analysis Time: %s\n\n", result.TimeStamp)

	// Write summary
	fmt.Fprintf(file, "Summary:\n")
	fmt.Fprintf(file, "  Total Commands: %d\n", result.Summary.TotalCommands)
	fmt.Fprintf(file, "  Successful Commands: %d\n", result.Summary.SuccessCount)
	fmt.Fprintf(file, "  Failed Commands: %d\n", result.Summary.ErrorCount)
	fmt.Fprintf(file, "  Command Types:\n")

	// Sort command types for consistent output
	var cmdTypes []string
	for cmdType := range result.Summary.CommandTypes {
		cmdTypes = append(cmdTypes, cmdType)
	}
	sort.Strings(cmdTypes)

	for _, cmdType := range cmdTypes {
		fmt.Fprintf(file, "    - %s: %d\n", cmdType, result.Summary.CommandTypes[cmdType])
	}

	// Data categories if present
	if len(result.Summary.DataCategories) > 0 {
		fmt.Fprintf(file, "  Data Categories:\n")
		var categories []string
		for category := range result.Summary.DataCategories {
			categories = append(categories, category)
		}
		sort.Strings(categories)

		for _, category := range categories {
			fmt.Fprintf(file, "    - %s: %d\n", category, result.Summary.DataCategories[category])
		}
	}

	// Command-response details
	fmt.Fprintf(file, "\nCommand-Response Details:\n")
	for i, cr := range result.CommandResponses {
		fmt.Fprintf(file, "\n[%d] Command: %s\n", i+1, cr.Command.CommandType)
		fmt.Fprintf(file, "  Time: %s\n", cr.Command.Timestamp)
		fmt.Fprintf(file, "  Hex: %s\n", cr.Command.RawHex)
		fmt.Fprintf(file, "  ASCII: %s\n", cr.Command.DecodedASCII)
		fmt.Fprintf(file, "  Response: %s\n", cr.Response.CommandType)
		fmt.Fprintf(file, "  Response Time: %s (delta: %s)\n", cr.Response.Timestamp, cr.TimeDelta)
		fmt.Fprintf(file, "  Response Hex: %s\n", cr.Response.RawHex)
		fmt.Fprintf(file, "  Response ASCII: %s\n", cr.Response.DecodedASCII)
		if cr.DataCategory != "" {
			fmt.Fprintf(file, "  Category: %s\n", cr.DataCategory)
		}
		if cr.Description != "" {
			fmt.Fprintf(file, "  Description: %s\n", cr.Description)
		}
	}

	return reportPath, nil
}

// GenerateCSVReport creates a CSV report from analysis results
func (rg *ReportGenerator) GenerateCSVReport(result *protocol.AnalysisResult) (string, error) {
	reportPath := rg.GetReportPath(
		result.Vendor,
		result.Model,
		result.Mode,
		"csv",
		fmt.Sprintf("%s_%s_analysis.csv", result.Model, result.Mode),
	)

	file, err := os.Create(reportPath)
	if err != nil {
		return "", fmt.Errorf("error creating CSV report: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write CSV header
	writer.Write([]string{
		"Timestamp", "Direction", "Command Type", "Length", "Raw Hex", "ASCII", "Notes", "File Descriptor",
	})

	// Write all communications
	for _, comm := range result.Communications {
		writer.Write([]string{
			comm.Timestamp,
			comm.Direction,
			comm.CommandType,
			fmt.Sprintf("%d", comm.Length),
			comm.RawHex,
			comm.DecodedASCII,
			comm.Notes,
			comm.FileDesc,
		})
	}

	return reportPath, nil
}

// GenerateHTMLReport creates an HTML report from analysis results
func (rg *ReportGenerator) GenerateHTMLReport(result *protocol.AnalysisResult) (string, error) {
	reportPath := rg.GetReportPath(
		result.Vendor,
		result.Model,
		result.Mode,
		"html",
		fmt.Sprintf("%s_%s_analysis.html", result.Model, result.Mode),
	)

	// HTML template defined here (shortened for brevity)
	htmlTemplate := `<!DOCTYPE html>
<html>
<head>
    <title>{{.Vendor}} {{.Model}} {{.Mode}} Protocol Analysis</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2 { color: #333; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .pc-to-radio { background-color: #e6f7ff; }
        .radio-to-pc { background-color: #f0fff0; }
    </style>
</head>
<body>
    <h1>{{.Vendor}} {{.Model}} {{.Mode}} Protocol Analysis</h1>
    <p>Analysis Time: {{.TimeStamp}}</p>
    
    <h2>Summary</h2>
    <ul>
        <li>Total Commands: {{.Summary.TotalCommands}}</li>
        <li>Successful Commands: {{.Summary.SuccessCount}}</li>
        <li>Failed Commands: {{.Summary.ErrorCount}}</li>
    </ul>
    
    <h2>Command Types</h2>
    <ul>
        {{range $type, $count := .Summary.CommandTypes}}
        <li>{{$type}}: {{$count}}</li>
        {{end}}
    </ul>
    
    {{if .Summary.DataCategories}}
    <h2>Data Categories</h2>
    <ul>
        {{range $cat, $count := .Summary.DataCategories}}
        <li>{{$cat}}: {{$count}}</li>
        {{end}}
    </ul>
    {{end}}
    
    <h2>Communications</h2>
    <table>
        <tr>
            <th>Time</th>
            <th>Direction</th>
            <th>Type</th>
            <th>Hex</th>
            <th>ASCII</th>
            <th>Notes</th>
        </tr>
        {{range .Communications}}
        <tr class="{{if eq .Direction "PC→Radio"}}pc-to-radio{{else}}radio-to-pc{{end}}">
            <td>{{.Timestamp}}</td>
            <td>{{.Direction}}</td>
            <td>{{.CommandType}}</td>
            <td>{{.RawHex}}</td>
            <td>{{.DecodedASCII}}</td>
            <td>{{.Notes}}</td>
        </tr>
        {{end}}
    </table>
    
    <div style="margin-top: 50px; text-align: center; color: #7f8c8d; border-top: 1px solid #bdc3c7; padding-top: 20px;">
        <p>Generated by REDBUG Protocol Analyzer | {{.TimeStamp}}</p>
    </div>
</body>
</html>`

	// Create and parse template
	tmpl, err := template.New("htmlReport").Parse(htmlTemplate)
	if err != nil {
		return "", fmt.Errorf("error parsing HTML template: %v", err)
	}

	// Create file
	file, err := os.Create(reportPath)
	if err != nil {
		return "", fmt.Errorf("error creating HTML report: %v", err)
	}
	defer file.Close()

	// Execute template
	if err := tmpl.Execute(file, result); err != nil {
		return "", fmt.Errorf("error executing HTML template: %v", err)
	}

	return reportPath, nil
}
