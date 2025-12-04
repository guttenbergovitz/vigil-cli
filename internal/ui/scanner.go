package ui

import (
	"fmt"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/viewport"
	"github.com/charmbracelet/lipgloss"
)

// TickMsg is sent periodically to trigger re-renders
type TickMsg struct {
	time time.Time
}

// ScanProgress tracks scanning progress
type ScanProgress struct {
	Current      int
	Total        int
	CurrentPkg   string
	CurrentVulns int
	Completed    bool
	Error        string
}

// VulnEntry represents a vulnerability for display in the TUI
type VulnEntry struct {
	Package        string
	CVE            string   // Primary ID (CVE-* or GHSA-*)
	CVEID          string   // CVE-YYYY-*** from MITRE if available
	Severity       string
	CVSS           float64
	Description    string
	CVETitle       string   // Title from MITRE/NVD
	CVEDescription string   // Description from MITRE/NVD
	PublishedAt    string   // Published date formatted
	DependencyPath []string // Full path from root to vulnerable package
}

// Model represents the TUI state
type Model struct {
	progress     ScanProgress
	startTime    time.Time
	result       *ScanResult  // Final scan result to display
	vulns        []VulnEntry  // Dynamic list of found vulnerabilities
	spinner      spinner.Model
	progressBar  progress.Model
	vulnTable    table.Model
	viewport     viewport.Model
	width        int
	height       int
	mu           sync.Mutex
}

// ScanResult holds the completed scan results for display
type ScanResult struct {
	TotalVulns    int
	CriticalVulns int
	HighVulns     int
	MediumVulns   int
	LowVulns      int
}

// Init initializes the model
func (m *Model) Init() tea.Cmd {
	return ticker()
}

// ticker returns a command that sends a tick message every 100ms
func ticker() tea.Cmd {
	return tea.Tick(time.Millisecond*100, func(t time.Time) tea.Msg {
		return TickMsg{time: t}
	})
}

// Update handles messages
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
		// Handle table/viewport navigation if needed
		if m.vulnTable.Focused() {
			var cmd tea.Cmd
			m.vulnTable, cmd = m.vulnTable.Update(msg)
			return m, cmd
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.viewport.Width = msg.Width
		m.viewport.Height = msg.Height - 10 // Reserve space for header/progress
		m.updateTable()
		return m, nil
	case ProgressMsg:
		m.mu.Lock()
		m.progress = msg.Progress
		m.mu.Unlock()
		m.updateTable()
		// Update progress bar
		if m.progress.Total > 0 {
			percent := float64(m.progress.Current) / float64(m.progress.Total)
			if percent > 1.0 {
				percent = 1.0
			}
			m.progressBar.SetPercent(percent)
		}
		return m, ticker()
	case VulnMsg:
		m.mu.Lock()
		m.vulns = append(m.vulns, msg.Entry)
		m.mu.Unlock()
		m.updateTable()
		return m, ticker()
	case DoneMsg:
		m.mu.Lock()
		m.progress.Completed = true
		m.result = msg.Result
		m.mu.Unlock()
		return m, tea.Quit
	case ErrorMsg:
		m.mu.Lock()
		m.progress.Error = msg.Err
		m.mu.Unlock()
		return m, tea.Quit
	case TickMsg:
		// Update spinner
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		// Ticker tick - just re-render by returning model with ticker cmd
		return m, tea.Batch(cmd, ticker())
	}
	return m, nil
}

// View renders the UI
func (m *Model) View() string {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.progress.Completed {
		return m.renderCompleted()
	}

	if m.progress.Error != "" {
		return m.renderError()
	}

	return m.renderScanning()
}

func (m *Model) renderScanning() string {
	var sections []string

	// Header with spinner
	header := m.spinner.View() + " " + lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("33")).
		Render("Vigil Scanning...")
	sections = append(sections, header)

	// Progress bar (custom manual bar to ensure visibility)
	if m.progress.Total > 0 {
		percent := float64(m.progress.Current) / float64(m.progress.Total)
		if percent > 1.0 {
			percent = 1.0
		}
		width := 40
		filled := int(percent * float64(width))
		if filled > width {
			filled = width
		}
		bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
		bar = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Render(bar)
		progressView := fmt.Sprintf("%s %d%% (%d/%d)", bar, int(percent*100), m.progress.Current, m.progress.Total)
		sections = append(sections, progressView)
	}

	// Current package
	if m.progress.CurrentPkg != "" {
		pkgLine := fmt.Sprintf("Scanning: %s",
			lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Render(m.progress.CurrentPkg))
		sections = append(sections, pkgLine)
	}

	// Elapsed time
	elapsed := time.Since(m.startTime).Seconds()
	sections = append(sections, fmt.Sprintf("⏱  Elapsed: %.0fs", elapsed))

	// Vulnerabilities found counter
	if m.progress.CurrentVulns > 0 {
		vulnCount := fmt.Sprintf("🚨 Vulnerabilities found: %s",
			lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render(fmt.Sprint(m.progress.CurrentVulns)))
		sections = append(sections, vulnCount)
	}

	// Dynamic vulnerability table
	if len(m.vulns) > 0 {
		sections = append(sections, "")
		sections = append(sections, lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("33")).Render("📋 Vulnerabilities Found:"))
		sections = append(sections, m.vulnTable.View())
	}

	sections = append(sections, "")
	sections = append(sections, "Press q to quit")

	return strings.Join(sections, "\n")
}

// updateTable rebuilds the table with current vulnerabilities
func (m *Model) updateTable() {
	if len(m.vulns) == 0 {
		return
	}

	// Calculate available width (reserve some space for margins)
	availableWidth := m.width - 4
	if availableWidth < 80 {
		availableWidth = 80
	}

	// Build table rows
	var rows []table.Row
	// Show last 20 vulnerabilities
	start := len(m.vulns) - 20
	if start < 0 {
		start = 0
	}

	for i := start; i < len(m.vulns); i++ {
		v := m.vulns[i]
		
		// Format dependency path
		pathStr := ""
		if len(v.DependencyPath) > 0 {
			// Show path: root -> dep1 -> dep2 -> vulnerable
			pathParts := make([]string, len(v.DependencyPath))
			for j, p := range v.DependencyPath {
				// Truncate long package names
				if len(p) > 15 {
					pathParts[j] = p[:12] + "..."
				} else {
					pathParts[j] = p
				}
			}
			pathStr = strings.Join(pathParts, " → ")
		}

		// Format CVE ID
		cveDisplay := v.CVE
		if v.CVEID != "" {
			cveDisplay = v.CVEID
		}

		// Format CVSS
		cvssStr := "-"
		if v.CVSS > 0 {
			cvssStr = fmt.Sprintf("%.1f", v.CVSS)
		}

		// Format package name
		pkgDisplay := v.Package

		// Format severity - use readable text (plain text for table compatibility)
		severityText := strings.ToLower(strings.TrimSpace(v.Severity))
		if severityText == "" {
			severityText = "unknown"
		}
		// Capitalize first letter properly
		if len(severityText) > 0 {
			severityText = strings.ToUpper(severityText[:1]) + severityText[1:]
		}

		// Format title - use Description or CVETitle (short description), fallback to CVE ID
		titleDisplay := ""
		if v.Description != "" {
			// Use Description as title (it's usually a short sentence)
			titleDisplay = v.Description
		} else if v.CVETitle != "" {
			titleDisplay = v.CVETitle
		}
		
		// Truncate if too long
		if len(titleDisplay) > 60 {
			// Try to truncate at sentence end
			truncated := titleDisplay[:60]
			if lastDot := strings.LastIndex(truncated, "."); lastDot > 40 {
				titleDisplay = truncated[:lastDot+1]
			} else {
				titleDisplay = truncated[:57] + "..."
			}
		}
		
		// Fallback to CVE ID if no title available
		if titleDisplay == "" {
			if v.CVEID != "" {
				titleDisplay = v.CVEID
			} else {
				titleDisplay = v.CVE
			}
		}

		// Format published date
		dateStr := "-"
		if v.PublishedAt != "" {
			dateStr = v.PublishedAt
		}

		rows = append(rows, table.Row{
			severityText,
			pkgDisplay,
			cveDisplay,
			cvssStr,
			titleDisplay,
			dateStr,
			pathStr,
		})
	}

	// Calculate column widths dynamically based on available space
	severityWidth := 10
	cveWidth := 18
	cvssWidth := 6
	dateWidth := 12
	titleWidth := 35
	pkgWidth := min(25, (availableWidth-severityWidth-cveWidth-cvssWidth-dateWidth-titleWidth-40)/2)
	pathWidth := availableWidth - severityWidth - pkgWidth - cveWidth - cvssWidth - dateWidth - titleWidth - 4

	// Define columns
	columns := []table.Column{
		{Title: "Severity", Width: severityWidth},
		{Title: "Package", Width: pkgWidth},
		{Title: "CVE ID", Width: cveWidth},
		{Title: "CVSS", Width: cvssWidth},
		{Title: "Title", Width: max(titleWidth, 20)},
		{Title: "Published", Width: dateWidth},
		{Title: "Dependency Path", Width: max(pathWidth, 15)},
	}

	// Create table
	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(false),
		table.WithHeight(min(len(rows)+1, 15)),
	)
	// Do not select any row to avoid highlight bar
	t.SetCursor(-1)

	// Style table
	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(true)
	// Remove selected-row styling to avoid highlight bar
	s.Selected = lipgloss.NewStyle()
	t.SetStyles(s)

	m.vulnTable = t
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// getSeverityColor returns color for severity level
func getSeverityColor(severity string) lipgloss.Color {
	severityLower := strings.ToLower(severity)
	switch severityLower {
	case "critical":
		return lipgloss.Color("196") // bright red
	case "high":
		return lipgloss.Color("208") // orange
	case "medium":
		return lipgloss.Color("226") // yellow
	case "low":
		return lipgloss.Color("33") // blue
	case "unknown":
		return lipgloss.Color("240") // grey for unknown
	default:
		// Try to match partial strings
		if strings.Contains(severityLower, "critical") {
			return lipgloss.Color("196")
		}
		if strings.Contains(severityLower, "high") {
			return lipgloss.Color("208")
		}
		if strings.Contains(severityLower, "medium") {
			return lipgloss.Color("226")
		}
		if strings.Contains(severityLower, "low") {
			return lipgloss.Color("33")
		}
		return lipgloss.Color("240") // grey for unknown/unrecognized
	}
}

func (m *Model) renderCompleted() string {
	var sections []string

	elapsed := time.Since(m.startTime).Seconds()
	header := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("42")).
		Render(fmt.Sprintf("✓ Scan complete! (%.0fs)", elapsed))
	sections = append(sections, header)

	if m.result != nil {
		if m.result.TotalVulns == 0 {
			sections = append(sections, lipgloss.NewStyle().
				Foreground(lipgloss.Color("42")).
				Render("✓ No vulnerabilities found"))
		} else {
			sections = append(sections, "")
			sections = append(sections, "Vulnerabilities found:")
			if m.result.CriticalVulns > 0 {
				sections = append(sections, fmt.Sprintf("  🔴 Critical:  %d", m.result.CriticalVulns))
			}
			if m.result.HighVulns > 0 {
				sections = append(sections, fmt.Sprintf("  🟠 High:      %d", m.result.HighVulns))
			}
			if m.result.MediumVulns > 0 {
				sections = append(sections, fmt.Sprintf("  🟡 Medium:    %d", m.result.MediumVulns))
			}
			if m.result.LowVulns > 0 {
				sections = append(sections, fmt.Sprintf("  🔵 Low:       %d", m.result.LowVulns))
			}
			sections = append(sections, fmt.Sprintf("  Total: %d vulnerabilities", m.result.TotalVulns))
		}
	}

	// Show vulnerability table if there are any
	if len(m.vulns) > 0 {
		sections = append(sections, "")
		sections = append(sections, lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("33")).Render("📋 Vulnerabilities Found:"))
		sections = append(sections, m.vulnTable.View())
	}

	sections = append(sections, "")
	sections = append(sections, "Press q to exit")

	return strings.Join(sections, "\n")
}

func (m *Model) renderError() string {
	return lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("196")).
		Render(fmt.Sprintf("✗ Error: %s\n", m.progress.Error))
}

// Message types
type ProgressMsg struct {
	Progress ScanProgress
}

type VulnMsg struct {
	Entry VulnEntry
}

type DoneMsg struct {
	Result *ScanResult
}

type ErrorMsg struct {
	Err string
}

// NewModel creates a new model
func NewModel() *Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("33"))

	// Initialize progress bar with solid color for better visibility
	p := progress.New(
		progress.WithWidth(40),
		progress.WithSolidFill("#FF6B6B"), // Red color for filled portion
	)
	p.Width = 40
	p.ShowPercentage = false // Don't show percentage in the bar itself, we'll add it manually
	p.Full = '█'
	p.Empty = '░'

	// Initialize empty table
	columns := []table.Column{
		{Title: "Severity", Width: 10},
		{Title: "Package", Width: 25},
		{Title: "CVE ID", Width: 18},
		{Title: "CVSS", Width: 6},
		{Title: "Title", Width: 35},
		{Title: "Published", Width: 12},
		{Title: "Dependency Path", Width: 50},
	}
	t := table.New(
		table.WithColumns(columns),
		table.WithRows([]table.Row{}),
		table.WithFocused(false),
		table.WithHeight(5),
	)

	// Style table
	tableStyles := table.DefaultStyles()
	tableStyles.Header = tableStyles.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(true)
	// Disable row highlight (purple bar) to keep table clean
	tableStyles.Selected = tableStyles.Selected.
		Foreground(lipgloss.Color("")). // no override
		Background(lipgloss.Color("")). // transparent
		Bold(false)
	t.SetStyles(tableStyles)

	// Initialize viewport
	vp := viewport.New(80, 20)

	return &Model{
		startTime:   time.Now(),
		progress:    ScanProgress{},
		spinner:     s,
		progressBar: p,
		vulnTable:   t,
		viewport:    vp,
		width:       80,
		height:      24,
	}
}

