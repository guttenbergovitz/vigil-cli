package ui

import (
	"fmt"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/spinner"
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
	Package      string
	CVE          string
	Severity     string
	CVSS         float64
	Description  string
	DependencyOf string // Direct parent in dependency tree
}

// Model represents the TUI state
type Model struct {
	progress     ScanProgress
	startTime    time.Time
	result       *ScanResult  // Final scan result to display
	vulns        []VulnEntry  // Dynamic list of found vulnerabilities
	spinner      spinner.Model
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
func (m Model) Init() tea.Cmd {
	return ticker()
}

// ticker returns a command that sends a tick message every 100ms
func ticker() tea.Cmd {
	return tea.Tick(time.Millisecond*100, func(t time.Time) tea.Msg {
		return TickMsg{time: t}
	})
}

// Update handles messages
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	case ProgressMsg:
		m.mu.Lock()
		m.progress = msg.Progress
		m.mu.Unlock()
		// Keep the ticker running
		return m, ticker()
	case VulnMsg:
		m.mu.Lock()
		m.vulns = append(m.vulns, msg.Entry)
		m.mu.Unlock()
		// Keep the ticker running
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
func (m Model) View() string {
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

func (m Model) renderScanning() string {
	var s string

	// Header with spinner
	s += m.spinner.View() + " " + lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("33")).
		Render("Vigil Scanning...\n")

	// Progress bar with animated characters
	width := 40
	filled := 0
	if m.progress.Total > 0 {
		filled = (m.progress.Current * width) / m.progress.Total
	}

	bar := "["
	for i := 0; i < width; i++ {
		if i < filled {
			bar += "▓"
		} else if i == filled {
			bar += "▒"
		} else {
			bar += "░"
		}
	}
	bar += "]"

	percentage := 0
	if m.progress.Total > 0 {
		percentage = (m.progress.Current * 100) / m.progress.Total
	}

	s += bar + fmt.Sprintf(" %d%% (%d/%d)\n", percentage, m.progress.Current, m.progress.Total)

	// Current package
	if m.progress.CurrentPkg != "" {
		s += fmt.Sprintf("Scanning: %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Render(m.progress.CurrentPkg))
	}

	// Elapsed time
	elapsed := time.Since(m.startTime).Seconds()
	s += fmt.Sprintf("⏱  Elapsed: %.0fs\n", elapsed)

	// Vulnerabilities found counter
	if m.progress.CurrentVulns > 0 {
		s += fmt.Sprintf("🚨 Vulnerabilities found: %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render(fmt.Sprint(m.progress.CurrentVulns)))
	}

	// Dynamic vulnerability table
	if len(m.vulns) > 0 {
		s += lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("33")).Render("📋 Vulnerabilities Found:\n")
		s += renderVulnTable(m.vulns)
	}

	s += "\nPress q to quit"

	return s
}

// renderVulnTable renders a formatted table of vulnerabilities
func renderVulnTable(vulns []VulnEntry) string {
	var s string

	// Header with columns
	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("255")).
		Background(lipgloss.Color("8")).
		Padding(0, 1)

	s += headerStyle.Render(fmt.Sprintf("%-12s %-20s %-15s %-8s %s\n",
		"Severity",
		"Package",
		"CVE ID",
		"CVSS",
		"Parent",
	))

	s += "─────────────────────────────────────────────────────────────────────────────────────────\n"

	// Show last 10 vulnerabilities
	start := len(vulns) - 10
	if start < 0 {
		start = 0
	}

	for i := start; i < len(vulns); i++ {
		v := vulns[i]
		severityColor := getSeverityColor(v.Severity)
		severityStyled := lipgloss.NewStyle().Foreground(severityColor).Bold(true).Render(padRight(v.Severity, 12))

		cvssStr := ""
		if v.CVSS > 0 {
			cvssStr = fmt.Sprintf("%.1f", v.CVSS)
		}

		parentDisplay := v.DependencyOf
		if len(parentDisplay) > 15 {
			parentDisplay = parentDisplay[:12] + "…"
		}

		pkgDisplay := v.Package
		if len(pkgDisplay) > 20 {
			pkgDisplay = pkgDisplay[:17] + "…"
		}

		cveDisplay := v.CVE
		if len(cveDisplay) > 15 {
			cveDisplay = cveDisplay[:12] + "…"
		}

		s += fmt.Sprintf("%s %-20s %-15s %-8s %s\n",
			severityStyled,
			padRight(pkgDisplay, 20),
			padRight(cveDisplay, 15),
			padRight(cvssStr, 8),
			parentDisplay,
		)
	}

	s += "─────────────────────────────────────────────────────────────────────────────────────────\n"

	return s
}

// padRight pads a string to the right with spaces
func padRight(s string, length int) string {
	if len(s) >= length {
		return s[:length]
	}
	return s + fmt.Sprintf("%*s", length-len(s), "")
}

// getSeverityColor returns color for severity level
func getSeverityColor(severity string) lipgloss.Color {
	switch severity {
	case "critical":
		return lipgloss.Color("196") // red
	case "high":
		return lipgloss.Color("208") // orange
	case "medium":
		return lipgloss.Color("226") // yellow
	default:
		return lipgloss.Color("33") // blue
	}
}

func (m Model) renderCompleted() string {
	var s string

	elapsed := time.Since(m.startTime).Seconds()
	s += lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("42")).
		Render(fmt.Sprintf("✓ Scan complete! (%.0fs)\n", elapsed))

	if m.result != nil {
		if m.result.TotalVulns == 0 {
			s += lipgloss.NewStyle().
				Foreground(lipgloss.Color("42")).
				Render("✓ No vulnerabilities found\n")
		} else {
			s += "Vulnerabilities found:\n"
			if m.result.CriticalVulns > 0 {
				s += fmt.Sprintf("  🔴 Critical:  %d\n", m.result.CriticalVulns)
			}
			if m.result.HighVulns > 0 {
				s += fmt.Sprintf("  🟠 High:      %d\n", m.result.HighVulns)
			}
			if m.result.MediumVulns > 0 {
				s += fmt.Sprintf("  🟡 Medium:    %d\n", m.result.MediumVulns)
			}
			if m.result.LowVulns > 0 {
				s += fmt.Sprintf("  🔵 Low:       %d\n", m.result.LowVulns)
			}
			s += fmt.Sprintf("  Total: %d vulnerabilities\n", m.result.TotalVulns)
		}
	}

	s += "Press q to exit"
	return s
}

func (m Model) renderError() string {
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
func NewModel() Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("33"))

	return Model{
		startTime: time.Now(),
		progress:  ScanProgress{},
		spinner:   s,
	}
}
