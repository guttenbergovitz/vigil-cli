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

// ViewState represents the active screen/mode of the TUI.
type ViewState int

const (
	StateScanning ViewState = iota
	StateExplorer
	StateDetail
)

// GroupMode represents how vulnerabilities are grouped in the explorer.
type GroupMode int

const (
	GroupFlat GroupMode = iota
	GroupPackage
	GroupSeverity
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
	Version        string
	CVE            string   // Primary ID (CVE-* or GHSA-*)
	CVEID          string   // CVE-YYYY-*** from MITRE if available
	Severity       string
	CVSS           float64
	CVSSVector     string
	Description    string
	CVETitle       string   // Title from MITRE/NVD
	CVEDescription string   // Description from MITRE/NVD
	PublishedAt    string   // Published date formatted
	DependencyPath []string // Full path from root to vulnerable package
}

// Model represents the interactive TUI state
type Model struct {
	state          ViewState
	progress       ScanProgress
	startTime      time.Time
	result         *ScanResult  // Final scan result to display
	vulns          []VulnEntry  // Full list of found vulnerabilities
	filteredVulns  []VulnEntry  // Filtered list based on search/severity
	spinner        spinner.Model
	progressBar    progress.Model
	vulnTable      table.Model
	viewport       viewport.Model
	styles         Styles
	width          int
	height         int
	selectedIdx    int
	filterSeverity string     // "", "critical", "high", "medium", "low"
	searchQuery    string
	isSearching    bool
	groupMode      GroupMode
	mu             sync.Mutex
}

// ScanResult holds the completed scan results for display
type ScanResult struct {
	TotalVulns    int
	CriticalVulns int
	HighVulns     int
	MediumVulns   int
	LowVulns      int
	SecretCount   int
}

// ProgressMsg updates scan progress
type ProgressMsg struct {
	Progress ScanProgress
}

// VulnMsg adds a vulnerability entry
type VulnMsg struct {
	Entry VulnEntry
}

// DoneMsg indicates scan completion
type DoneMsg struct {
	Result *ScanResult
}

// ErrorMsg indicates scan error
type ErrorMsg struct {
	Err string
}

// NewModel initializes the TUI model
func NewModel() *Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("33"))

	p := progress.New(progress.WithDefaultGradient())

	// Initialize empty table
	columns := []table.Column{
		{Title: "SEVERITY", Width: 10},
		{Title: "PACKAGE", Width: 20},
		{Title: "CVE / ID", Width: 18},
		{Title: "TITLE / DESCRIPTION", Width: 45},
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(true),
		table.WithHeight(12),
	)

	tStyle := table.DefaultStyles()
	tStyle.Header = tStyle.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(true)
	tStyle.Selected = tStyle.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(true)
	t.SetStyles(tStyle)

	vp := viewport.New(80, 20)

	return &Model{
		state:       StateScanning,
		startTime:   time.Now(),
		spinner:     s,
		progressBar: p,
		vulnTable:   t,
		viewport:    vp,
		styles:      DefaultStyles(),
		width:       100,
		height:      30,
	}
}

// SetProgress updates scan progress state
func (m *Model) SetProgress(current, total int, currentPkg string, vulns int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.progress.Current = current
	m.progress.Total = total
	m.progress.CurrentPkg = currentPkg
	m.progress.CurrentVulns = vulns
}

// AddVulnerability adds a detected vulnerability entry
func (m *Model) AddVulnerability(entry VulnEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.vulns = append(m.vulns, entry)
}

// SetDone marks scanning as finished and enables interactive exploration mode
func (m *Model) SetDone(result *ScanResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.progress.Completed = true
	m.result = result
	m.state = StateExplorer
	m.applyFiltersLocked()
}

// SetError marks scanning as failed
func (m *Model) SetError(err string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.progress.Error = err
}

// Init initializes the model
func (m *Model) Init() tea.Cmd {
	return ticker()
}

func ticker() tea.Cmd {
	return tea.Tick(time.Millisecond*100, func(t time.Time) tea.Msg {
		return TickMsg{time: t}
	})
}

// Update handles UI events and state transitions
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return m.handleKeyPress(msg)
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.viewport.Width = msg.Width - 4
		m.viewport.Height = msg.Height - 10
		m.updateTableLayout()
		return m, nil
	case ProgressMsg:
		m.mu.Lock()
		m.progress = msg.Progress
		m.mu.Unlock()
		m.updateTableLayout()
		return m, ticker()
	case VulnMsg:
		m.mu.Lock()
		m.vulns = append(m.vulns, msg.Entry)
		m.mu.Unlock()
		m.applyFilters()
		return m, ticker()
	case DoneMsg:
		m.mu.Lock()
		m.progress.Completed = true
		m.result = msg.Result
		m.state = StateExplorer
		m.mu.Unlock()
		m.applyFilters()
		return m, nil
	case ErrorMsg:
		m.mu.Lock()
		m.progress.Error = msg.Err
		m.mu.Unlock()
		return m, tea.Quit
	case TickMsg:
		var cmd tea.Cmd
		if m.state == StateScanning {
			m.spinner, cmd = m.spinner.Update(msg)
			return m, tea.Batch(cmd, ticker())
		}
		return m, nil
	}
	return m, nil
}

func (m *Model) handleKeyPress(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// Quit hotkeys
	if key == "ctrl+c" {
		return m, tea.Quit
	}

	// Search mode typing
	if m.isSearching {
		switch key {
		case "enter", "esc":
			m.isSearching = false
			return m, nil
		case "backspace":
			if len(m.searchQuery) > 0 {
				m.searchQuery = m.searchQuery[:len(m.searchQuery)-1]
				m.applyFilters()
			}
			return m, nil
		default:
			if len(key) == 1 {
				m.searchQuery += key
				m.applyFilters()
			}
			return m, nil
		}
	}

	switch m.state {
	case StateScanning:
		if key == "q" {
			return m, tea.Quit
		}

	case StateExplorer:
		switch key {
		case "q":
			return m, tea.Quit
		case "enter":
			if len(m.filteredVulns) > 0 && m.selectedIdx < len(m.filteredVulns) {
				m.state = StateDetail
				m.updateDetailViewport()
			}
		case "1":
			m.filterSeverity = "critical"
			m.applyFilters()
		case "2":
			m.filterSeverity = "high"
			m.applyFilters()
		case "3":
			m.filterSeverity = "medium"
			m.applyFilters()
		case "4":
			m.filterSeverity = "low"
			m.applyFilters()
		case "0", "a":
			m.filterSeverity = ""
			m.applyFilters()
		case "/":
			m.isSearching = true
			m.searchQuery = ""
		case "g":
			m.groupMode = (m.groupMode + 1) % 3
			m.applyFilters()
		case "esc":
			m.searchQuery = ""
			m.filterSeverity = ""
			m.applyFilters()
		case "up", "k":
			if m.selectedIdx > 0 {
				m.selectedIdx--
				m.vulnTable.SetCursor(m.selectedIdx)
			}
		case "down", "j":
			if m.selectedIdx < len(m.filteredVulns)-1 {
				m.selectedIdx++
				m.vulnTable.SetCursor(m.selectedIdx)
			}
		}

	case StateDetail:
		switch key {
		case "esc", "q", "backspace":
			m.state = StateExplorer
		case "up", "k":
			m.viewport.LineUp(1)
		case "down", "j":
			m.viewport.LineDown(1)
		}
	}

	return m, nil
}

func (m *Model) applyFilters() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.applyFiltersLocked()
}

func (m *Model) applyFiltersLocked() {
	var result []VulnEntry
	search := strings.ToLower(strings.TrimSpace(m.searchQuery))

	for _, v := range m.vulns {
		// Severity filter
		if m.filterSeverity != "" {
			if !strings.EqualFold(v.Severity, m.filterSeverity) {
				continue
			}
		}

		// Text search filter
		if search != "" {
			matchPkg := strings.Contains(strings.ToLower(v.Package), search)
			matchCVE := strings.Contains(strings.ToLower(v.CVE), search) || strings.Contains(strings.ToLower(v.CVEID), search)
			matchTitle := strings.Contains(strings.ToLower(v.CVETitle), search) || strings.Contains(strings.ToLower(v.Description), search)
			if !matchPkg && !matchCVE && !matchTitle {
				continue
			}
		}

		result = append(result, v)
	}

	m.filteredVulns = result
	if m.selectedIdx >= len(m.filteredVulns) {
		m.selectedIdx = 0
	}
	m.updateTableLayout()
}

func (m *Model) updateTableLayout() {
	var rows []table.Row
	for _, v := range m.filteredVulns {
		cveDisp := v.CVE
		if v.CVEID != "" {
			cveDisp = v.CVEID
		}
		title := v.Description
		if title == "" {
			title = v.CVETitle
		}
		if len(title) > 40 {
			title = title[:37] + "..."
		}

		rows = append(rows, table.Row{
			strings.ToUpper(v.Severity),
			v.Package,
			cveDisp,
			title,
		})
	}

	m.vulnTable.SetRows(rows)
}

func (m *Model) updateDetailViewport() {
	if len(m.filteredVulns) == 0 || m.selectedIdx >= len(m.filteredVulns) {
		return
	}

	v := m.filteredVulns[m.selectedIdx]
	var b strings.Builder

	// Header section
	b.WriteString(m.styles.Title.Render(fmt.Sprintf("󰍉 VULNERABILITY DETAILS: %s", v.Package)) + "\n\n")

	cveDisp := v.CVE
	if v.CVEID != "" {
		cveDisp = fmt.Sprintf("%s (%s)", v.CVEID, v.CVE)
	}

	badge := RenderSeverityBadge(v.Severity, m.styles)
	cvssStr := fmt.Sprintf("%.1f", v.CVSS)
	if v.CVSS == 0 {
		cvssStr = "N/A"
	}

	b.WriteString(fmt.Sprintf("  %-16s %s\n", "Severity:", badge))
	b.WriteString(fmt.Sprintf("  %-16s %s\n", "CVSS Score:", cvssStr))
	b.WriteString(fmt.Sprintf("  %-16s %s\n", "CVE / Primary ID:", cveDisp))
	if v.PublishedAt != "" {
		b.WriteString(fmt.Sprintf("  %-16s %s\n", "Published Date:", v.PublishedAt))
	}
	b.WriteString("\n")

	// Description section
	b.WriteString(m.styles.Title.Render("󰈔 Description") + "\n")
	desc := v.CVEDescription
	if desc == "" {
		desc = v.Description
	}
	if desc == "" {
		desc = "No detailed description available."
	}
	b.WriteString(desc + "\n\n")

	// Dependency Chain Tree section
	b.WriteString(m.styles.Title.Render("󰒍 Dependency Chain Path") + "\n")
	if len(v.DependencyPath) > 0 {
		for i, nodeName := range v.DependencyPath {
			indent := strings.Repeat("    ", i)
			prefix := "└── "
			if i == 0 {
				prefix = "󰏖 Root: "
				b.WriteString(fmt.Sprintf("%s%s%s\n", indent, prefix, m.styles.ChainNode.Render(nodeName)))
			} else if i == len(v.DependencyPath)-1 {
				b.WriteString(fmt.Sprintf("%s%s%s [VULNERABLE]\n", indent, prefix, m.styles.ChainTarget.Render(nodeName)))
			} else {
				b.WriteString(fmt.Sprintf("%s%s%s\n", indent, prefix, m.styles.ChainTree.Render(nodeName)))
			}
		}
	} else {
		b.WriteString(fmt.Sprintf("  └── %s (Direct Dependency)\n", v.Package))
	}

	b.WriteString("\n" + m.styles.Subtitle.Render("Press [Esc] or [q] to return to list view"))

	m.viewport.SetContent(b.String())
}

// View renders the TUI screen depending on current state
func (m *Model) View() string {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.progress.Error != "" {
		return m.renderError()
	}

	switch m.state {
	case StateScanning:
		return m.renderScanning()
	case StateExplorer:
		return m.renderExplorer()
	case StateDetail:
		return m.renderDetail()
	default:
		return m.renderScanning()
	}
}

func (m *Model) renderScanning() string {
	var sections []string

	header := m.spinner.View() + " " + m.styles.Header.Render("Vigil Vulnerability Scanner")
	sections = append(sections, header, "")

	if m.progress.Total > 0 {
		percent := float64(m.progress.Current) / float64(m.progress.Total)
		if percent > 1.0 {
			percent = 1.0
		}
		width := 40
		filled := int(percent * float64(width))
		bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
		progressView := fmt.Sprintf("[%s] %d%% (%d/%d packages)", bar, int(percent*100), m.progress.Current, m.progress.Total)
		sections = append(sections, progressView)
	}

	if m.progress.CurrentPkg != "" {
		sections = append(sections, fmt.Sprintf("Scanning: %s", m.styles.Subtitle.Render(m.progress.CurrentPkg)))
	}

	// Elapsed time
	elapsed := time.Since(m.startTime).Seconds()
	sections = append(sections, fmt.Sprintf("󰥔  Elapsed: %.0fs | Found: %d vulnerabilities", elapsed, len(m.vulns)))

	if len(m.vulns) > 0 {
		sections = append(sections, "", m.styles.Title.Render("󰍜 Vulnerabilities Stream:"), m.vulnTable.View())
	}

	sections = append(sections, "", m.styles.Subtitle.Render("Press q to cancel"))
	return strings.Join(sections, "\n")
}

func (m *Model) renderExplorer() string {
	var sections []string

	// Header banner
	header := m.styles.Header.Render(fmt.Sprintf("󰒍 VIGIL SECURITY EXPLORER - %d VULNERABILITIES DETECTED", len(m.vulns)))
	sections = append(sections, header)

	// Filter & Search bar
	filterStr := "ALL"
	if m.filterSeverity != "" {
		filterStr = strings.ToUpper(m.filterSeverity)
	}
	searchStr := "none"
	if m.searchQuery != "" {
		searchStr = fmt.Sprintf("%q", m.searchQuery)
	}
	if m.isSearching {
		searchStr = fmt.Sprintf("%q █", m.searchQuery)
	}

	filterBar := fmt.Sprintf("Filter: [%s] | Search: %s | Showing %d of %d vulnerabilities",
		m.styles.KeyHint.Render(filterStr),
		m.styles.SearchPrompt.Render(searchStr),
		len(m.filteredVulns),
		len(m.vulns),
	)
	sections = append(sections, m.styles.FilterBar.Render(filterBar), "")

	// Table or Empty view
	if len(m.filteredVulns) > 0 {
		sections = append(sections, m.vulnTable.View())
	} else {
		sections = append(sections, m.styles.Subtitle.Render("  No vulnerabilities match current filter/search criteria."))
	}

	// Hotkeys Status Bar Footer
	footer := m.styles.StatusBar.Render(
		"[1-4] Severity | [/] Search | [Enter] Inspect Detail | [g] Group | [Esc] Reset | [q] Quit",
	)
	sections = append(sections, "", footer)

	return strings.Join(sections, "\n")
}

func (m *Model) renderDetail() string {
	var sections []string

	header := m.styles.Header.Render("󰍉 VIGIL SECURITY DEEP INSPECTOR")
	sections = append(sections, header, "")
	sections = append(sections, m.viewport.View())

	return strings.Join(sections, "\n")
}

func (m *Model) renderError() string {
	return fmt.Sprintf("\n[!] Vigil Error: %s\nPress q to exit.\n", m.progress.Error)
}
