package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/viewport"
	"github.com/charmbracelet/lipgloss"
	"github.com/guttenbergovitz/vigil-cli/internal/container"
	"github.com/guttenbergovitz/vigil-cli/internal/export"
	"github.com/guttenbergovitz/vigil-cli/internal/license"
	"github.com/guttenbergovitz/vigil-cli/internal/secrets"
	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// ViewState represents screen mode.
type ViewState int

const (
	StateScanning ViewState = iota
	StateExplorer
	StateDetail
	StateExportModal
)

// TickMsg triggers periodic UI updates during scan.
type TickMsg struct {
	time time.Time
}

// ScanProgress tracks scan progress.
type ScanProgress struct {
	Current      int
	Total        int
	CurrentPkg   string
	CurrentVulns int
	Completed    bool
	Error        string
}

// VulnEntry represents an SCA vulnerability entry.
type VulnEntry struct {
	Package        string
	Version        string
	CVE            string
	CVEID          string
	Severity       string
	CVSS           float64
	CVSSVector     string
	Description    string
	CVETitle       string
	CVEDescription string
	PublishedAt    string
	DependencyPath []string
}

// Model represents the fullscreen DevSecOps TUI state.
type Model struct {
	activeTab       ActiveTab
	state           ViewState
	progress        ScanProgress
	startTime       time.Time
	result          *types.ScanResult
	graph           *types.DependencyGraph
	vulns           []VulnEntry
	secretFindings  []secrets.SecretFinding
	iacIssues       []container.SecurityIssue
	licenseFindings []license.LicenseFinding
	filteredItems   []TUIFinding
	spinner         spinner.Model
	progressBar     progress.Model
	vulnTable       table.Model
	viewport        viewport.Model
	styles          Styles
	width           int
	height          int
	selectedIdx     int
	filterSeverity  string // "", "critical", "high", "medium", "low"
	searchQuery     string
	isSearching     bool
	groupMode       GroupMode
	exportFormat    string // "json", "csv", "markdown", "cyclonedx", "spdx"
	exportStatus    string
	mu              sync.Mutex
}

// ProgressMsg updates scan progress.
type ProgressMsg struct {
	Progress ScanProgress
}

// VulnMsg adds a vulnerability entry.
type VulnMsg struct {
	Entry VulnEntry
}

// DoneMsg indicates scan completion.
type DoneMsg struct {
	Result *types.ScanResult
	Graph  *types.DependencyGraph
}

// ErrorMsg indicates scan error.
type ErrorMsg struct {
	Err string
}

// NewModel initializes the TUI model.
func NewModel() *Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#BD93F9"))

	p := progress.New(progress.WithDefaultGradient())

	columns := []table.Column{
		{Title: "DOMAIN", Width: 10},
		{Title: "SEVERITY", Width: 12},
		{Title: "TARGET / PACKAGE", Width: 24},
		{Title: "ID / RULE", Width: 20},
		{Title: "REASON FLAGGED", Width: 45},
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(true),
		table.WithHeight(14),
	)

	tStyle := table.DefaultStyles()
	tStyle.Header = tStyle.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("#6272A4")).
		BorderBottom(true).
		Bold(true)
	tStyle.Selected = tStyle.Selected.
		Foreground(lipgloss.Color("#F8F8F2")).
		Background(lipgloss.Color("#44475A")).
		Bold(true)
	t.SetStyles(tStyle)

	vp := viewport.New(100, 20)

	return &Model{
		activeTab:   TabVulnerabilities,
		state:       StateScanning,
		startTime:   time.Now(),
		spinner:     s,
		progressBar: p,
		vulnTable:   t,
		viewport:    vp,
		styles:      DefaultStyles(),
		width:       120,
		height:      35,
	}
}

// SetProgress updates scan progress state.
func (m *Model) SetProgress(current, total int, currentPkg string, vulns int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.progress.Current = current
	m.progress.Total = total
	m.progress.CurrentPkg = currentPkg
	m.progress.CurrentVulns = vulns
}

// AddVulnerability adds a detected vulnerability entry.
func (m *Model) AddVulnerability(entry VulnEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.vulns = append(m.vulns, entry)
}

// SetDone marks scanning as finished and enables interactive exploration mode.
func (m *Model) SetDone(result *types.ScanResult, graph *types.DependencyGraph, secretsList []secrets.SecretFinding, iacList []container.SecurityIssue, licensesList []license.LicenseFinding) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.progress.Completed = true
	m.result = result
	m.graph = graph
	m.secretFindings = secretsList
	m.iacIssues = iacList
	m.licenseFindings = licensesList
	m.state = StateExplorer
	m.applyFiltersLocked()
}

// SetError marks scanning as failed.
func (m *Model) SetError(err string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.progress.Error = err
}

// Init initializes the model.
func (m *Model) Init() tea.Cmd {
	return ticker()
}

func ticker() tea.Cmd {
	return tea.Tick(time.Millisecond*100, func(t time.Time) tea.Msg {
		return TickMsg{time: t}
	})
}

// Update handles key presses and state transitions.
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
		m.graph = msg.Graph
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

	if key == "ctrl+c" {
		return m, tea.Quit
	}

	// Search Mode input handler
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

	// Export Modal input handler
	if m.state == StateExportModal {
		switch key {
		case "esc", "q":
			m.state = StateExplorer
			m.exportStatus = ""
		case "1":
			return m, m.executeExport("json")
		case "2":
			return m, m.executeExport("csv")
		case "3":
			return m, m.executeExport("markdown")
		case "4":
			return m, m.executeExport("cyclonedx")
		case "5":
			return m, m.executeExport("spdx")
		}
		return m, nil
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
		case "tab":
			m.activeTab = (m.activeTab + 1) % 5
			m.applyFilters()
		case "1":
			m.activeTab = TabVulnerabilities
			m.applyFilters()
		case "2":
			m.activeTab = TabSecrets
			m.applyFilters()
		case "3":
			m.activeTab = TabIaC
			m.applyFilters()
		case "4":
			m.activeTab = TabLicenses
			m.applyFilters()
		case "5":
			m.activeTab = TabDependencyGraph
			m.applyFilters()
		case "enter":
			m.selectedIdx = m.vulnTable.Cursor()
			if len(m.filteredItems) > 0 && m.selectedIdx >= 0 && m.selectedIdx < len(m.filteredItems) {
				m.state = StateDetail
				m.updateDetailViewport()
			}
		case "g":
			m.groupMode = (m.groupMode + 1) % 3
			m.applyFilters()
		case "e":
			m.state = StateExportModal
		case "/":
			m.isSearching = true
			m.searchQuery = ""
		case "c":
			m.filterSeverity = "critical"
			m.applyFilters()
		case "h":
			m.filterSeverity = "high"
			m.applyFilters()
		case "m":
			m.filterSeverity = "medium"
			m.applyFilters()
		case "l":
			m.filterSeverity = "low"
			m.applyFilters()
		case "a", "esc":
			m.filterSeverity = ""
			m.searchQuery = ""
			m.applyFilters()
		case "up", "k", "down", "j":
			var cmd tea.Cmd
			m.vulnTable, cmd = m.vulnTable.Update(msg)
			m.selectedIdx = m.vulnTable.Cursor()
			return m, cmd
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
	var items []TUIFinding

	// 1. Collect findings according to ActiveTab
	switch m.activeTab {
	case TabVulnerabilities:
		for _, v := range m.vulns {
			cveID := v.CVE
			if v.CVEID != "" {
				cveID = v.CVEID
			}
			reason := fmt.Sprintf("Known CVE with CVSS %.1f exposure in dependency chain", v.CVSS)
			if v.CVEDescription != "" {
				reason = v.CVEDescription
			}
			items = append(items, TUIFinding{
				Domain:         "SCA",
				Package:        v.Package,
				Version:        v.Version,
				ID:             cveID,
				Severity:       v.Severity,
				CVSS:           v.CVSS,
				Title:          v.CVETitle,
				Description:    v.Description,
				ReasonFlagged:  reason,
				DependencyPath: v.DependencyPath,
				Remediation:    "Upgrade package to non-vulnerable patch version",
			})
		}

	case TabSecrets:
		for _, s := range m.secretFindings {
			relPath := filepath.Base(s.FilePath)
			items = append(items, TUIFinding{
				Domain:        "SECRET",
				Package:       relPath,
				ID:            string(s.Type),
				Severity:      "secret",
				Title:         fmt.Sprintf("Leaked %s at line %d", s.Type, s.LineNumber),
				Description:   s.LineContent,
				ReasonFlagged: fmt.Sprintf("Hardcoded secret pattern matched with Shannon entropy %.2f", s.Entropy),
				Remediation:   "Revoke secret key immediately and remove from source code / git history",
				RawSecret:     s,
			})
		}

	case TabIaC:
		for _, iac := range m.iacIssues {
			relPath := filepath.Base(iac.Source)
			items = append(items, TUIFinding{
				Domain:        "IaC",
				Package:       relPath,
				ID:            iac.RuleID,
				Severity:      string(iac.Severity),
				Title:         iac.Title,
				Description:   iac.Message,
				ReasonFlagged: fmt.Sprintf("IaC Security Linter Rule %s triggered: %s", iac.RuleID, iac.Message),
				Remediation:   "Update Dockerfile / GitHub Action workflow according to security best practices",
				RawIaC:        iac,
			})
		}

	case TabLicenses:
		for _, lic := range m.licenseFindings {
			sev := "low"
			reason := "Permissive license (MIT/Apache/BSD) safe for commercial distribution"
			if lic.Category == license.Copyleft {
				sev = "high"
				reason = "Copyleft license (GPL/AGPL) poses legal infection risk for commercial software"
			}
			items = append(items, TUIFinding{
				Domain:        "LICENSE",
				Package:       lic.PackageName,
				Version:       lic.Version,
				ID:            lic.License,
				Severity:      sev,
				Title:         fmt.Sprintf("%s (%s)", lic.License, lic.Category),
				Description:   fmt.Sprintf("Package %s uses %s license", lic.PackageName, lic.License),
				ReasonFlagged: reason,
				Remediation:   "Review open source license compliance terms",
				RawLicense:    lic,
			})
		}

	case TabDependencyGraph:
		// Convert graph nodes into findings for tree exploration
		if m.graph != nil {
			for _, node := range m.graph.Nodes {
				items = append(items, TUIFinding{
					Domain:        "GRAPH",
					Package:       node.Name,
					Version:       node.Version,
					ID:            fmt.Sprintf("Depth %d", node.Depth),
					Severity:      "low",
					Title:         fmt.Sprintf("Node: %s@%s", node.Name, node.Version),
					Description:   fmt.Sprintf("Ecosystem: %s | Direct: %v | Depth: %d", node.Ecosystem, node.Direct, node.Depth),
					ReasonFlagged: fmt.Sprintf("Dependency node in tree with %d vulnerabilities", len(node.Vulnerabilities)),
				})
			}
		}
	}

	// 2. Apply Severity & Text Search filtering
	var filtered []TUIFinding
	search := strings.ToLower(strings.TrimSpace(m.searchQuery))

	for _, item := range items {
		if m.filterSeverity != "" && !strings.EqualFold(item.Severity, m.filterSeverity) {
			continue
		}
		if search != "" {
			matchPkg := strings.Contains(strings.ToLower(item.Package), search)
			matchID := strings.Contains(strings.ToLower(item.ID), search)
			matchTitle := strings.Contains(strings.ToLower(item.Title), search) || strings.Contains(strings.ToLower(item.Description), search)
			if !matchPkg && !matchID && !matchTitle {
				continue
			}
		}
		filtered = append(filtered, item)
	}

	// 3. Apply Grouping Mode if requested
	if m.groupMode == GroupPackage {
		filtered = groupFindingsByPackage(filtered)
	} else if m.groupMode == GroupSeverity {
		filtered = groupFindingsBySeverity(filtered)
	}

	m.filteredItems = filtered
	if m.selectedIdx >= len(m.filteredItems) {
		m.selectedIdx = 0
	}
	m.updateTableLayout()
}

func (m *Model) updateTableLayout() {
	var rows []table.Row
	for _, item := range m.filteredItems {
		reason := item.ReasonFlagged
		if len(reason) > 42 {
			reason = reason[:39] + "..."
		}
		rows = append(rows, table.Row{
			item.Domain,
			strings.ToUpper(item.Severity),
			item.Package,
			item.ID,
			reason,
		})
	}
	m.vulnTable.SetRows(rows)
}

func (m *Model) updateDetailViewport() {
	if len(m.filteredItems) == 0 || m.selectedIdx >= len(m.filteredItems) {
		return
	}

	item := m.filteredItems[m.selectedIdx]
	var b strings.Builder

	// Header Banner
	b.WriteString(m.styles.Title.Render(fmt.Sprintf("󰍉 SECURITY FINDING DEEP INSPECTION: %s", item.Package)) + "\n\n")

	badge := RenderSeverityBadge(item.Severity, m.styles)
	b.WriteString(fmt.Sprintf("  %-18s %s\n", "Domain:", item.Domain))
	b.WriteString(fmt.Sprintf("  %-18s %s\n", "Severity:", badge))
	b.WriteString(fmt.Sprintf("  %-18s %s\n", "Package / Target:", item.Package))
	if item.Version != "" {
		b.WriteString(fmt.Sprintf("  %-18s %s\n", "Version:", item.Version))
	}
	b.WriteString(fmt.Sprintf("  %-18s %s\n", "ID / Rule:", item.ID))
	b.WriteString("\n")

	// EXPLICIT REASON FLAGGED SECTION
	b.WriteString(m.styles.Title.Render("💡 REASON WHY THIS WAS FLAGGED") + "\n")
	b.WriteString(m.styles.ReasonBox.Render(item.ReasonFlagged) + "\n\n")

	// Description Section
	b.WriteString(m.styles.Title.Render("󰈔 Full Description & Context") + "\n")
	b.WriteString(item.Description + "\n\n")

	// Dependency Path Visualizer
	if len(item.DependencyPath) > 0 {
		b.WriteString(m.styles.Title.Render("󰒍 Dependency Chain Tree Path") + "\n")
		for i, nodeName := range item.DependencyPath {
			indent := strings.Repeat("    ", i)
			prefix := "└── "
			if i == 0 {
				prefix = "󰏖 Root: "
				b.WriteString(fmt.Sprintf("%s%s%s\n", indent, prefix, m.styles.ChainNode.Render(nodeName)))
			} else if i == len(item.DependencyPath)-1 {
				b.WriteString(fmt.Sprintf("%s%s%s [VULNERABLE TARGET]\n", indent, prefix, m.styles.ChainTarget.Render(nodeName)))
			} else {
				b.WriteString(fmt.Sprintf("%s%s%s\n", indent, prefix, m.styles.ChainTree.Render(nodeName)))
			}
		}
		b.WriteString("\n")
	}

	// Remediation Section
	if item.Remediation != "" {
		b.WriteString(m.styles.Title.Render("🛠️ Recommended Action / Remediation") + "\n")
		b.WriteString(m.styles.KeyHint.Render(item.Remediation) + "\n\n")
	}

	b.WriteString(m.styles.Subtitle.Render("Press [Esc] or [q] to return to Main Explorer"))
	m.viewport.SetContent(b.String())
}

func (m *Model) executeExport(fmtName string) tea.Cmd {
	if m.result == nil {
		m.exportStatus = "Error: No scan result available to export"
		return nil
	}

	ext := fmtName
	if fmtName == "cyclonedx" {
		ext = "cyclonedx.json"
	} else if fmtName == "spdx" {
		ext = "spdx.json"
	}

	fileName := fmt.Sprintf("vigil-export-%d.%s", time.Now().Unix(), ext)
	file, err := os.Create(fileName)
	if err != nil {
		m.exportStatus = fmt.Sprintf("Error creating export file: %v", err)
		return nil
	}
	defer file.Close()

	var exportErr error
	switch fmtName {
	case "json":
		exportErr = export.JSON(m.result, file)
	case "csv":
		exportErr = export.CSV(m.result, file)
	case "markdown":
		exportErr = export.Markdown(m.result, file)
	case "cyclonedx":
		exportErr = export.CycloneDX(m.result, file)
	case "spdx":
		exportErr = export.SPDX(m.result, file)
	}

	if exportErr != nil {
		m.exportStatus = fmt.Sprintf("Export failed: %v", exportErr)
	} else {
		m.exportStatus = fmt.Sprintf("Successfully exported scan findings to %s", fileName)
		m.state = StateExplorer
	}

	return nil
}

// View renders the fullscreen TUI screen
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
	case StateExportModal:
		return m.renderExportModal()
	default:
		return m.renderScanning()
	}
}

func (m *Model) renderScanning() string {
	var sections []string
	header := m.spinner.View() + " " + m.styles.Header.Render("Vigil DevSecOps Full-Spectrum Scanner")
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

	// 1. Top Header Banner
	vulnCount := 0
	if m.result != nil {
		vulnCount = m.result.TotalVulns
	} else {
		vulnCount = len(m.vulns)
	}

	headerText := fmt.Sprintf("🛡️ VIGIL DEVSECOPS DASHBOARD | %d VULNS | %d SECRETS | %d IAC RISKS",
		vulnCount, len(m.secretFindings), len(m.iacIssues))
	sections = append(sections, m.styles.Header.Render(headerText))

	// 2. Navigation Tabs Bar
	tabs := []string{"[1] Vulns (SCA)", "[2] Secrets", "[3] IaC Security", "[4] Licenses", "[5] Dep Graph"}
	var renderedTabs []string
	for i, tab := range tabs {
		if ActiveTab(i) == m.activeTab {
			renderedTabs = append(renderedTabs, m.styles.ActiveTab.Render(tab))
		} else {
			renderedTabs = append(renderedTabs, m.styles.InactiveTab.Render(tab))
		}
	}
	tabsRow := lipgloss.JoinHorizontal(lipgloss.Top, renderedTabs...)
	sections = append(sections, tabsRow)

	// 3. Filter & Search Bar
	filterStr := "ALL"
	if m.filterSeverity != "" {
		filterStr = strings.ToUpper(m.filterSeverity)
	}
	groupStr := "FLAT"
	if m.groupMode == GroupPackage {
		groupStr = "BY PACKAGE"
	} else if m.groupMode == GroupSeverity {
		groupStr = "BY SEVERITY"
	}

	searchStr := "none"
	if m.searchQuery != "" {
		searchStr = fmt.Sprintf("%q", m.searchQuery)
	}
	if m.isSearching {
		searchStr = fmt.Sprintf("%q █", m.searchQuery)
	}

	filterBar := fmt.Sprintf("Group: [%s] | Filter: [%s] | Search: %s | Showing %d items",
		m.styles.KeyHint.Render(groupStr),
		m.styles.KeyHint.Render(filterStr),
		m.styles.SearchPrompt.Render(searchStr),
		len(m.filteredItems),
	)
	sections = append(sections, m.styles.FilterBar.Render(filterBar), "")

	// 4. Main Table View
	if len(m.filteredItems) > 0 {
		sections = append(sections, m.vulnTable.View())
	} else {
		sections = append(sections, m.styles.Subtitle.Render("  No findings match current view criteria."))
	}

	// 5. Status / Footer Bar
	if m.exportStatus != "" {
		sections = append(sections, m.styles.KeyHint.Render("󰄬 "+m.exportStatus))
	}

	footer := m.styles.StatusBar.Render(
		"[1-5/Tab] View | [c/h/m/l] Filter | [/] Search | [g] Group | [Enter] Detail | [e] Export | [q] Quit",
	)
	sections = append(sections, "", footer)

	return strings.Join(sections, "\n")
}

func (m *Model) renderDetail() string {
	var sections []string
	header := m.styles.Header.Render("󰍉 VIGIL DEVSECOPS DEEP INSPECTOR")
	sections = append(sections, header, "")
	sections = append(sections, m.viewport.View())
	return strings.Join(sections, "\n")
}

func (m *Model) renderExportModal() string {
	var b strings.Builder
	b.WriteString(m.styles.Title.Render("󰈔 VIGIL EXPORT REPORT DIALOG") + "\n\n")
	b.WriteString("Select export format:\n\n")
	b.WriteString("  [1] JSON Format (.json)\n")
	b.WriteString("  [2] CSV Spreadsheet (.csv)\n")
	b.WriteString("  [3] Markdown Report (.md)\n")
	b.WriteString("  [4] CycloneDX v1.5 SBOM (.cyclonedx.json)\n")
	b.WriteString("  [5] SPDX v2.3 SBOM (.spdx.json)\n\n")
	b.WriteString(m.styles.Subtitle.Render("Press [1-5] to export, or [Esc] to cancel"))

	return m.styles.ModalBox.Render(b.String())
}

func (m *Model) renderError() string {
	return fmt.Sprintf("\n[!] Vigil Error: %s\nPress q to exit.\n", m.progress.Error)
}

func groupFindingsByPackage(items []TUIFinding) []TUIFinding {
	groupedMap := make(map[string][]TUIFinding)
	for _, item := range items {
		groupedMap[item.Package] = append(groupedMap[item.Package], item)
	}

	var result []TUIFinding
	for pkg, list := range groupedMap {
		headerFinding := TUIFinding{
			Domain:        list[0].Domain,
			Package:       pkg,
			ID:            fmt.Sprintf("(%d findings)", len(list)),
			Severity:      list[0].Severity,
			ReasonFlagged: fmt.Sprintf("Package group containing %d security items", len(list)),
		}
		result = append(result, headerFinding)
		result = append(result, list...)
	}
	return result
}

func groupFindingsBySeverity(items []TUIFinding) []TUIFinding {
	groupedMap := make(map[string][]TUIFinding)
	for _, item := range items {
		sev := strings.ToLower(item.Severity)
		groupedMap[sev] = append(groupedMap[sev], item)
	}

	var result []TUIFinding
	order := []string{"critical", "high", "medium", "low", "secret", "iac"}
	for _, sev := range order {
		if list, ok := groupedMap[sev]; ok && len(list) > 0 {
			headerFinding := TUIFinding{
				Domain:        "GROUP",
				Package:       strings.ToUpper(sev),
				ID:            fmt.Sprintf("(%d items)", len(list)),
				Severity:      sev,
				ReasonFlagged: fmt.Sprintf("Severity category %s", strings.ToUpper(sev)),
			}
			result = append(result, headerFinding)
			result = append(result, list...)
		}
	}
	return result
}
