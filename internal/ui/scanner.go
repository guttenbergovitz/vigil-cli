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

// Model represents the Lazygit/btm style Fullscreen DevSecOps TUI state.
type Model struct {
	activeTab       ActiveTab
	activePane      ActivePane
	state           ViewState
	isMaximized     bool
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
	reasonVP        viewport.Model
	chainVP         viewport.Model
	detailVP        viewport.Model
	styles          Styles
	width           int
	height          int
	selectedIdx     int
	filterSeverity  string // "", "critical", "high", "medium", "low"
	searchQuery     string
	isSearching     bool
	groupMode       GroupMode
	exportFormat        string // "json", "csv", "markdown", "cyclonedx", "spdx"
	exportStatus        string
	tableReasonColWidth int
	tableTargetColWidth int
	tableIDColWidth     int
	mu                  sync.Mutex
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
		{Title: "TARGET / PACKAGE", Width: 25},
		{Title: "ID / RULE", Width: 20},
		{Title: "REASON SUMMARY", Width: 35},
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(true),
		table.WithHeight(10),
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

	rVP := viewport.New(50, 10)
	cVP := viewport.New(50, 10)
	dVP := viewport.New(50, 10)

	return &Model{
		activeTab:  TabVulnerabilities,
		activePane: PaneTable,
		state:      StateScanning,
		startTime:  time.Now(),
		spinner:    s,
		progressBar: p,
		vulnTable:  t,
		reasonVP:   rVP,
		chainVP:    cVP,
		detailVP:   dVP,
		styles:     DefaultStyles(),
		width:      140,
		height:     40,
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

// Update handles key presses, window resizing, and state transitions.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return m.handleKeyPress(msg)
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.recalculateViewports()
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
			m.activePane = (m.activePane + 1) % 4
		case "shift+tab":
			m.activePane = (m.activePane + 3) % 4
		case "w", "f":
			m.isMaximized = !m.isMaximized
			m.recalculateViewports()
		case "1":
			m.activeTab = TabVulnerabilities
			m.selectedIdx = 0
			m.vulnTable.SetCursor(0)
			m.applyFilters()
		case "2":
			m.activeTab = TabSecrets
			m.selectedIdx = 0
			m.vulnTable.SetCursor(0)
			m.applyFilters()
		case "3":
			m.activeTab = TabIaC
			m.selectedIdx = 0
			m.vulnTable.SetCursor(0)
			m.applyFilters()
		case "4":
			m.activeTab = TabLicenses
			m.selectedIdx = 0
			m.vulnTable.SetCursor(0)
			m.applyFilters()
		case "5":
			m.activeTab = TabDependencyGraph
			m.selectedIdx = 0
			m.vulnTable.SetCursor(0)
			m.applyFilters()
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
		case "up", "k":
			if m.activePane == PaneTable {
				var cmd tea.Cmd
				m.vulnTable, cmd = m.vulnTable.Update(msg)
				m.selectedIdx = m.vulnTable.Cursor()
				m.updateSelectedPaneContents()
				return m, cmd
			} else if m.activePane == PaneReason {
				m.reasonVP.LineUp(1)
			} else if m.activePane == PaneChain {
				m.chainVP.LineUp(1)
			} else if m.activePane == PaneDetails {
				m.detailVP.LineUp(1)
			}
		case "down", "j":
			if m.activePane == PaneTable {
				var cmd tea.Cmd
				m.vulnTable, cmd = m.vulnTable.Update(msg)
				m.selectedIdx = m.vulnTable.Cursor()
				m.updateSelectedPaneContents()
				return m, cmd
			} else if m.activePane == PaneReason {
				m.reasonVP.LineDown(1)
			} else if m.activePane == PaneChain {
				m.chainVP.LineDown(1)
			} else if m.activePane == PaneDetails {
				m.detailVP.LineDown(1)
			}
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

	// Collect findings according to ActiveTab
	switch m.activeTab {
	case TabVulnerabilities:
		for _, v := range m.vulns {
			cveID := v.CVE
			if v.CVEID != "" {
				cveID = v.CVEID
			}
			reason := fmt.Sprintf("A vulnerability affects %s (%s). The issue is tracked upstream as %s with CVSS score %.1f. Specially crafted payloads or triggers may result in security compromise.", v.Package, v.Version, cveID, v.CVSS)
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
				Description:   fmt.Sprintf("Hardcoded secret discovered in %s:%d\nMatch: %s", s.FilePath, s.LineNumber, s.Match),
				ReasonFlagged: fmt.Sprintf("High-entropy secret key pattern matching %s discovered in source code (Shannon Entropy: %.2f)", s.Type, s.Entropy),
				Remediation:   "Revoke secret key immediately and remove from git commit history",
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
				ReasonFlagged: fmt.Sprintf("IaC Linter Rule %s triggered: %s", iac.RuleID, iac.Message),
				Remediation:   "Update Dockerfile / GitHub Action workflow according to security best practices",
				RawIaC:        iac,
			})
		}

	case TabLicenses:
		for _, lic := range m.licenseFindings {
			sev := "low"
			reason := "Permissive license (MIT/Apache/BSD) safe for commercial software distribution"
			if lic.Category == license.Copyleft {
				sev = "high"
				reason = "Copyleft license (GPL/AGPL) poses legal infection risk requiring source code disclosure"
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
				Remediation:   "Review open source license terms and compliance requirements",
				RawLicense:    lic,
			})
		}

	case TabDependencyGraph:
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
					ReasonFlagged: fmt.Sprintf("Dependency graph node with %d vulnerabilities", len(node.Vulnerabilities)),
				})
			}
		}
	}

	// Severity & Text Search filtering
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

	// Grouping Mode
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
	m.updateSelectedPaneContents()
}

func (m *Model) recalculateViewports() {
	bodyHeight := m.height - 4
	if bodyHeight < 8 {
		bodyHeight = 8
	}

	topHeight := bodyHeight / 2
	bottomHeight := bodyHeight - topHeight

	availWidth := m.width - 2
	if availWidth < 30 {
		availWidth = 30
	}

	wReason := int(float64(availWidth) * 0.25)
	wDetail := int(float64(availWidth) * 0.50)
	wChain := availWidth - wReason - wDetail

	if m.isMaximized {
		topHeight = bodyHeight
		bottomHeight = bodyHeight
		wReason = m.width - 2
		wDetail = m.width - 2
		wChain = m.width - 2
	}

	// Calculate rich 5-column table widths spanning full width across the top
	tableInnerWidth := availWidth - 10
	if tableInnerWidth < 30 {
		tableInnerWidth = 30
	}
	domainColWidth := 10
	sevColWidth := 12
	remWidth := tableInnerWidth - domainColWidth - sevColWidth
	targetColWidth := int(float64(remWidth) * 0.25)
	idColWidth := int(float64(remWidth) * 0.25)
	reasonColWidth := remWidth - targetColWidth - idColWidth
	if reasonColWidth < 10 {
		reasonColWidth = 10
	}

	m.tableTargetColWidth = targetColWidth
	m.tableIDColWidth = idColWidth
	m.tableReasonColWidth = reasonColWidth

	m.vulnTable.SetColumns([]table.Column{
		{Title: "DOMAIN", Width: domainColWidth},
		{Title: "SEVERITY", Width: sevColWidth},
		{Title: "TARGET / PACKAGE", Width: targetColWidth},
		{Title: "ID / RULE", Width: idColWidth},
		{Title: "REASON SUMMARY", Width: reasonColWidth},
	})

	m.vulnTable.SetWidth(availWidth - 4)
	m.vulnTable.SetHeight(topHeight - 3)

	m.reasonVP.Width = wReason - 4
	m.reasonVP.Height = bottomHeight - 3

	m.detailVP.Width = wDetail - 4
	m.detailVP.Height = bottomHeight - 3

	m.chainVP.Width = wChain - 4
	m.chainVP.Height = bottomHeight - 3

	m.updateSelectedPaneContents()
}

func (m *Model) updateTableLayout() {
	targetWidth := m.tableTargetColWidth
	if targetWidth <= 0 {
		targetWidth = 20
	}
	idWidth := m.tableIDColWidth
	if idWidth <= 0 {
		idWidth = 20
	}
	reasonWidth := m.tableReasonColWidth
	if reasonWidth <= 0 {
		reasonWidth = 30
	}

	var rows []table.Row
	for _, item := range m.filteredItems {
		pkgStr := item.Package
		if len(pkgStr) > targetWidth {
			if targetWidth > 3 {
				pkgStr = pkgStr[:targetWidth-3] + "..."
			}
		}

		idStr := item.ID
		if len(idStr) > idWidth {
			if idWidth > 3 {
				idStr = idStr[:idWidth-3] + "..."
			}
		}

		reasonSummary := item.ReasonFlagged
		if len(reasonSummary) > reasonWidth {
			if reasonWidth > 3 {
				reasonSummary = reasonSummary[:reasonWidth-3] + "..."
			}
		}

		rows = append(rows, table.Row{
			item.Domain,
			strings.ToUpper(item.Severity),
			pkgStr,
			idStr,
			reasonSummary,
		})
	}
	m.vulnTable.SetRows(rows)
}

func (m *Model) updateSelectedPaneContents() {
	if len(m.filteredItems) == 0 {
		m.reasonVP.SetContent("No findings in this category.")
		m.chainVP.SetContent("No dependency chain available.")
		m.detailVP.SetContent("No detailed inspection content.")
		return
	}

	if m.selectedIdx < 0 || m.selectedIdx >= len(m.filteredItems) {
		m.selectedIdx = 0
		m.vulnTable.SetCursor(0)
	}

	item := m.filteredItems[m.selectedIdx]

	// 1. Reason Viewport Content (Word Wrapped)
	reasonWrapped := lipgloss.NewStyle().
		Width(m.reasonVP.Width).
		Render(item.ReasonFlagged)
	m.reasonVP.SetContent(reasonWrapped)

	// 2. Dependency Chain Viewport Content
	var chainBuf strings.Builder
	if len(item.DependencyPath) > 0 {
		for i, nodeName := range item.DependencyPath {
			indent := strings.Repeat("  ", i)
			if i == 0 {
				chainBuf.WriteString(fmt.Sprintf("%s󰏖 Root: %s\n", indent, nodeName))
			} else if i == len(item.DependencyPath)-1 {
				chainBuf.WriteString(fmt.Sprintf("%s└── %s [VULNERABLE TARGET]\n", indent, nodeName))
			} else {
				chainBuf.WriteString(fmt.Sprintf("%s└── %s\n", indent, nodeName))
			}
		}
	} else {
		chainBuf.WriteString(fmt.Sprintf("Target: %s@%s\nNo deep dependency path recorded.", item.Package, item.Version))
	}
	m.chainVP.SetContent(chainBuf.String())

	// 3. Detail Inspection Viewport Content
	var detailBuf strings.Builder
	detailBuf.WriteString(fmt.Sprintf("Target Package: %s\n", item.Package))
	if item.Version != "" {
		detailBuf.WriteString(fmt.Sprintf("Version: %s\n", item.Version))
	}
	detailBuf.WriteString(fmt.Sprintf("ID / Rule: %s\n", item.ID))
	detailBuf.WriteString(fmt.Sprintf("Severity: %s\n\n", RenderSeverityBadge(item.Severity, m.styles)))

	detailBuf.WriteString("󰈔 Context & Description:\n")
	descWrapped := lipgloss.NewStyle().
		Width(m.detailVP.Width).
		Render(item.Description)
	detailBuf.WriteString(descWrapped + "\n\n")

	if item.Remediation != "" {
		detailBuf.WriteString("🛠️ Recommended Action:\n")
		remWrapped := lipgloss.NewStyle().
			Width(m.detailVP.Width).
			Render(item.Remediation)
		detailBuf.WriteString(remWrapped + "\n")
	}

	m.detailVP.SetContent(detailBuf.String())
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
		m.exportStatus = fmt.Sprintf("Exported findings to %s", fileName)
		m.state = StateExplorer
	}

	return nil
}

// View renders the Lazygit/btm style Fullscreen DevSecOps Multi-Pane TUI
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
		return m.renderLazygitExplorer()
	case StateExportModal:
		return m.renderExportModal()
	default:
		return m.renderScanning()
	}
}

func (m *Model) renderScanning() string {
	var sections []string
	header := m.styles.Header.Render(fmt.Sprintf("🛡️ VIGIL DEVSECOPS SCANNER %s", m.spinner.View()))
	sections = append(sections, header)

	bodyHeight := m.height - 4
	if bodyHeight < 10 {
		bodyHeight = 10
	}

	availWidth := m.width - 2
	if availWidth < 20 {
		availWidth = 20
	}

	// Calculate dynamic table column widths for scanning view (subtracting 14 for outer box border & cell padding)
	scanTableInnerWidth := availWidth - 14
	if scanTableInnerWidth < 30 {
		scanTableInnerWidth = 30
	}
	domainColWidth := 10
	sevColWidth := 12
	remWidth := scanTableInnerWidth - domainColWidth - sevColWidth
	targetColWidth := int(float64(remWidth) * 0.25)
	idColWidth := int(float64(remWidth) * 0.25)
	reasonColWidth := remWidth - targetColWidth - idColWidth
	if reasonColWidth < 10 {
		reasonColWidth = 10
	}
	m.tableTargetColWidth = targetColWidth
	m.tableIDColWidth = idColWidth
	m.tableReasonColWidth = reasonColWidth

	m.vulnTable.SetColumns([]table.Column{
		{Title: "DOMAIN", Width: domainColWidth},
		{Title: "SEVERITY", Width: sevColWidth},
		{Title: "TARGET / PACKAGE", Width: targetColWidth},
		{Title: "ID / RULE", Width: idColWidth},
		{Title: "REASON SUMMARY", Width: reasonColWidth},
	})
	m.vulnTable.SetWidth(availWidth - 4)
	m.vulnTable.SetHeight(bodyHeight - 8)

	var scanBody []string
	if m.progress.Total > 0 {
		percent := float64(m.progress.Current) / float64(m.progress.Total)
		if percent > 1.0 {
			percent = 1.0
		}
		barWidth := 30
		filled := int(percent * float64(barWidth))
		bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
		scanBody = append(scanBody, fmt.Sprintf("[%s] %d%% (%d/%d packages)", bar, int(percent*100), m.progress.Current, m.progress.Total))
	}

	if m.progress.CurrentPkg != "" {
		scanBody = append(scanBody, fmt.Sprintf("Scanning Target: %s", m.styles.Subtitle.Render(m.progress.CurrentPkg)))
	}

	elapsed := time.Since(m.startTime).Seconds()
	scanBody = append(scanBody, fmt.Sprintf("󰥔 Elapsed: %.0fs | Found Vulnerabilities: %d", elapsed, len(m.vulns)))

	if len(m.vulns) > 0 {
		scanBody = append(scanBody, "", m.styles.Title.Render("󰍜 Live Vulnerabilities Stream:"), m.vulnTable.View())
	}

	boxContent := strings.Join(scanBody, "\n")
	scanPaneBox := RenderPaneBorder("󰥔 Full-Spectrum Security Scan in Progress", boxContent, availWidth, bodyHeight, true)
	sections = append(sections, scanPaneBox)

	footer := m.styles.StatusBar.Render("Press [q] to cancel scanning")
	sections = append(sections, footer)

	return strings.Join(sections, "\n")
}

func (m *Model) renderLazygitExplorer() string {
	var sections []string

	// 1. Top Header Banner
	vulnCount := 0
	if m.result != nil {
		vulnCount = m.result.TotalVulns
	} else {
		vulnCount = len(m.vulns)
	}

	headerText := fmt.Sprintf("🛡️ VIGIL LAZYGIT DEVSECOPS DASHBOARD | %d VULNS | %d SECRETS | %d IAC RISKS",
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

	filterBar := fmt.Sprintf("Group: [%s] | Filter: [%s] | Search: %s | Active Pane: [%d] | Maximize: [%v]",
		m.styles.KeyHint.Render(groupStr),
		m.styles.KeyHint.Render(filterStr),
		m.styles.SearchPrompt.Render(searchStr),
		m.activePane+1,
		m.isMaximized,
	)
	sections = append(sections, m.styles.FilterBar.Render(filterBar))

	// 4. Multi-Pane Lazygit / btm Grid Layout
	bodyHeight := m.height - 4
	if bodyHeight < 8 {
		bodyHeight = 8
	}

	topHeight := bodyHeight / 2
	bottomHeight := bodyHeight - topHeight

	availWidth := m.width - 2
	if availWidth < 30 {
		availWidth = 30
	}

	wReason := int(float64(availWidth) * 0.25)
	wDetail := int(float64(availWidth) * 0.50)
	wChain := availWidth - wReason - wDetail

	if m.isMaximized {
		var activePaneBox string
		switch m.activePane {
		case PaneTable:
			activePaneBox = RenderPaneBorder("󰍜 [1] Security Findings Table (Maximized)", m.vulnTable.View(), m.width-2, bodyHeight, true)
		case PaneReason:
			activePaneBox = RenderPaneBorder("💡 [2] Reason Why Flagged (Maximized)", m.reasonVP.View(), m.width-2, bodyHeight, true)
		case PaneDetails:
			activePaneBox = RenderPaneBorder("󰈔 [3] Detailed Inspection (Maximized)", m.detailVP.View(), m.width-2, bodyHeight, true)
		case PaneChain:
			activePaneBox = RenderPaneBorder("󰒍 [4] Dependency Tree Path (Maximized)", m.chainVP.View(), m.width-2, bodyHeight, true)
		}
		sections = append(sections, activePaneBox)
	} else {
		// Top Full-Width Table Pane
		topRow := RenderPaneBorder("󰍜 [1] Security Findings Table", m.vulnTable.View(), availWidth, topHeight, m.activePane == PaneTable)

		// Bottom 3-Column Panes (25% Reason, 50% Details, 25% Chain Graph)
		pReason := RenderPaneBorder("💡 [2] Reason Why Flagged", m.reasonVP.View(), wReason, bottomHeight, m.activePane == PaneReason)
		pDetail := RenderPaneBorder("󰈔 [3] Detailed Inspection", m.detailVP.View(), wDetail, bottomHeight, m.activePane == PaneDetails)
		pChain := RenderPaneBorder("󰒍 [4] Dependency Tree Path", m.chainVP.View(), wChain, bottomHeight, m.activePane == PaneChain)
		bottomRow := lipgloss.JoinHorizontal(lipgloss.Top, pReason, pDetail, pChain)

		grid := lipgloss.JoinVertical(lipgloss.Left, topRow, bottomRow)
		sections = append(sections, grid)
	}

	// 5. Status / Footer Bar
	if m.exportStatus != "" {
		sections = append(sections, m.styles.KeyHint.Render("󰄬 "+m.exportStatus))
	}

	footer := m.styles.StatusBar.Render(
		"[Tab] Focus Pane | [w/f] Maximize | [↑/↓/k/j] Navigate/Scroll | [1-5] View | [/] Search | [g] Group | [e] Export | [q] Quit",
	)
	sections = append(sections, footer)

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
			ID:            fmt.Sprintf("(%d items)", len(list)),
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
