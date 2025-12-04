package ui

import (
	"fmt"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ScanProgress tracks scanning progress
type ScanProgress struct {
	Current      int
	Total        int
	CurrentPkg   string
	CurrentVulns int
	Completed    bool
	Error        string
	StartTime    time.Time
}

// Model represents the TUI state
type Model struct {
	progress ScanProgress
	mu       sync.Mutex
}

// Init initializes the model
func (m Model) Init() tea.Cmd {
	return nil
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
	case DoneMsg:
		m.mu.Lock()
		m.progress.Completed = true
		m.mu.Unlock()
		return m, tea.Quit
	case ErrorMsg:
		m.mu.Lock()
		m.progress.Error = msg.Err
		m.mu.Unlock()
		return m, tea.Quit
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

	// Header
	s += lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("33")).
		Render("🔍 Vigil Scanning...\n\n")

	// Progress bar
	width := 40
	filled := 0
	if m.progress.Total > 0 {
		filled = (m.progress.Current * width) / m.progress.Total
	}

	bar := "["
	for i := 0; i < width; i++ {
		if i < filled {
			bar += "="
		} else {
			bar += " "
		}
	}
	bar += "]"

	s += bar + fmt.Sprintf(" %d/%d\n\n", m.progress.Current, m.progress.Total)

	// Current package
	if m.progress.CurrentPkg != "" {
		s += fmt.Sprintf("Current: %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Render(m.progress.CurrentPkg))
	}

	// Elapsed time
	elapsed := time.Since(m.progress.StartTime).Seconds()
	s += fmt.Sprintf("Elapsed: %.0fs\n", elapsed)

	// Vulnerabilities found
	if m.progress.CurrentVulns > 0 {
		s += fmt.Sprintf("Vulns found: %d\n", lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render(fmt.Sprint(m.progress.CurrentVulns)))
	}

	s += "\nPress q to quit"

	return s
}

func (m Model) renderCompleted() string {
	return lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("42")).
		Render("✓ Scan complete!\n")
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

type DoneMsg struct{}

type ErrorMsg struct {
	Err string
}

// NewModel creates a new model
func NewModel() Model {
	return Model{
		progress: ScanProgress{
			StartTime: time.Now(),
		},
	}
}
