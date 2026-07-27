package ui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Styles holds predefined Lipgloss styles for Vigil Fullscreen TUI.
type Styles struct {
	Header           lipgloss.Style
	Title            lipgloss.Style
	Subtitle         lipgloss.Style
	ActiveTab        lipgloss.Style
	InactiveTab      lipgloss.Style
	TabGap           lipgloss.Style
	FilterBar        lipgloss.Style
	StatusBar        lipgloss.Style
	KeyHint          lipgloss.Style
	Card             lipgloss.Style
	BadgeCritical    lipgloss.Style
	BadgeHigh        lipgloss.Style
	BadgeMedium      lipgloss.Style
	BadgeLow         lipgloss.Style
	BadgeUnknown     lipgloss.Style
	BadgeSecret      lipgloss.Style
	BadgeIaC         lipgloss.Style
	ChainTree        lipgloss.Style
	ChainNode        lipgloss.Style
	ChainTarget      lipgloss.Style
	SearchPrompt     lipgloss.Style
	SelectedRow      lipgloss.Style
	DetailPanel      lipgloss.Style
	ModalBox         lipgloss.Style
	ReasonBox        lipgloss.Style
}

// DefaultStyles returns modern, high-contrast Lipgloss styles for Vigil TUI.
func DefaultStyles() Styles {
	return Styles{
		Header: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#F8F8F2")).
			Background(lipgloss.Color("#BD93F9")).
			Padding(0, 1),

		Title: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#BD93F9")),

		Subtitle: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6272A4")),

		ActiveTab: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#F8F8F2")).
			Background(lipgloss.Color("#6272A4")).
			Padding(0, 2),

		InactiveTab: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6272A4")).
			Background(lipgloss.Color("#282A36")).
			Padding(0, 2),

		TabGap: lipgloss.NewStyle().
			Background(lipgloss.Color("#282A36")),

		FilterBar: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F8F8F2")).
			Background(lipgloss.Color("#44475A")).
			Padding(0, 1),

		StatusBar: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F8F8F2")).
			Background(lipgloss.Color("#282A36")).
			Padding(0, 1),

		KeyHint: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#50FA7B")),

		Card: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#6272A4")).
			Padding(1, 2),

		BadgeCritical: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#FF5555")).
			Padding(0, 1),

		BadgeHigh: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#282A36")).
			Background(lipgloss.Color("#FFB86C")).
			Padding(0, 1),

		BadgeMedium: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#282A36")).
			Background(lipgloss.Color("#F1FA8C")).
			Padding(0, 1),

		BadgeLow: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#282A36")).
			Background(lipgloss.Color("#8BE9FD")).
			Padding(0, 1),

		BadgeUnknown: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F8F8F2")).
			Background(lipgloss.Color("#6272A4")).
			Padding(0, 1),

		BadgeSecret: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#282A36")).
			Background(lipgloss.Color("#FF79C6")).
			Padding(0, 1),

		BadgeIaC: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#282A36")).
			Background(lipgloss.Color("#8BE9FD")).
			Padding(0, 1),

		ChainTree: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#BD93F9")),

		ChainNode: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F8F8F2")),

		ChainTarget: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FF5555")),

		SearchPrompt: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#50FA7B")),

		SelectedRow: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#F8F8F2")).
			Background(lipgloss.Color("#44475A")),

		DetailPanel: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#BD93F9")).
			Padding(1, 2),

		ModalBox: lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(lipgloss.Color("#50FA7B")).
			Background(lipgloss.Color("#282A36")).
			Padding(1, 3),

		ReasonBox: lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("#FFB86C")).
			Padding(0, 1),
	}
}

// RenderSeverityBadge returns a colored Lipgloss badge for severity string with Nerd Fonts icon.
func RenderSeverityBadge(sev string, s Styles) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return s.BadgeCritical.Render("󰅚 CRITICAL")
	case "high":
		return s.BadgeHigh.Render("󰀦 HIGH")
	case "medium":
		return s.BadgeMedium.Render("󰀦 MEDIUM")
	case "low":
		return s.BadgeLow.Render("󰌵 LOW")
	case "secret":
		return s.BadgeSecret.Render("󰌆 SECRET")
	case "iac":
		return s.BadgeIaC.Render("󰒍 IAC ISSUE")
	default:
		return s.BadgeUnknown.Render("UNKNOWN")
	}
}

// RenderPaneBorder creates a dynamically sized panel box with active/inactive highlights and title.
func RenderPaneBorder(title string, content string, width, height int, isActive bool) string {
	if width < 10 {
		width = 10
	}
	if height < 3 {
		height = 3
	}

	borderColor := "#6272A4"
	titleColor := "#8BE9FD"
	if isActive {
		borderColor = "#BD93F9"
		titleColor = "#50FA7B"
	}

	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(borderColor)).
		Width(width - 2).
		Height(height - 2)

	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color(titleColor))

	header := titleStyle.Render(" " + title + " ")
	return boxStyle.Render(header + "\n" + content)
}
