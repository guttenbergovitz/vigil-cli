package types

// SeverityMap maps string severity names to Severity type.
var SeverityMap = map[string]Severity{
	"low":      Low,
	"medium":   Medium,
	"high":     High,
	"critical": Critical,
}

// SeverityRank provides ordering for severity comparison.
var SeverityRank = map[Severity]int{
	Low:      1,
	Medium:   2,
	High:     3,
	Critical: 4,
}

// ParseSeverity parses a string into a Severity value.
func ParseSeverity(s string) (Severity, bool) {
	sev, ok := SeverityMap[s]
	return sev, ok
}

// HigherOrEqualThan returns true if this severity is >= the given severity.
func (s Severity) HigherOrEqualThan(min Severity) bool {
	return SeverityRank[s] >= SeverityRank[min]
}
