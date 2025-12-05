package report

import (
	"github.com/guttenbergovitz/vigil-cli/internal/types"
)

// RecommendedAction represents the recommended remediation action
type RecommendedAction string

const (
	ActionImmediateHotfix    RecommendedAction = "Immediate hotfix"
	ActionUpgradeNextRelease RecommendedAction = "Upgrade in next release"
	ActionInfraMitigation    RecommendedAction = "Infra mitigation required"
	ActionMonitoringOnly     RecommendedAction = "Monitoring only"
	ActionRiskAcceptance     RecommendedAction = "Risk acceptance candidate"
)

// DetermineRecommendedAction determines the recommended action for a vulnerability
func DetermineRecommendedAction(
	vuln types.Vulnerability,
	depType types.DependencyType,
	exploitType ExploitType,
	exploitability RuntimeExploitability,
) RecommendedAction {
	isProduction := depType == types.Production
	severity := vuln.Severity

	// CRITICAL in production always requires immediate hotfix
	if severity == types.Critical && isProduction {
		return ActionImmediateHotfix
	}

	// HIGH in production with high exploitability requires immediate hotfix
	if severity == types.High && isProduction && exploitability == ExploitableYes {
		return ActionImmediateHotfix
	}

	// HIGH in production with conditional exploitability can wait for next release
	if severity == types.High && isProduction {
		return ActionUpgradeNextRelease
	}

	// MEDIUM in production should be upgraded in next release
	if severity == types.Medium && isProduction {
		return ActionUpgradeNextRelease
	}

	// RCE/Injection even in dev should be fixed
	if (exploitType == ExploitRCE || exploitType == ExploitInjection) && severity >= types.Medium {
		return ActionUpgradeNextRelease
	}

	// Dev-only or LOW severity can be monitored
	if !isProduction || severity == types.Low {
		if exploitability == ExploitableYes && (exploitType == ExploitRCE || exploitType == ExploitInjection) {
			return ActionMonitoringOnly
		}
		return ActionRiskAcceptance
	}

	// Default to upgrade in next release
	return ActionUpgradeNextRelease
}
