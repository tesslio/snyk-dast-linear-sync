package sync

import (
	"time"

	"github.com/tesslio/snyk-dast-linear-sync/internal/config"
	"github.com/tesslio/snyk-dast-linear-sync/internal/model"
)

// DueDateScenario describes one possible due date computation for a finding.
type DueDateScenario struct {
	Name    string `json:"name"`
	DueDate string `json:"due_date"`
	Base    string `json:"base"`
	Reason  string `json:"reason"`
}

// DiagnoseOptions carries the run-level state the diagnostic needs to report
// what the sync would actually write, beyond the finding and the ticket.
type DiagnoseOptions struct {
	// ColdStartGuardActive is set when the cache holds the cold-start marker
	// (AcceptancesColdStartMetaKey): the sync then keeps an open ticket's due
	// date when the desired one is earlier.
	ColdStartGuardActive bool
	// ColdStartSince is the marker's value, for display.
	ColdStartSince string
}

// DueDateDiagnostics contains the full picture for a single managed issue and
// its matching Snyk DAST finding.
type DueDateDiagnostics struct {
	Finding  model.Finding       `json:"finding"`
	Existing model.ExistingIssue `json:"existing"`
	// Desired is what the sync would write, cold-start guard applied.
	Desired     model.DesiredIssue `json:"desired"`
	Diff        *model.IssueDiff   `json:"diff"`
	WouldUpdate bool               `json:"would_update"`
	// ColdStartGuardActive mirrors the option; DueDateHeldByColdStart is set
	// when the guard kept the existing due date, and UnguardedDueDate is the
	// date the SLA alone would give, with its reason.
	ColdStartGuardActive      bool              `json:"cold_start_guard_active"`
	ColdStartSince            string            `json:"cold_start_since,omitempty"`
	DueDateHeldByColdStart    bool              `json:"due_date_held_by_cold_start"`
	UnguardedDueDate          string            `json:"unguarded_due_date"`
	UnguardedDueDateReason    string            `json:"unguarded_due_date_reason"`
	Scenarios                 []DueDateScenario `json:"scenarios"`
	SnoozedScenario           DueDateScenario   `json:"snoozed_scenario"`
	WasSnoozed                bool              `json:"was_snoozed"`
	SnykHash                  string            `json:"snyk_dast_hash"`
	LinearHash                string            `json:"linear_hash"`
	PendingTerminalTransition bool              `json:"pending_terminal_transition"`
}

// DiagnoseDueDate computes the desired issue, the diff against the existing
// Linear issue, and every plausible due date scenario for a single finding.
func DiagnoseDueDate(cfg config.Config, finding model.Finding, existing model.ExistingIssue, opts DiagnoseOptions) DueDateDiagnostics {
	desired := desiredIssue(cfg, finding)
	unguardedDueDate, unguardedReason := desired.DueDate, desired.DueDateReason
	held := false
	if opts.ColdStartGuardActive {
		held = holdDueDate(existing, &desired, cfg.Linear.States)
	}
	diff := ComputeDiff(existing, desired)
	snoozedDueDate, snoozedBase, snoozedReason := issueDueDateFromAcceptanceExpiry(cfg.Linear.Due, finding)

	scenarios := make([]DueDateScenario, 0, 2)
	if creationDueDate, creationBase, creationReason := issueDueDateFromCreatedAt(cfg.Linear.Due, finding); creationDueDate != "" {
		scenarios = append(scenarios, DueDateScenario{
			Name:    "finding creation (CreatedAt + severity SLA)",
			DueDate: creationDueDate,
			Base:    creationBase,
			Reason:  creationReason,
		})
	}
	if ignoreExpiryDueDate, ignoreExpiryBase, ignoreExpiryReason := issueDueDateFromAcceptanceExpiry(cfg.Linear.Due, finding); ignoreExpiryDueDate != "" {
		scenarios = append(scenarios, DueDateScenario{
			Name:    "acceptance expiry (IgnoreExpiresAt + severity SLA)",
			DueDate: ignoreExpiryDueDate,
			Base:    ignoreExpiryBase,
			Reason:  ignoreExpiryReason,
		})
	}

	return DueDateDiagnostics{
		Finding:                   finding,
		Existing:                  existing,
		Desired:                   desired,
		Diff:                      diff,
		WouldUpdate:               needsUpdate(existing, desired),
		ColdStartGuardActive:      opts.ColdStartGuardActive,
		ColdStartSince:            opts.ColdStartSince,
		DueDateHeldByColdStart:    held,
		UnguardedDueDate:          unguardedDueDate,
		UnguardedDueDateReason:    unguardedReason,
		WasSnoozed:                finding.Status == model.FindingSnoozed,
		SnoozedScenario:           dueDateScenario("acceptance expiry (IgnoreExpiresAt + severity SLA)", snoozedDueDate, snoozedBase, snoozedReason),
		Scenarios:                 scenarios,
		SnykHash:                  desiredIssueHash(desired),
		LinearHash:                existingIssueHash(existing),
		PendingTerminalTransition: pendingTerminalTransition(existing, desired),
	}
}

func dueDateScenario(name, dueDate, base, reason string) DueDateScenario {
	return DueDateScenario{
		Name:    name,
		DueDate: dueDate,
		Base:    base,
		Reason:  reason,
	}
}

func issueDueDateFromCreatedAt(dueCfg config.DueDateConfig, finding model.Finding) (string, string, string) {
	if finding.CreatedAt.IsZero() {
		return "", "", ""
	}
	createdAtUTC := finding.CreatedAt.UTC()
	baseDate := time.Date(createdAtUTC.Year(), createdAtUTC.Month(), createdAtUTC.Day(), 0, 0, 0, 0, time.UTC)
	return dueDateFromBase(baseDate, "finding creation", dueCfg, finding)
}

func issueDueDateFromAcceptanceExpiry(dueCfg config.DueDateConfig, finding model.Finding) (string, string, string) {
	if finding.IgnoreExpiresAt.IsZero() {
		return "", "", ""
	}
	expiresUTC := finding.IgnoreExpiresAt.UTC()
	baseDate := time.Date(expiresUTC.Year(), expiresUTC.Month(), expiresUTC.Day(), 0, 0, 0, 0, time.UTC)
	return dueDateFromBase(baseDate, "acceptance expiry", dueCfg, finding)
}
