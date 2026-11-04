package snykdast

import (
	"context"
	"strings"
	"time"

	"github.com/tesslio/snyk-dast-linear-sync/internal/cache"
	"github.com/tesslio/snyk-dast-linear-sync/internal/model"
)

// revokedAcceptanceGrace is how long a remembered acceptance is kept after
// Snyk DAST first reports the finding as not accepted while the expiry is
// still ahead, before the sync concludes the acceptance was revoked and
// forgets it. It is measured from the last confirmation and covers a partial
// or stale API response. It never applies to a genuine lapse: Snyk DAST
// reverts the finding to `notfixed` once the acceptance expires and no longer
// reports the expiry, and the remembered row is then the only record of the
// date the due date is based on.
const revokedAcceptanceGrace = 7 * 24 * time.Hour

// AcceptanceStore is the cache the Snyk DAST loader remembers time-limited
// acceptances in, keyed by fingerprint.
type AcceptanceStore interface {
	cache.AcceptanceMemoryStore
	LoadAcceptances(context.Context) (map[string]cache.AcceptanceMeta, error)
	SaveAcceptances(context.Context, map[string]cache.AcceptanceMeta) error
}

// acceptanceMemory is what one run knows about time-limited acceptances: the
// rows the cache remembered at the start of the run, and the rows that
// survive once every finding Snyk DAST reports has been seen. Snyk DAST is
// authoritative, and the memory is only the sync's record of what it
// previously reported, so a row is dropped only when Snyk DAST contradicts
// it (see observe).
type acceptanceMemory struct {
	cached  map[string]cache.AcceptanceMeta
	next    map[string]cache.AcceptanceMeta
	seen    map[string]struct{}
	dropped []cache.AcceptanceMeta
	// malformed lists the fingerprints of findings reported as accepted with
	// an expiration_date that could not be parsed, for the commit log.
	malformed []string
}

func newAcceptanceMemory(cached map[string]cache.AcceptanceMeta) *acceptanceMemory {
	if cached == nil {
		cached = map[string]cache.AcceptanceMeta{}
	}
	return &acceptanceMemory{
		cached: cached,
		next:   make(map[string]cache.AcceptanceMeta, len(cached)),
		seen:   make(map[string]struct{}),
	}
}

// observe maps one finding's Snyk DAST state against the memory and decides
// what the cache remembers for it after this run:
//
//   - a finding Snyk DAST reports as accepted with an expiry replaces the
//     memory with that expiry (the latest report wins, since Snyk DAST is
//     authoritative), clears any earlier contradiction, and the expiry is
//     the due-date base;
//   - a finding Snyk DAST reports as accepted with no expiry at all (a
//     permanent acceptance) supersedes any remembered time-limited
//     acceptance, which is dropped;
//   - a finding reported as accepted with an expiry that cannot be parsed
//     says nothing usable: the remembered row is carried forward unchanged
//     (neither confirmed nor contradicted) and the case is logged;
//   - a finding no longer reported as accepted whose remembered expiry has
//     passed, with no contradiction before that, lapsed: Snyk DAST reverted
//     it to `notfixed` because the acceptance ran out, and the expiry stays
//     the due-date base for good;
//   - a finding no longer reported as accepted while the remembered expiry
//     is still ahead contradicts the memory: the acceptance was revoked (or
//     the finding was fixed or invalidated). The first such observation is
//     recorded durably, so the expiry passing later does not turn the
//     revocation into a lapse. The row is kept, and its expiry applied, for
//     revokedAcceptanceGrace after Snyk DAST last confirmed it, so a partial
//     response does not move the due date, then dropped.
//
// A finding missing from the response is never observed, so it is neither
// confirmed nor contradicted (see rows). The returned status is the one Snyk
// DAST's own state maps to; the memory only supplies the expiry, and
// remembered says when it did.
func (m *acceptanceMemory) observe(fingerprint, state string, expirationDate *string, now time.Time) (status model.FindingStatus, expires time.Time, remembered bool) {
	m.seen[fingerprint] = struct{}{}
	status, expires, activeUntil := mapStatus(state, expirationDate, now)
	prev, had := m.cached[fingerprint]
	switch {
	case !expires.IsZero():
		m.next[fingerprint] = cache.AcceptanceMeta{
			Fingerprint: fingerprint,
			ExpiresAt:   expires,
			ActiveUntil: activeUntil,
			ConfirmedAt: now,
		}
		return status, expires, false
	case isAcceptedState(state) && expirationDate != nil && strings.TrimSpace(*expirationDate) != "":
		// Accepted with a date the sync cannot read. Not a permanent
		// acceptance, and not a confirmation of what is remembered either.
		m.malformed = append(m.malformed, fingerprint)
		if !had {
			return status, time.Time{}, false
		}
		m.next[fingerprint] = prev
		return status, prev.ExpiresAt, true
	case isAcceptedState(state) || !had:
		return status, time.Time{}, false
	}

	if prev.ContradictedAt.IsZero() && !prev.ActiveUntil.After(now) {
		// Lapsed: the only record of the due-date base, kept for good.
		m.next[fingerprint] = prev
		return status, prev.ExpiresAt, true
	}
	// Contradicted: now, or on an earlier run. The stamp outlives the
	// expiry, so a revocation does not become a lapse once the date passes.
	if prev.ContradictedAt.IsZero() {
		prev.ContradictedAt = now
	}
	if prev.ConfirmedAt.IsZero() {
		// Unknown confirmation time: the grace clock starts this run.
		prev.ConfirmedAt = now
	}
	if now.Sub(prev.ConfirmedAt) >= revokedAcceptanceGrace {
		m.dropped = append(m.dropped, prev)
		return status, time.Time{}, false
	}
	m.next[fingerprint] = prev
	return status, prev.ExpiresAt, true
}

// rows returns what the cache holds after this run. A remembered acceptance
// for a finding the snapshot did not contain (its target was deleted, or the
// finding is otherwise gone) is kept as it was: Snyk DAST said nothing about
// it this run, and the row is inert while no finding reads it.
func (m *acceptanceMemory) rows() map[string]cache.AcceptanceMeta {
	for fingerprint, meta := range m.cached {
		if _, seen := m.seen[fingerprint]; !seen {
			m.next[fingerprint] = meta
		}
	}
	return m.next
}

func isAcceptedState(state string) bool {
	return strings.EqualFold(strings.TrimSpace(state), "accepted")
}
