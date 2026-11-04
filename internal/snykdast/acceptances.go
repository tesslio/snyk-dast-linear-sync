package snykdast

import (
	"context"
	"strings"
	"time"

	"github.com/tesslio/snyk-dast-linear-sync/internal/cache"
	"github.com/tesslio/snyk-dast-linear-sync/internal/model"
)

// revokedAcceptanceGrace is how long a remembered acceptance whose expiry is
// still ahead is kept after Snyk DAST stops reporting the finding as
// accepted, before the sync concludes the acceptance was revoked and forgets
// it. It covers a partial or stale API response. It never applies to a
// lapsed acceptance (expiry behind): Snyk DAST reverts the finding to
// `notfixed` once the acceptance expires and no longer reports the expiry,
// and the remembered row is then the only record of the date the due date is
// based on.
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
//     authoritative), and the expiry is the due-date base;
//   - a finding Snyk DAST reports as permanently accepted supersedes any
//     remembered time-limited acceptance, which is dropped;
//   - a finding no longer reported as accepted keeps a remembered expiry
//     that has lapsed for good: Snyk DAST reverted it to `notfixed` because
//     the acceptance ran out, and the expiry stays the due-date base;
//   - a finding no longer reported as accepted while the remembered expiry
//     is still ahead contradicts the memory: the acceptance was revoked (or
//     the finding was fixed or invalidated). The row is kept for
//     revokedAcceptanceGrace after Snyk DAST last confirmed it, so a partial
//     response does not move the due date, then dropped.
//
// The returned status is the one Snyk DAST's own state maps to; the memory
// only supplies the expiry, and remembered says when it did.
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
	case isAcceptedState(state) || !had:
		return status, time.Time{}, false
	}

	if !prev.ActiveUntil.After(now) {
		// Lapsed: the only record of the due-date base, kept for good.
		m.next[fingerprint] = prev
		return status, prev.ExpiresAt, true
	}
	if prev.ConfirmedAt.IsZero() {
		// Unknown confirmation time: the grace clock starts this run.
		prev.ConfirmedAt = now
		m.next[fingerprint] = prev
		return status, prev.ExpiresAt, true
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
