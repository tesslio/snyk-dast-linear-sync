package cache

import "context"

// AcceptanceMemoryStateKey distinguishes an untrusted first load from an
// explicitly trusted empty memory. It is written before any loader can seed
// acceptance rows, so a load that fails after seeding some rows still leaves
// evidence that the memory began empty.
const AcceptanceMemoryStateKey = "acceptances_memory_state"

// AcceptanceMemoryTrusted is the AcceptanceMemoryStateKey value recorded once
// the memory is known to be complete: after a successful run that found
// nothing to protect, or when an operator clears the cold-start guard.
const AcceptanceMemoryTrusted = "trusted"

const acceptanceMemoryPending = "pending"

// AcceptanceMemoryStore is the part of the cache the cold-start guard reads
// and writes. Both the sync and the Snyk DAST loader use it.
type AcceptanceMemoryStore interface {
	GetMeta(context.Context, string) (string, bool, error)
	SetMeta(context.Context, string, string) error
	HasAcceptanceRows(context.Context) (bool, error)
}

// PrepareAcceptanceMemory records whether the acceptance memory began empty
// and reports it. The pending state persists across failed loads, including
// diagnostic loads that populate the memory outside Service.Run, until a
// successful run or an operator marks the memory trusted.
func PrepareAcceptanceMemory(ctx context.Context, store AcceptanceMemoryStore) (pending bool, err error) {
	state, ok, err := store.GetMeta(ctx, AcceptanceMemoryStateKey)
	if err != nil {
		return false, err
	}
	if ok {
		return state != AcceptanceMemoryTrusted, nil
	}
	present, err := store.HasAcceptanceRows(ctx)
	if err != nil {
		return false, err
	}
	state = AcceptanceMemoryTrusted
	if !present {
		state = acceptanceMemoryPending
	}
	if err := store.SetMeta(ctx, AcceptanceMemoryStateKey, state); err != nil {
		return false, err
	}
	return !present, nil
}
