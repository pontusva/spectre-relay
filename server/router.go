package server

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"nhooyr.io/websocket"

	"spectre-relay/model"
)

// Router routes authenticated client payloads to recipients.
// Rate limiting is per authenticated userID, decoupled from IP so that
// a single user behind NAT can't burn through a shared per-IP budget
// and so multiple users from one IP each get a full quota.
type Router struct {
	store          *Store
	maxMessageSize int
	ratePerMin     int
	rateMu         sync.Mutex
	rateAttempts   map[string][]time.Time
}

func NewRouter(store *Store, maxMessageSize, ratePerMin int) *Router {
	return &Router{
		store:          store,
		maxMessageSize: maxMessageSize,
		ratePerMin:     ratePerMin,
		rateAttempts:   make(map[string][]time.Time),
	}
}

func (r *Router) allow(userID string) bool {
	now := time.Now()
	r.rateMu.Lock()
	defer r.rateMu.Unlock()
	cutoff := now.Add(-time.Minute)
	xs := r.rateAttempts[userID]
	kept := xs[:0]
	for _, t := range xs {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= r.ratePerMin {
		r.rateAttempts[userID] = kept
		return false
	}
	kept = append(kept, now)
	r.rateAttempts[userID] = kept
	return true
}

// Route handles one inbound payload from an authenticated sender.
//
// SECURITY decisions on this path:
//   - Oversize payloads are dropped silently. The websocket SetReadLimit
//     already enforces this at the framing layer; this is defense in depth.
//   - Rate-limited senders have messages dropped silently — no signal that
//     they have crossed a threshold.
//   - Malformed JSON is dropped silently. No parser-error feedback.
//   - "Unknown" recipients are queued, not rejected. The relay CANNOT
//     distinguish "user never registered" from "user offline right now",
//     and surfacing that distinction to a sender would be a presence
//     oracle — an attacker could probe any UserID to learn who has ever
//     used the system. All recipients therefore look the same to the
//     sender: messages either go through, or appear to.
func (r *Router) Route(ctx context.Context, senderID string, payload []byte) {
	if len(payload) > r.maxMessageSize {
		return
	}
	if !r.allow(senderID) {
		return
	}

	// Try sealed first; that is the preferred wire form.
	var sealed model.SealedEnvelope
	if err := json.Unmarshal(payload, &sealed); err == nil &&
		sealed.RecipientID != "" && len(sealed.Ciphertext) > 0 {
		r.deliver(ctx, sealed.RecipientID, queuedMessage{Sealed: &sealed})
		return
	}
	var open model.OpenEnvelope
	if err := json.Unmarshal(payload, &open); err == nil &&
		open.RecipientID != "" && len(open.Ciphertext) > 0 {
		r.deliver(ctx, open.RecipientID, queuedMessage{Open: &open})
		return
	}
	// Drop silently.
}

func (r *Router) deliver(ctx context.Context, recipientID string, m queuedMessage) {
	conn, online := r.store.LookupClient(recipientID)
	if online {
		raw, err := marshalQueued(m)
		if err == nil {
			wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			werr := conn.Write(wctx, websocket.MessageText, raw)
			cancel()
			if werr == nil {
				return
			}
		}
		// Direct delivery failed (write error, slow client, etc.).
		// Fall through to enqueue so the message survives a flapping client.
	}
	r.store.Enqueue(recipientID, m)
}

// FlushQueue drains any persisted messages to a freshly-connected user.
// Called immediately after successful registration.
func (r *Router) FlushQueue(ctx context.Context, userID string, conn *websocket.Conn) {
	msgs := r.store.DrainQueue(userID)
	for i, m := range msgs {
		raw, err := marshalQueued(m)
		if err != nil {
			continue
		}
		wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		werr := conn.Write(wctx, websocket.MessageText, raw)
		cancel()
		if werr != nil {
			// Re-enqueue this message and everything after it; preserves
			// ordering by re-inserting in order.
			for _, leftover := range msgs[i:] {
				r.store.Enqueue(userID, leftover)
			}
			return
		}
	}
}

func marshalQueued(m queuedMessage) ([]byte, error) {
	if m.Sealed != nil {
		return json.Marshal(m.Sealed)
	}
	if m.Open != nil {
		return json.Marshal(m.Open)
	}
	return nil, errNoEnvelope
}

var errNoEnvelope = errString("no envelope")

type errString string

func (e errString) Error() string { return string(e) }
