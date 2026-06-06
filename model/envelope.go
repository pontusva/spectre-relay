package model

// SealedEnvelope carries a recipient-encrypted payload with the sender hidden
// from the relay entirely.
//
// NOTE: SenderID is intentionally absent at the type level — not nullable,
// not "" empty-string, just gone. Making this a compile-time constraint means
// no code path in the relay can ever accidentally log or inspect the sender
// of a sealed envelope. Metadata resistance is a goal, not a setting.
type SealedEnvelope struct {
	RecipientID string `json:"recipient_id"`
	Ciphertext  []byte `json:"ciphertext"`
	TimestampMS int64  `json:"timestamp_ms"`
	// ID is the SHA-256 hex of Ciphertext, used for relay-side dedup only.
	ID string `json:"id"`

	// FederationSenderRelay is set by the receiving relay when a message
	// arrives via the /federation/deliver endpoint. It tells the recipient
	// client which relay the sender is registered on, so replies can be
	// routed correctly. Never set by clients — relay-only metadata.
	// Empty for local (non-federated) messages.
	FederationSenderRelay string `json:"federation_sender_relay,omitempty"`
}

// OpenEnvelope is the alternative wire form where the sender is disclosed.
// Use only in flows that explicitly require sender attribution; SealedEnvelope
// is preferred for everything else.
type OpenEnvelope struct {
	SenderID    string `json:"sender_id"`
	RecipientID string `json:"recipient_id"`
	Ciphertext  []byte `json:"ciphertext"`
	TimestampMS int64  `json:"timestamp_ms"`
	ID          string `json:"id"`
}

// Challenge is the server-issued random nonce the client must sign with its
// ed25519 identity key during the auth handshake.
type Challenge struct {
	Nonce []byte `json:"nonce"`
}

// AuthRequest is the client's response to a Challenge.
// All fields are base64-encoded; the server decodes and verifies the signature
// over the raw 32-byte nonce.
type AuthRequest struct {
	UserID            string `json:"user_id"`
	IdentityPublicKey string `json:"identity_public_key"`
	Signature         string `json:"signature"`
}

// AuthResponse never carries detailed errors. The Error field exists for the
// rare case of a generic protocol-level failure response, but in practice
// failed handshakes close the connection silently — sending a body would
// be a side channel for user enumeration / oracle attacks.
// `omitempty` is intentionally absent on Success: the client must always see
// an explicit boolean and never infer success from an absent field.
type AuthResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
}
