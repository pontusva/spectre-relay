package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"nhooyr.io/websocket"

	"spectre-relay/model"
)

const (
	// Hard cap per recipient queue. 500 messages * 64KB = ~32MB max per user;
	// bounded memory prevents an attacker spamming one recipient to OOM the relay.
	maxQueuePerRecipient = 500

	// Suffix appended to the queue file path to derive the key file location.
	// Separate file so the encrypted queue can be backed up or audited
	// without exposing the key (defense in depth against operator mistakes).
	keyFileSuffix = ".key"
)

// queuedMessage is the on-disk envelope wrapper.
// Only one of Sealed/Open is populated per record — the relay never
// converts between forms, so a SealedEnvelope sent by Alice stays sealed
// in storage and on delivery.
type queuedMessage struct {
	Sealed    *model.SealedEnvelope `json:"sealed,omitempty"`
	Open      *model.OpenEnvelope   `json:"open,omitempty"`
	ExpiresAt int64                 `json:"expires_at"`
}

// Store owns the client registry and the offline queue.
// All public methods are safe for concurrent use.
type Store struct {
	mu        sync.RWMutex
	clients   map[string]*websocket.Conn
	queue     map[string][]queuedMessage
	queuePath string
	key       []byte
	ttl       time.Duration
	log       *slog.Logger
	stopCh    chan struct{}
}

// NewStore initializes (or restores) the persistent encrypted queue.
// On first run it generates a fresh AES-256 key and persists it next to
// the queue file with mode 0600.
func NewStore(queuePath string, ttlSeconds int64, log *slog.Logger) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(queuePath), 0o700); err != nil {
		return nil, err
	}
	key, err := loadOrCreateKey(queuePath + keyFileSuffix)
	if err != nil {
		return nil, err
	}
	s := &Store{
		clients:   make(map[string]*websocket.Conn),
		queue:     make(map[string][]queuedMessage),
		queuePath: queuePath,
		key:       key,
		ttl:       time.Duration(ttlSeconds) * time.Second,
		log:       log,
		stopCh:    make(chan struct{}),
	}
	if err := s.loadFromDisk(); err != nil {
		return nil, err
	}
	go s.purgeLoop()
	return s, nil
}

// Register binds userID to its current WebSocket connection.
// If a previous connection existed for the user, it is returned so the
// caller can close it — only one active session per user is supported.
func (s *Store) Register(userID string, c *websocket.Conn) (prev *websocket.Conn) {
	s.mu.Lock()
	prev = s.clients[userID]
	s.clients[userID] = c
	s.mu.Unlock()
	return prev
}

// Unregister removes userID's mapping only if it still points at c.
// Prevents a stale defer from unregistering a newer reconnect.
func (s *Store) Unregister(userID string, c *websocket.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.clients[userID] == c {
		delete(s.clients, userID)
	}
}

func (s *Store) LookupClient(userID string) (*websocket.Conn, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.clients[userID]
	return c, ok
}

// Enqueue persists a message for later delivery.
//
// SECURITY: silent drop on overflow. The relay does not signal the sender
// that the recipient queue is full because queue-full state is itself
// metadata that distinguishes one recipient from another.
func (s *Store) Enqueue(recipientID string, msg queuedMessage) {
	s.mu.Lock()
	defer s.mu.Unlock()

	q := s.queue[recipientID]

	// Drop expired entries at insertion to keep the cap meaningful.
	now := time.Now().Unix()
	live := q[:0]
	for _, m := range q {
		if m.ExpiresAt > now {
			live = append(live, m)
		}
	}
	q = live

	if len(q) >= maxQueuePerRecipient {
		s.queue[recipientID] = q
		return
	}
	msg.ExpiresAt = time.Now().Add(s.ttl).Unix()
	q = append(q, msg)
	s.queue[recipientID] = q

	if err := s.persistLocked(); err != nil {
		// Log only the error class — never the recipient ID or content.
		s.log.Error("queue persist failed", "err_type", classifyErr(err))
	}
}

// DrainQueue returns and removes all live (non-expired) messages for a user.
func (s *Store) DrainQueue(recipientID string) []queuedMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := s.queue[recipientID]
	now := time.Now().Unix()
	live := make([]queuedMessage, 0, len(q))
	for _, m := range q {
		if m.ExpiresAt > now {
			live = append(live, m)
		}
	}
	delete(s.queue, recipientID)
	if err := s.persistLocked(); err != nil {
		s.log.Error("queue persist failed", "err_type", classifyErr(err))
	}
	return live
}

// ConnectedClients is an ops metric: count only, no identifiers.
func (s *Store) ConnectedClients() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.clients)
}

// QueuedMessages is an ops metric: total across all users, no per-user data.
func (s *Store) QueuedMessages() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	total := 0
	for _, q := range s.queue {
		total += len(q)
	}
	return total
}

// Stop terminates the background purge goroutine. Call during shutdown.
func (s *Store) Stop() {
	select {
	case <-s.stopCh:
		// already closed
	default:
		close(s.stopCh)
	}
}

// purgeLoop runs every 5 minutes, removing expired entries.
// Persisted state is rewritten on each pass so a crash never leaves
// expired ciphertext lingering past its TTL on disk.
func (s *Store) purgeLoop() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-t.C:
			s.purgeExpired()
		}
	}
}

func (s *Store) purgeExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	for uid, q := range s.queue {
		live := q[:0]
		for _, m := range q {
			if m.ExpiresAt > now {
				live = append(live, m)
			}
		}
		if len(live) == 0 {
			delete(s.queue, uid)
		} else {
			s.queue[uid] = live
		}
	}
	if err := s.persistLocked(); err != nil {
		s.log.Error("queue persist failed", "err_type", classifyErr(err))
	}
}

// persistLocked encrypts the in-memory queue map and writes it to disk
// atomically. Caller MUST hold s.mu.
//
// Layout on disk: [12-byte GCM nonce][ciphertext||tag].
// Atomic write via tempfile + rename so a crash mid-write cannot
// produce a torn file that fails authentication on load.
func (s *Store) persistLocked() error {
	plaintext, err := json.Marshal(s.queue)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, nil)

	dir := filepath.Dir(s.queuePath)
	tmp, err := os.CreateTemp(dir, "queue-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(sealed); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, s.queuePath)
}

// loadFromDisk reads the encrypted queue file (if present) and restores
// only non-expired entries.
func (s *Store) loadFromDisk() error {
	data, err := os.ReadFile(s.queuePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(data) == 0 {
		return nil
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	if len(data) < gcm.NonceSize() {
		return errors.New("queue file truncated")
	}
	nonce, ct := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		// Authentication failure: refuse to start rather than serve
		// a possibly-tampered queue file.
		return errors.New("queue authentication failed")
	}
	var loaded map[string][]queuedMessage
	if err := json.Unmarshal(plain, &loaded); err != nil {
		return err
	}
	now := time.Now().Unix()
	for uid, q := range loaded {
		live := q[:0]
		for _, m := range q {
			if m.ExpiresAt > now {
				live = append(live, m)
			}
		}
		if len(live) > 0 {
			s.queue[uid] = live
		}
	}
	return nil
}

// loadOrCreateKey returns a 32-byte AES-256 key from `path`, generating a
// fresh one if no key file exists. Mode 0600. Length is validated strictly.
func loadOrCreateKey(path string) ([]byte, error) {
	if data, err := os.ReadFile(path); err == nil {
		if len(data) != 32 {
			return nil, errors.New("invalid key file length")
		}
		return data, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// classifyErr returns a coarse error class for logging — never the message.
func classifyErr(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, os.ErrNotExist) {
		return "not_exist"
	}
	if errors.Is(err, os.ErrPermission) {
		return "permission"
	}
	return "io"
}
