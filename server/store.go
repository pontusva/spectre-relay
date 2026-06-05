package server

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"nhooyr.io/websocket"
	_ "modernc.org/sqlite"

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
	db        *sql.DB
	conn      *sql.Conn
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
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)

	conn, err := db.Conn(context.Background())
	if err != nil {
		db.Close()
		return nil, err
	}

	s := &Store{
		clients:   make(map[string]*websocket.Conn),
		db:        db,
		conn:      conn,
		queuePath: queuePath,
		key:       key,
		ttl:       time.Duration(ttlSeconds) * time.Second,
		log:       log,
		stopCh:    make(chan struct{}),
	}

	if err := s.loadFromDisk(); err != nil {
		s.conn.Close()
		s.db.Close()
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

	ctx := context.Background()

	// Drop expired entries at insertion to keep the cap meaningful.
	_, err := s.conn.ExecContext(ctx, "DELETE FROM queue WHERE recipient_id = ? AND expires_at < unixepoch()", recipientID)
	if err != nil {
		s.log.Error("queue delete expired failed", "err_type", classifyErr(err))
		return
	}

	var count int
	err = s.conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM queue WHERE recipient_id = ?", recipientID).Scan(&count)
	if err != nil {
		s.log.Error("queue count failed", "err_type", classifyErr(err))
		return
	}

	if count >= maxQueuePerRecipient {
		return
	}

	msg.ExpiresAt = time.Now().Add(s.ttl).Unix()
	plaintext, err := json.Marshal(msg)
	if err != nil {
		s.log.Error("queue marshal failed", "err_type", classifyErr(err))
		return
	}

	ciphertext, err := s.encrypt(plaintext)
	if err != nil {
		s.log.Error("queue encrypt failed", "err_type", classifyErr(err))
		return
	}

	_, err = s.conn.ExecContext(ctx, "INSERT INTO queue (recipient_id, payload, expires_at) VALUES (?, ?, ?)", recipientID, ciphertext, msg.ExpiresAt)
	if err != nil {
		s.log.Error("queue insert failed", "err_type", classifyErr(err))
		return
	}

	if err := s.persistLocked(); err != nil {
		s.log.Error("queue persist failed", "err_type", classifyErr(err))
	}
}

// DrainQueue returns and removes all live (non-expired) messages for a user.
func (s *Store) DrainQueue(recipientID string) []queuedMessage {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := context.Background()

	tx, err := s.conn.BeginTx(ctx, nil)
	if err != nil {
		s.log.Error("queue tx begin failed", "err_type", classifyErr(err))
		return nil
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx, "SELECT payload, expires_at FROM queue WHERE recipient_id = ? ORDER BY id ASC", recipientID)
	if err != nil {
		s.log.Error("queue query failed", "err_type", classifyErr(err))
		return nil
	}
	defer rows.Close()

	now := time.Now().Unix()
	var messages []queuedMessage
	for rows.Next() {
		var ciphertext []byte
		var expiresAt int64
		if err := rows.Scan(&ciphertext, &expiresAt); err != nil {
			s.log.Error("queue scan failed", "err_type", classifyErr(err))
			continue
		}
		if expiresAt < now {
			continue
		}
		plaintext, err := s.decrypt(ciphertext)
		if err != nil {
			s.log.Error("queue decrypt failed", "err_type", classifyErr(err))
			continue
		}
		var msg queuedMessage
		if err := json.Unmarshal(plaintext, &msg); err != nil {
			s.log.Error("queue unmarshal failed", "err_type", classifyErr(err))
			continue
		}
		messages = append(messages, msg)
	}
	rows.Close()

	_, err = tx.ExecContext(ctx, "DELETE FROM queue WHERE recipient_id = ?", recipientID)
	if err != nil {
		s.log.Error("queue delete failed", "err_type", classifyErr(err))
		return nil
	}

	if err := tx.Commit(); err != nil {
		s.log.Error("queue commit failed", "err_type", classifyErr(err))
		return nil
	}

	if err := s.persistLocked(); err != nil {
		s.log.Error("queue persist failed", "err_type", classifyErr(err))
	}

	return messages
}

// ConnectedClients is an ops metric: count only, no identifiers.
func (s *Store) ConnectedClients() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.clients)
}

// QueuedMessages is an ops metric: total across all users, no per-user data.
func (s *Store) QueuedMessages() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	var total int
	err := s.conn.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM queue WHERE expires_at >= unixepoch()").Scan(&total)
	if err != nil {
		s.log.Error("queue count failed", "err_type", classifyErr(err))
		return 0
	}
	return total
}

// Stop terminates the background purge goroutine and closes the database connection.
func (s *Store) Stop() {
	select {
	case <-s.stopCh:
		// already closed
	default:
		close(s.stopCh)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		s.conn.Close()
	}
	if s.db != nil {
		s.db.Close()
	}
}

// purgeLoop runs every 5 minutes, removing expired entries.
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
	_, err := s.conn.ExecContext(context.Background(), "DELETE FROM queue WHERE expires_at < unixepoch()")
	if err != nil {
		s.log.Error("queue purge failed", "err_type", classifyErr(err))
		return
	}
	if err := s.persistLocked(); err != nil {
		s.log.Error("queue persist failed", "err_type", classifyErr(err))
	}
}

func (s *Store) encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (s *Store) decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

func (s *Store) loadFromDisk() error {
	data, err := os.ReadFile(s.queuePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s.initSchema()
		}
		return err
	}
	if len(data) == 0 {
		return s.initSchema()
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
		return errors.New("queue authentication failed")
	}

	err = s.conn.Raw(func(driverConn interface{}) error {
		return deserializeDB(driverConn, plain)
	})
	if err != nil {
		return err
	}

	return nil
}

func (s *Store) initSchema() error {
	_, err := s.conn.ExecContext(context.Background(), `
		CREATE TABLE IF NOT EXISTS queue (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			recipient_id TEXT NOT NULL,
			payload BLOB NOT NULL,
			expires_at INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_queue_recipient_expires ON queue (recipient_id, expires_at);
		CREATE INDEX IF NOT EXISTS idx_queue_expires ON queue (expires_at);
	`)
	if err != nil {
		return err
	}
	return s.persistLocked()
}

func (s *Store) persistLocked() error {
	var plain []byte
	err := s.conn.Raw(func(driverConn interface{}) error {
		var err error
		plain, err = serializeDB(driverConn)
		return err
	})
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
	sealed := gcm.Seal(nonce, nonce, plain, nil)

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

func serializeDB(driverConn interface{}) ([]byte, error) {
	val := reflect.ValueOf(driverConn)
	method := val.MethodByName("Serialize")
	if !method.IsValid() {
		return nil, errors.New("Serialize method not found on driver connection")
	}
	results := method.Call(nil)
	if len(results) != 2 {
		return nil, errors.New("unexpected number of return values from Serialize")
	}
	if !results[1].IsNil() {
		return nil, results[1].Interface().(error)
	}
	return results[0].Bytes(), nil
}

func deserializeDB(driverConn interface{}, data []byte) error {
	val := reflect.ValueOf(driverConn)
	method := val.MethodByName("Deserialize")
	if !method.IsValid() {
		return errors.New("Deserialize method not found on driver connection")
	}
	results := method.Call([]reflect.Value{reflect.ValueOf(data)})
	if len(results) != 1 {
		return errors.New("unexpected number of return values from Deserialize")
	}
	if !results[0].IsNil() {
		return results[0].Interface().(error)
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
