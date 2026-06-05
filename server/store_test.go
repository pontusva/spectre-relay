package server

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"spectre-relay/model"
)

func TestStore_BasicEnqueueDrain(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "offline_queue.db")

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := NewStore(dbPath, 600, logger) // 10 min TTL
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer store.Stop()

	// 1. Verify key file was created
	keyPath := dbPath + keyFileSuffix
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatalf("Key file was not created: %v", err)
	}

	// 2. Enqueue a message for a namespaced recipient ID
	recipient := "alice@relay-a.com"
	msg := queuedMessage{
		Open: &model.OpenEnvelope{
			SenderID:    "bob@relay-b.com",
			RecipientID: recipient,
			Ciphertext:  []byte("hello world"),
			TimestampMS: time.Now().UnixMilli(),
			ID:          "msg-id-1",
		},
	}

	store.Enqueue(recipient, msg)

	if count := store.QueuedMessages(); count != 1 {
		t.Errorf("Expected 1 queued message, got %d", count)
	}

	// 3. Drain and verify content
	drained := store.DrainQueue(recipient)
	if len(drained) != 1 {
		t.Fatalf("Expected 1 drained message, got %d", len(drained))
	}

	retrieved := drained[0]
	if retrieved.Open == nil {
		t.Fatal("Retrieved message is missing Open envelope")
	}
	if retrieved.Open.SenderID != "bob@relay-b.com" {
		t.Errorf("Expected sender bob@relay-b.com, got %q", retrieved.Open.SenderID)
	}
	if string(retrieved.Open.Ciphertext) != "hello world" {
		t.Errorf("Expected ciphertext 'hello world', got %q", string(retrieved.Open.Ciphertext))
	}

	// 4. Verify queue is drained (empty)
	if count := store.QueuedMessages(); count != 0 {
		t.Errorf("Expected 0 queued messages after drain, got %d", count)
	}
}

func TestStore_CapPerRecipient(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "offline_queue.db")

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := NewStore(dbPath, 600, logger)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer store.Stop()

	recipient := "alice@relay-a.com"

	// Enqueue 505 messages
	for i := 0; i < 505; i++ {
		msg := queuedMessage{
			Open: &model.OpenEnvelope{
				SenderID:    "bob@relay-b.com",
				RecipientID: recipient,
				Ciphertext:  []byte("hello"),
				TimestampMS: time.Now().UnixMilli(),
				ID:          "msg-id",
			},
		}
		store.Enqueue(recipient, msg)
	}

	// Verify that the cap (500) was enforced
	drained := store.DrainQueue(recipient)
	if len(drained) != maxQueuePerRecipient {
		t.Errorf("Expected exactly %d messages (cap), got %d", maxQueuePerRecipient, len(drained))
	}
}

func TestStore_ExpirationAndPurge(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "offline_queue.db")

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	// Create store with 1 second TTL
	store, err := NewStore(dbPath, 1, logger)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer store.Stop()

	recipient := "alice@relay-a.com"
	msg := queuedMessage{
		Open: &model.OpenEnvelope{
			SenderID:    "bob@relay-b.com",
			RecipientID: recipient,
			Ciphertext:  []byte("hello"),
			TimestampMS: time.Now().UnixMilli(),
			ID:          "msg-id",
		},
	}

	store.Enqueue(recipient, msg)

	if count := store.QueuedMessages(); count != 1 {
		t.Fatalf("Expected 1 queued message initially, got %d", count)
	}

	// Sleep so message expires
	time.Sleep(2 * time.Second)

	// QueuedMessages should count only unexpired messages
	if count := store.QueuedMessages(); count != 0 {
		t.Errorf("Expected 0 unexpired messages, got %d", count)
	}

	// DrainQueue should return empty because it's expired
	drained := store.DrainQueue(recipient)
	if len(drained) != 0 {
		t.Errorf("Expected 0 drained messages after expiration, got %d", len(drained))
	}

	// Enqueue again and manually trigger purgeExpired
	store.Enqueue(recipient, msg)
	if count := store.QueuedMessages(); count != 1 {
		t.Fatalf("Expected 1 queued message initially, got %d", count)
	}

	time.Sleep(2 * time.Second)
	store.purgeExpired()

	// Verify that the row is physically deleted from the DB
	var rowCount int
	err = store.conn.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM queue").Scan(&rowCount)
	if err != nil {
		t.Fatalf("Failed to query DB row count: %v", err)
	}
	if rowCount != 0 {
		t.Errorf("Expected 0 physical rows in DB after purge, got %d", rowCount)
	}
}

func TestStore_KeyPersistenceAndReload(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "offline_queue.db")

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	// Create first store and enqueue a message
	store1, err := NewStore(dbPath, 600, logger)
	if err != nil {
		t.Fatalf("Failed to create store 1: %v", err)
	}
	recipient := "alice@relay-a.com"
	msg := queuedMessage{
		Open: &model.OpenEnvelope{
			SenderID:    "bob@relay-b.com",
			RecipientID: recipient,
			Ciphertext:  []byte("secret data"),
			TimestampMS: time.Now().UnixMilli(),
			ID:          "msg-id-1",
		},
	}
	store1.Enqueue(recipient, msg)
	store1.Stop()

	// Re-open the same DB with a second store instance
	store2, err := NewStore(dbPath, 600, logger)
	if err != nil {
		t.Fatalf("Failed to create store 2: %v", err)
	}
	defer store2.Stop()

	// Drain and verify that key was persistence-compatible and decrypted correctly
	drained := store2.DrainQueue(recipient)
	if len(drained) != 1 {
		t.Fatalf("Expected 1 drained message on reload, got %d", len(drained))
	}
	if string(drained[0].Open.Ciphertext) != "secret data" {
		t.Errorf("Expected 'secret data', got %q", string(drained[0].Open.Ciphertext))
	}
}
