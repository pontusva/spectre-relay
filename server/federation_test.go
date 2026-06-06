package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"spectre-relay/config"
	"spectre-relay/model"
)

func TestFederation_OutboundRouting(t *testing.T) {
	// 1. Set up a mock HTTP server to act as the remote relay
	var receivedBody []byte
	var receivedContentType string
	var receivedRelayID string
	remoteServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/federation/deliver" && r.Method == http.MethodPost {
			receivedContentType = r.Header.Get("Content-Type")
			receivedRelayID = r.Header.Get("X-Spectre-Relay-ID")
			var err error
			receivedBody, err = io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("Failed to read body: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer remoteServer.Close()

	// Parse host:port from mock server URL
	u, err := url.Parse(remoteServer.URL)
	if err != nil {
		t.Fatalf("Failed to parse mock server URL: %v", err)
	}
	remoteHostPort := u.Host // e.g. "127.0.0.1:49382"

	// 2. Set up local Store and Router on relay-a
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "offline_queue.db")
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := NewStore(dbPath, 60, logger)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer store.Stop()

	// NewRouter on relay-a
	router := NewRouter(store, 65536, 60, "relay-a")

	// 3. Test forwarding a SealedEnvelope to remote host
	recipient := "bob@" + remoteHostPort
	sealedMsg := queuedMessage{
		Sealed: &model.SealedEnvelope{
			RecipientID: recipient,
			Ciphertext:  []byte("secret remote payload"),
			ID:          "msg-id-1",
		},
	}

	router.deliver(context.Background(), recipient, sealedMsg)

	// Since forwarding runs in a background goroutine, sleep shortly to allow it to finish
	time.Sleep(100 * time.Millisecond)
	time.Sleep(200 * time.Millisecond)

	if receivedContentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %q", receivedContentType)
	}

	if receivedRelayID != "relay-a" {
		t.Errorf("Expected X-Spectre-Relay-ID 'relay-a', got %q", receivedRelayID)
	}

	var parsedSealed model.SealedEnvelope
	if err := json.Unmarshal(receivedBody, &parsedSealed); err != nil {
		t.Fatalf("Failed to unmarshal forwarded JSON: %v", err)
	}
	if parsedSealed.RecipientID != recipient {
		t.Errorf("Expected recipient %q, got %q", recipient, parsedSealed.RecipientID)
	}
	if string(parsedSealed.Ciphertext) != "secret remote payload" {
		t.Errorf("Expected ciphertext 'secret remote payload', got %q", string(parsedSealed.Ciphertext))
	}

	// Reset received variables
	receivedBody = nil
	receivedContentType = ""
	receivedRelayID = ""

	// 4. Test that OpenEnvelope is NOT forwarded to remote host
	openMsg := queuedMessage{
		Open: &model.OpenEnvelope{
			SenderID:    "alice",
			RecipientID: recipient,
			Ciphertext:  []byte("open payload"),
			ID:          "msg-id-2",
		},
	}

	router.deliver(context.Background(), recipient, openMsg)
	time.Sleep(100 * time.Millisecond)

	if len(receivedBody) != 0 {
		t.Errorf("Expected OpenEnvelope to be dropped silently, but received POST: %s", string(receivedBody))
	}
}

func TestFederation_LocalNormalization(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "offline_queue.db")
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := NewStore(dbPath, 60, logger)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer store.Stop()

	// Local relay-id is relay-a
	router := NewRouter(store, 65536, 60, "relay-a")

	// Deliver local namespaced message
	recipient := "alice@relay-a"
	sealedMsg := queuedMessage{
		Sealed: &model.SealedEnvelope{
			RecipientID: recipient,
			Ciphertext:  []byte("local secret"),
			ID:          "msg-id-1",
		},
	}

	router.deliver(context.Background(), recipient, sealedMsg)

	// Verify it was enqueued under the normalized ID "alice" (stripping @relay-a)
	drained := store.DrainQueue("alice")
	if len(drained) != 1 {
		t.Fatalf("Expected 1 message enqueued for local normalized ID 'alice', got %d", len(drained))
	}
	if string(drained[0].Sealed.Ciphertext) != "local secret" {
		t.Errorf("Expected 'local secret', got %q", string(drained[0].Sealed.Ciphertext))
	}
}

func TestFederation_LocalNormalization_WithPorts(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "offline_queue.db")
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	store, err := NewStore(dbPath, 60, logger)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer store.Stop()

	// Local relay-id contains a port
	router := NewRouter(store, 65536, 60, "relay-a:8080")

	// Test 1: Deliver to recipient with a matching host and matching port
	recipient1 := "alice@relay-a:8080"
	sealedMsg1 := queuedMessage{
		Sealed: &model.SealedEnvelope{
			RecipientID: recipient1,
			Ciphertext:  []byte("local secret 1"),
			ID:          "msg-id-1",
		},
	}
	router.deliver(context.Background(), recipient1, sealedMsg1)

	// Test 2: Deliver to recipient with a matching host but no port
	recipient2 := "bob@relay-a"
	sealedMsg2 := queuedMessage{
		Sealed: &model.SealedEnvelope{
			RecipientID: recipient2,
			Ciphertext:  []byte("local secret 2"),
			ID:          "msg-id-2",
		},
	}
	router.deliver(context.Background(), recipient2, sealedMsg2)

	// Verify both were normalized to their local usernames
	drainedAlice := store.DrainQueue("alice")
	if len(drainedAlice) != 1 {
		t.Fatalf("Expected 1 message enqueued for 'alice', got %d", len(drainedAlice))
	}
	if string(drainedAlice[0].Sealed.Ciphertext) != "local secret 1" {
		t.Errorf("Expected 'local secret 1', got %q", string(drainedAlice[0].Sealed.Ciphertext))
	}

	drainedBob := store.DrainQueue("bob")
	if len(drainedBob) != 1 {
		t.Fatalf("Expected 1 message enqueued for 'bob', got %d", len(drainedBob))
	}
	if string(drainedBob[0].Sealed.Ciphertext) != "local secret 2" {
		t.Errorf("Expected 'local secret 2', got %q", string(drainedBob[0].Sealed.Ciphertext))
	}
}


func TestFederation_ReceiveEndpoint(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "offline_queue.db")
	prekeyPath := filepath.Join(dir, "prekeys.db")
	caPath := filepath.Join(dir, "ca.key")

	cfg := &config.Config{
		ListenAddr:       ":8080",
		OfflineQueuePath: dbPath,
		PrekeyStorePath:  prekeyPath,
		SealedCAPath:     caPath,
		DevMode:          true,
		RelayID:          "relay-a",
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	srv, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("Failed to initialize server: %v", err)
	}
	defer srv.store.Stop()

	// Mock endpoint handler call
	// 1. Valid local recipient
	reqBody, _ := json.Marshal(model.SealedEnvelope{
		RecipientID: "alice@relay-a",
		Ciphertext:  []byte("hello alice"),
		ID:          "msg-1",
	})
	req := httptest.NewRequest(http.MethodPost, "/federation/deliver", bytes.NewReader(reqBody))
	req.Header.Set("X-Spectre-Relay-ID", "relay-b")
	rec := httptest.NewRecorder()

	srv.handleFederationDeliver(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("Expected HTTP 204, got %d", rec.Code)
	}

	// Verify enqueued locally (normalized to "alice")
	drained := srv.store.DrainQueue("alice")
	if len(drained) != 1 {
		t.Fatalf("Expected 1 message for alice, got %d", len(drained))
	}
	if drained[0].Sealed.RecipientID != "alice@relay-a" {
		t.Errorf("Expected RecipientID 'alice@relay-a', got %q", drained[0].Sealed.RecipientID)
	}
	if drained[0].Sealed.FederationSenderRelay != "relay-b" {
		t.Errorf("Expected FederationSenderRelay 'relay-b', got %q", drained[0].Sealed.FederationSenderRelay)
	}

	// 1b. Missing header (must return 204 and not enqueue)
	reqBodyNoHeader, _ := json.Marshal(model.SealedEnvelope{
		RecipientID: "charlie@relay-a",
		Ciphertext:  []byte("hello charlie"),
		ID:          "msg-no-header",
	})
	reqNoHeader := httptest.NewRequest(http.MethodPost, "/federation/deliver", bytes.NewReader(reqBodyNoHeader))
	recNoHeader := httptest.NewRecorder()

	srv.handleFederationDeliver(recNoHeader, reqNoHeader)

	if recNoHeader.Code != http.StatusNoContent {
		t.Errorf("Expected HTTP 204, got %d", recNoHeader.Code)
	}

	drainedCharlie := srv.store.DrainQueue("charlie")
	if len(drainedCharlie) != 0 {
		t.Errorf("Expected 0 messages for charlie, got %d", len(drainedCharlie))
	}

	// 1c. Empty header (must return 204 and not enqueue)
	reqBodyEmptyHeader, _ := json.Marshal(model.SealedEnvelope{
		RecipientID: "charlie@relay-a",
		Ciphertext:  []byte("hello charlie"),
		ID:          "msg-empty-header",
	})
	reqEmptyHeader := httptest.NewRequest(http.MethodPost, "/federation/deliver", bytes.NewReader(reqBodyEmptyHeader))
	reqEmptyHeader.Header.Set("X-Spectre-Relay-ID", "")
	recEmptyHeader := httptest.NewRecorder()

	srv.handleFederationDeliver(recEmptyHeader, reqEmptyHeader)

	if recEmptyHeader.Code != http.StatusNoContent {
		t.Errorf("Expected HTTP 204, got %d", recEmptyHeader.Code)
	}

	drainedCharlie2 := srv.store.DrainQueue("charlie")
	if len(drainedCharlie2) != 0 {
		t.Errorf("Expected 0 messages for charlie, got %d", len(drainedCharlie2))
	}

	// 2. Reject remote recipient (drop silently with 204)
	reqBodyRemote, _ := json.Marshal(model.SealedEnvelope{
		RecipientID: "bob@relay-b",
		Ciphertext:  []byte("hello bob"),
		ID:          "msg-2",
	})
	reqRemote := httptest.NewRequest(http.MethodPost, "/federation/deliver", bytes.NewReader(reqBodyRemote))
	reqRemote.Header.Set("X-Spectre-Relay-ID", "relay-b")
	recRemote := httptest.NewRecorder()

	srv.handleFederationDeliver(recRemote, reqRemote)

	if recRemote.Code != http.StatusNoContent {
		t.Errorf("Expected HTTP 204, got %d", recRemote.Code)
	}

	// Verify NOT enqueued locally
	drainedRemote := srv.store.DrainQueue("bob")
	if len(drainedRemote) != 0 {
		t.Errorf("Expected 0 messages for bob, got %d", len(drainedRemote))
	}
}
