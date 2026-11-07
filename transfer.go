package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verify/document"
)

const (
	nonceLifetime = 2 * time.Minute
	maxNonces     = 256
	maxRefusals   = 20
	maxBodyBytes  = 2*maxDocumentBytes + 1<<20
)

var errNoKey = errors.New("this enclave holds no key")

type refusal struct {
	At     time.Time `json:"at"`
	Stage  string    `json:"stage"`
	Reason string    `json:"reason"`
}

// server is one enclave's half of the probe. Its role comes from what it holds:
// whichever side has the key is the holder.
type server struct {
	transfer *ecdh.PrivateKey
	attester attester
	verifier verifier
	client   *http.Client
	booted   time.Time

	mu       sync.Mutex
	key      []byte
	nonces   map[string]time.Time
	refusals []refusal
	lastPeer *peerIdentity
}

func newServer(transfer *ecdh.PrivateKey, a attester, v verifier, client *http.Client) *server {
	return &server{
		transfer: transfer,
		attester: a,
		verifier: v,
		client:   client,
		booted:   time.Now(),
		nonces:   make(map[string]time.Time),
	}
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /status", s.handleStatus)
	mux.HandleFunc("GET /prove", s.handleProve)
	mux.HandleFunc("GET /attest", s.handleAttest)
	mux.HandleFunc("POST /generate", s.handleGenerate)
	mux.HandleFunc("POST /pull", s.handlePull)
	mux.HandleFunc("POST /transfer/begin", s.handleBegin)
	mux.HandleFunc("POST /transfer/finish", s.handleFinish)
	return mux
}

func (s *server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"uptime_s":        int(time.Since(s.booted).Seconds()),
		"has_key":         s.key != nil,
		"transfer_key_fp": fingerprint(s.transfer.PublicKey()),
		"last_peer":       s.lastPeer,
		"refusals":        s.refusals,
	})
}

// handleProve shows the key is held without revealing it.
func (s *server) handleProve(w http.ResponseWriter, r *http.Request) {
	challenge := r.URL.Query().Get("challenge")
	if challenge == "" {
		writeError(w, http.StatusBadRequest, errors.New("challenge is required"))
		return
	}
	s.mu.Lock()
	key := s.key
	s.mu.Unlock()
	if key == nil {
		writeError(w, http.StatusConflict, errNoKey)
		return
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(challenge))
	writeJSON(w, http.StatusOK, map[string]string{"proof": hex.EncodeToString(mac.Sum(nil))})
}

// handleAttest returns a document for any nonce. A document only says what this
// enclave is, so anyone may have one; the replay checks rely on this.
func (s *server) handleAttest(w http.ResponseWriter, r *http.Request) {
	nonce, err := decodeNonce(r.URL.Query().Get("nonce"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	doc, err := s.attester.Attest(r.Context(), nonce)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(doc)
}

func (s *server) handleGenerate(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key != nil {
		writeError(w, http.StatusConflict, errors.New("this enclave already holds a key"))
		return
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.key = key
	writeJSON(w, http.StatusOK, map[string]bool{"generated": true})
}

type beginResponse struct {
	HolderNonce string `json:"holder_nonce"`
}

func (s *server) handleBegin(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key == nil {
		writeError(w, http.StatusConflict, errNoKey)
		return
	}
	now := time.Now()
	for n, expires := range s.nonces {
		if now.After(expires) {
			delete(s.nonces, n)
		}
	}
	if len(s.nonces) >= maxNonces {
		writeError(w, http.StatusTooManyRequests, errors.New("too many open transfers"))
		return
	}
	nonce, err := document.RandomNonce()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	encoded := hex.EncodeToString(nonce)
	s.nonces[encoded] = now.Add(nonceLifetime)
	writeJSON(w, http.StatusOK, beginResponse{HolderNonce: encoded})
}

type finishRequest struct {
	HolderNonce    string `json:"holder_nonce"`
	RequesterNonce string `json:"requester_nonce"`
	Document       []byte `json:"document"`
}

type finishResponse struct {
	Document []byte `json:"document"`
	Sealed   []byte `json:"sealed"`
}

// handleFinish is the only way a key leaves an enclave. The channel is
// untrusted: TLS here ends at the peer's shim and proves nothing about the code.
func (s *server) handleFinish(w http.ResponseWriter, r *http.Request) {
	var req finishRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decoding request: %w", err))
		return
	}
	holderNonce, err := decodeNonce(req.HolderNonce)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	requesterNonce, err := decodeNonce(req.RequesterNonce)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.consumeNonce(req.HolderNonce); err != nil {
		s.refuse(w, "nonce", err)
		return
	}
	peer, err := s.verifier.Verify(req.Document, holderNonce)
	if err != nil {
		s.refuse(w, "verify", err)
		return
	}
	s.recordPeer(peer)

	s.mu.Lock()
	key := s.key
	s.mu.Unlock()
	if key == nil {
		writeError(w, http.StatusConflict, errNoKey)
		return
	}
	mine := s.transfer.PublicKey()
	box, err := boxKey(s.transfer, peer.Key, mine, peer.Key, holderNonce, requesterNonce)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	sealed, err := seal(box, key)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	doc, err := s.attester.Attest(r.Context(), requesterNonce)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, finishResponse{Document: doc, Sealed: sealed})
}

type pullRequest struct {
	Peer string `json:"peer"`
}

// handlePull is the requester side. A pull that fails leaves the enclave empty,
// and its error is the holder's reason, so the operator sees why.
func (s *server) handlePull(w http.ResponseWriter, r *http.Request) {
	var req pullRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decoding request: %w", err))
		return
	}
	if req.Peer == "" || strings.ContainsAny(req.Peer, "/?#@") {
		writeError(w, http.StatusBadRequest, errors.New("peer must be a bare hostname"))
		return
	}
	s.mu.Lock()
	held := s.key != nil
	s.mu.Unlock()
	if held {
		writeError(w, http.StatusConflict, errors.New("this enclave already holds a key"))
		return
	}
	stats, err := s.pull(r.Context(), "https://"+req.Peer)
	if err != nil {
		log.Printf("pull from %s failed: %v", req.Peer, err)
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

type pullStats struct {
	Pulled        bool          `json:"pulled"`
	Elapsed       string        `json:"elapsed"`
	DocumentBytes int           `json:"document_bytes"`
	Holder        *peerIdentity `json:"holder"`
}

func (s *server) pull(ctx context.Context, base string) (*pullStats, error) {
	start := time.Now()
	var begun beginResponse
	if err := s.postJSON(ctx, base+"/transfer/begin", nil, &begun); err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	holderNonce, err := decodeNonce(begun.HolderNonce)
	if err != nil {
		return nil, fmt.Errorf("holder's nonce: %w", err)
	}
	requesterNonce, err := document.RandomNonce()
	if err != nil {
		return nil, err
	}
	doc, err := s.attester.Attest(ctx, holderNonce)
	if err != nil {
		return nil, fmt.Errorf("attesting to holder: %w", err)
	}
	var finished finishResponse
	finish := finishRequest{
		HolderNonce:    begun.HolderNonce,
		RequesterNonce: hex.EncodeToString(requesterNonce),
		Document:       doc,
	}
	if err := s.postJSON(ctx, base+"/transfer/finish", finish, &finished); err != nil {
		return nil, fmt.Errorf("finish: %w", err)
	}
	holder, err := s.verifier.Verify(finished.Document, requesterNonce)
	if err != nil {
		return nil, fmt.Errorf("verifying holder: %w", err)
	}
	s.recordPeer(holder)
	mine := s.transfer.PublicKey()
	box, err := boxKey(s.transfer, holder.Key, holder.Key, mine, holderNonce, requesterNonce)
	if err != nil {
		return nil, err
	}
	key, err := unseal(box, finished.Sealed)
	if err != nil {
		return nil, fmt.Errorf("opening sealed key: %w", err)
	}
	s.mu.Lock()
	s.key = key
	s.mu.Unlock()
	return &pullStats{
		Pulled:        true,
		Elapsed:       time.Since(start).Round(time.Millisecond).String(),
		DocumentBytes: len(doc),
		Holder:        holder,
	}, nil
}

func (s *server) postJSON(ctx context.Context, url string, in, out any) error {
	var body bytes.Buffer
	if in != nil {
		if err := json.NewEncoder(&body).Encode(in); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("peer answered %d: %.400s", resp.StatusCode, raw)
	}
	return json.Unmarshal(raw, out)
}

// consumeNonce makes each challenge single-use, so a document for it can't be
// replayed, even by someone who saw the first exchange.
func (s *server) consumeNonce(encoded string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	expires, ok := s.nonces[encoded]
	if !ok {
		return errors.New("unknown or already used nonce")
	}
	delete(s.nonces, encoded)
	if time.Now().After(expires) {
		return errors.New("expired nonce")
	}
	return nil
}

func (s *server) recordPeer(peer *peerIdentity) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastPeer = peer
}

func (s *server) refuse(w http.ResponseWriter, stage string, err error) {
	s.mu.Lock()
	s.refusals = append(s.refusals, refusal{At: time.Now().UTC(), Stage: stage, Reason: fmt.Sprintf("%.300v", err)})
	if len(s.refusals) > maxRefusals {
		s.refusals = s.refusals[len(s.refusals)-maxRefusals:]
	}
	s.mu.Unlock()
	log.Printf("refused at %s: %v", stage, err)
	writeError(w, http.StatusForbidden, fmt.Errorf("refused at %s: %w", stage, err))
}

func decodeNonce(encoded string) ([]byte, error) {
	nonce, err := hex.DecodeString(encoded)
	if err != nil || len(nonce) != document.NonceSize {
		return nil, fmt.Errorf("nonce must be %d hex-encoded bytes", document.NonceSize)
	}
	return nonce, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("writing response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
