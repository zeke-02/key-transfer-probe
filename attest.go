package main

import (
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
)

const (
	attestationSocket = "/tinfoil/attestation.sock"
	transferKeyID     = "transfer"
	maxDocumentBytes  = 32 << 20
)

// attester produces this enclave's document for a nonce.
type attester interface {
	Attest(ctx context.Context, nonce []byte) ([]byte, error)
}

// verifier checks a peer's document and returns its endorsed transfer key.
type verifier interface {
	Verify(doc, nonce []byte) (*peerIdentity, error)
}

// peerIdentity is what the document proved. Everything but Key is reported so
// the probe records what Tinfoil actually signs, including the release times
// a public delay would need.
type peerIdentity struct {
	Key                *ecdh.PublicKey `json:"-"`
	KeyFingerprint     string          `json:"key_fingerprint"`
	ConfigName         string          `json:"config_name,omitempty"`
	ConfigApprovalTime *time.Time      `json:"config_approval_time,omitempty"`
	ConfigSignatureAt  *time.Time      `json:"config_signature_time,omitempty"`
	ConfigRepo         string          `json:"config_repo,omitempty"`
	CodeTag            string          `json:"code_tag,omitempty"`
	FreshnessExpiresAt *time.Time      `json:"freshness_expires_at,omitempty"`
}

type socketAttester struct{ client *http.Client }

func newSocketAttester(path string) *socketAttester {
	return &socketAttester{client: &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", path)
			},
		},
	}}
}

func (a *socketAttester) Attest(ctx context.Context, nonce []byte) ([]byte, error) {
	url := "http://localhost/.well-known/tinfoil-attestation?nonce=" + hex.EncodeToString(nonce)
	var last error
	for range 10 {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := a.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("attestation socket: %w", err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxDocumentBytes))
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("reading attestation: %w", err)
		}
		switch resp.StatusCode {
		case http.StatusOK:
			return body, nil
		case http.StatusServiceUnavailable:
			last = errors.New("attestation socket not ready")
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(2 * time.Second):
			}
		default:
			return nil, fmt.Errorf("attestation socket answered %d: %.200s", resp.StatusCode, body)
		}
	}
	return nil, last
}

// tinfoilVerifier pins the peer to one repo and release. CodeTag can't do this:
// on V3 config collateral it names the runtime, not the release.
type tinfoilVerifier struct {
	verifier *verify.Verifier
	pin      string
}

func newTinfoilVerifier(pin string) (*tinfoilVerifier, error) {
	v, err := verify.NewVerifier()
	if err != nil {
		return nil, err
	}
	if err := v.CheckRepoVerifiability(pin); err != nil {
		return nil, fmt.Errorf("peer pin %q: %w", pin, err)
	}
	return &tinfoilVerifier{verifier: v, pin: pin}, nil
}

func (t *tinfoilVerifier) Verify(doc, nonce []byte) (*peerIdentity, error) {
	verified, err := t.verifier.VerifyV3(doc, nonce, t.pin)
	if err != nil {
		return nil, err
	}
	spkiHex, ok := verified.CryptoMaterialData(transferKeyID, document.KeySPKIV1Format)
	if !ok {
		return nil, fmt.Errorf("attestation endorses no %q key", transferKeyID)
	}
	key, err := parseEndorsedKey(spkiHex)
	if err != nil {
		return nil, err
	}
	identity := &peerIdentity{
		Key:            key,
		KeyFingerprint: fingerprint(key),
		ConfigRepo:     verified.ConfigRepo(),
		CodeTag:        verified.CodeTag(),
	}
	if config, ok := verified.Config(); ok {
		identity.ConfigName = config.Name
		identity.ConfigApprovalTime = optionalTime(config.ApprovalTime)
		identity.ConfigSignatureAt = optionalTime(config.SignatureTime)
	}
	identity.FreshnessExpiresAt = optionalTime(verified.FreshnessExpiresAt())
	return identity, nil
}

func optionalTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
