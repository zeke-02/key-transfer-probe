package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeAuthority stands in for hardware: a document is the nonce plus the name of
// the enclave that made it, and only enrolled names verify. Names without a tag
// run v1.0.0.
type fakeAuthority struct {
	enrolled map[string]*ecdh.PublicKey
	tags     map[string]string
}

type fakeAttester struct{ name string }

func (f fakeAttester) Attest(_ context.Context, nonce []byte) ([]byte, error) {
	return []byte(f.name + "|" + hex.EncodeToString(nonce)), nil
}

func (a *fakeAuthority) Verify(doc, nonce []byte) (*peerIdentity, error) {
	name, boundTo, ok := strings.Cut(string(doc), "|")
	if !ok || boundTo != hex.EncodeToString(nonce) {
		return nil, errors.New("document is not bound to this nonce")
	}
	key, ok := a.enrolled[name]
	if !ok {
		return nil, errors.New("not the pinned release")
	}
	tag, ok := a.tags[name]
	if !ok {
		tag = "v1.0.0"
	}
	return &peerIdentity{Key: key, KeyFingerprint: fingerprint(key), CodeTag: tag}, nil
}

func newTransferKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

type enclave struct {
	s   *server
	url string
}

func startEnclave(t *testing.T, name string, a *fakeAuthority, enroll bool) *enclave {
	t.Helper()
	key := newTransferKey(t)
	if enroll {
		a.enrolled[name] = key.PublicKey()
	}
	s := newServer(key, fakeAttester{name}, a, http.DefaultClient)
	ts := httptest.NewServer(s.routes())
	t.Cleanup(ts.Close)
	return &enclave{s: s, url: ts.URL}
}

func newPair(t *testing.T) (*fakeAuthority, *enclave, *enclave) {
	t.Helper()
	a := &fakeAuthority{enrolled: map[string]*ecdh.PublicKey{}, tags: map[string]string{}}
	return a, startEnclave(t, "vault", a, true), startEnclave(t, "edge", a, true)
}

func (e *enclave) generate(t *testing.T) {
	t.Helper()
	resp, err := http.Post(e.url+"/generate", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("generate answered %d", resp.StatusCode)
	}
}

func (e *enclave) proof(t *testing.T, challenge string) (string, int) {
	t.Helper()
	resp, err := http.Get(e.url + "/prove?challenge=" + challenge)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out["proof"], resp.StatusCode
}

func (e *enclave) begin(t *testing.T) string {
	t.Helper()
	resp, err := http.Post(e.url+"/transfer/begin", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out beginResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out.HolderNonce
}

func (e *enclave) finish(t *testing.T, req finishRequest) int {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(e.url+"/transfer/finish", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func randomNonce(t *testing.T) string {
	t.Helper()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(nonce)
}

func attestFor(t *testing.T, name, nonce string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(nonce)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := fakeAttester{name}.Attest(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestKeySurvivesLosingEitherSide(t *testing.T) {
	a, vault, edge := newPair(t)
	vault.generate(t)
	want, _ := vault.proof(t, "hello")

	if _, err := edge.s.pull(context.Background(), vault.url); err != nil {
		t.Fatalf("first transfer: %v", err)
	}
	if got, _ := edge.proof(t, "hello"); got != want {
		t.Fatal("edge's key differs from the vault's")
	}

	// A redeployed vault is empty and has a new attested key.
	reborn := startEnclave(t, "vault", a, true)
	if _, status := reborn.proof(t, "hello"); status != http.StatusConflict {
		t.Fatalf("a fresh enclave should be empty, prove answered %d", status)
	}
	if _, err := reborn.s.pull(context.Background(), edge.url); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got, _ := reborn.proof(t, "hello"); got != want {
		t.Fatal("restored key differs from the original")
	}
}

func TestUnapprovedPeerGetsNothing(t *testing.T) {
	a, vault, _ := newPair(t)
	vault.generate(t)
	other := startEnclave(t, "other-repo", a, false)

	_, err := other.s.pull(context.Background(), vault.url)
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected a refusal, got %v", err)
	}
	if _, status := other.proof(t, "hello"); status != http.StatusConflict {
		t.Fatalf("refused peer ended up with a key, prove answered %d", status)
	}
}

func TestPullerRefusesUnapprovedHolder(t *testing.T) {
	a, vault, _ := newPair(t)
	other := startEnclave(t, "other-repo", a, false)
	other.generate(t)
	// A hostile holder hands its key to anyone, so only vault's check stops this.
	other.s.verifier = &fakeAuthority{enrolled: map[string]*ecdh.PublicKey{
		"vault":      vault.s.transfer.PublicKey(),
		"other-repo": other.s.transfer.PublicKey(),
	}}

	_, err := vault.s.pull(context.Background(), other.url)
	if err == nil || !strings.Contains(err.Error(), "verifying holder") {
		t.Fatalf("expected vault to refuse the holder, got %v", err)
	}
	if _, status := vault.proof(t, "hello"); status != http.StatusConflict {
		t.Fatalf("vault installed the key, prove answered %d", status)
	}
}

func TestOlderReleaseGetsNothing(t *testing.T) {
	a, vault, _ := newPair(t)
	a.tags["vault"] = "v1.2.0"
	vault.generate(t)
	old := startEnclave(t, "old-vault", a, true)
	a.tags["old-vault"] = "v1.1.9"

	_, err := old.s.pull(context.Background(), vault.url)
	if err == nil || !strings.Contains(err.Error(), "minimum tag") {
		t.Fatalf("expected the older release to be refused, got %v", err)
	}
	if _, status := old.proof(t, "hello"); status != http.StatusConflict {
		t.Fatalf("older release ended up with a key, prove answered %d", status)
	}
}

func TestUpgradePullsFromOlderRelease(t *testing.T) {
	a, vault, _ := newPair(t)
	vault.generate(t)
	next := startEnclave(t, "next-vault", a, true)
	a.tags["next-vault"] = "v1.10.0"

	if _, err := next.s.pull(context.Background(), vault.url); err != nil {
		t.Fatalf("upgrade pull: %v", err)
	}
	// The new release then serves its own peers at or above v1.10.0 only.
	stale := startEnclave(t, "stale", a, true)
	if _, err := stale.s.pull(context.Background(), next.url); err == nil {
		t.Fatal("v1.0.0 pulled from v1.10.0")
	}
}

func TestUntaggedReleaseGetsNothing(t *testing.T) {
	a, vault, edge := newPair(t)
	vault.generate(t)
	a.tags["edge"] = ""

	if _, err := edge.s.pull(context.Background(), vault.url); err == nil {
		t.Fatal("a peer with no release tag got the key")
	}
}

func TestHolderWithoutTagRefusesEveryone(t *testing.T) {
	a, vault, edge := newPair(t)
	a.tags["vault"] = "latest"
	vault.generate(t)

	_, err := edge.s.pull(context.Background(), vault.url)
	if err == nil || !strings.Contains(err.Error(), "own release tag") {
		t.Fatalf("expected the holder to fail closed, got %v", err)
	}
}

func TestDocumentForAnotherNonceIsRefused(t *testing.T) {
	_, vault, _ := newPair(t)
	vault.generate(t)
	nonce := vault.begin(t)
	status := vault.finish(t, finishRequest{
		HolderNonce:    nonce,
		RequesterNonce: randomNonce(t),
		Document:       attestFor(t, "edge", randomNonce(t)),
	})
	if status != http.StatusForbidden {
		t.Fatalf("stale document answered %d", status)
	}
}

func TestNonceWorksOnce(t *testing.T) {
	_, vault, _ := newPair(t)
	vault.generate(t)
	nonce := vault.begin(t)
	req := finishRequest{HolderNonce: nonce, RequesterNonce: randomNonce(t), Document: attestFor(t, "edge", nonce)}
	if status := vault.finish(t, req); status != http.StatusOK {
		t.Fatalf("first use answered %d", status)
	}
	if status := vault.finish(t, req); status != http.StatusForbidden {
		t.Fatalf("replay answered %d", status)
	}
}

func TestUnknownNonceIsRefused(t *testing.T) {
	_, vault, _ := newPair(t)
	vault.generate(t)
	nonce := randomNonce(t)
	status := vault.finish(t, finishRequest{HolderNonce: nonce, RequesterNonce: randomNonce(t), Document: attestFor(t, "edge", nonce)})
	if status != http.StatusForbidden {
		t.Fatalf("invented nonce answered %d", status)
	}
}

func TestSealedBoxOpensOnlyForTheVerifiedPeer(t *testing.T) {
	holder, requester, stranger := newTransferKey(t), newTransferKey(t), newTransferKey(t)
	hn, rn := []byte(randomNonce(t)), []byte(randomNonce(t))
	sent, err := boxKey(holder, requester.PublicKey(), holder.PublicKey(), requester.PublicKey(), hn, rn)
	if err != nil {
		t.Fatal(err)
	}
	box, err := seal(sent, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	opened, err := boxKey(requester, holder.PublicKey(), holder.PublicKey(), requester.PublicKey(), hn, rn)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := unseal(opened, box); err != nil || string(got) != "secret" {
		t.Fatalf("peer couldn't open the box: %q, %v", got, err)
	}

	wrongPeer, err := boxKey(stranger, holder.PublicKey(), holder.PublicKey(), requester.PublicKey(), hn, rn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unseal(wrongPeer, box); err == nil {
		t.Fatal("a stranger opened the box")
	}

	otherExchange, err := boxKey(requester, holder.PublicKey(), holder.PublicKey(), requester.PublicKey(), hn, []byte(randomNonce(t)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unseal(otherExchange, box); err == nil {
		t.Fatal("a box from another exchange opened")
	}

	tampered := bytes.Clone(box)
	tampered[len(tampered)-1] ^= 1
	if _, err := unseal(opened, tampered); err == nil {
		t.Fatal("altered ciphertext opened")
	}
}

func TestPinFormatIsAccepted(t *testing.T) {
	if _, err := newTinfoilVerifier("zeke-02/key-transfer-probe@v0.0.1"); err != nil {
		t.Fatal(err)
	}
}

func TestLoadsTinfoilKeyFormats(t *testing.T) {
	key := newTransferKey(t)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "private_key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadTransferKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Equal(key) {
		t.Fatal("loaded a different key")
	}

	spki, err := x509.MarshalPKIXPublicKey(key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	endorsed, err := parseEndorsedKey(hex.EncodeToString(spki))
	if err != nil {
		t.Fatal(err)
	}
	if !endorsed.Equal(key.PublicKey()) {
		t.Fatal("parsed a different public key")
	}
}
