package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// Both sides hold attested keys, so a static X25519 agreement authenticates
// both of them: only the verified peer can open the box, and only the verified
// holder could have made it. The nonces bind the box to this one exchange.
func boxKey(mine *ecdh.PrivateKey, peer *ecdh.PublicKey, holder, requester *ecdh.PublicKey, holderNonce, requesterNonce []byte) ([]byte, error) {
	shared, err := mine.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("key agreement: %w", err)
	}
	info := []byte("key-transfer-probe/v1")
	info = append(info, holder.Bytes()...)
	info = append(info, requester.Bytes()...)
	info = append(info, holderNonce...)
	info = append(info, requesterNonce...)
	return hkdf.Key(sha256.New, shared, nil, string(info), 32)
}

func seal(key, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func unseal(key, box []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(box) < gcm.NonceSize() {
		return nil, errors.New("sealed box is too short")
	}
	return gcm.Open(nil, box[:gcm.NonceSize()], box[gcm.NonceSize():], nil)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func loadTransferKey(path string) (*ecdh.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s holds no PEM block", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	key, ok := parsed.(*ecdh.PrivateKey)
	if !ok || key.Curve() != ecdh.X25519() {
		return nil, fmt.Errorf("%s is %T, not an X25519 key", path, parsed)
	}
	return key, nil
}

// parseEndorsedKey reads the hex SPKI DER that attestation endorses.
func parseEndorsedKey(spkiHex string) (*ecdh.PublicKey, error) {
	der, err := hex.DecodeString(spkiHex)
	if err != nil {
		return nil, fmt.Errorf("decoding endorsed key: %w", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parsing endorsed key: %w", err)
	}
	key, ok := parsed.(*ecdh.PublicKey)
	if !ok || key.Curve() != ecdh.X25519() {
		return nil, fmt.Errorf("endorsed key is %T, not X25519", parsed)
	}
	return key, nil
}

func fingerprint(key *ecdh.PublicKey) string {
	sum := sha256.Sum256(key.Bytes())
	return hex.EncodeToString(sum[:8])
}
