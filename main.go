// Throwaway probe for Fount Mail: can two Tinfoil enclaves verify each other and
// pass a key that nobody else can read? The key is random and worthless, and it
// never leaves either enclave except sealed to a verified peer.
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

const (
	listenAddr    = ":8080"
	transferKeyAt = "/run/tinfoil/keys/" + transferKeyID + "/private_key.pem"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "health" {
		// The image is FROM scratch, so the binary is its own healthcheck.
		resp, err := http.Get("http://127.0.0.1" + listenAddr + "/health")
		if err != nil || resp.StatusCode != http.StatusOK {
			fmt.Fprintln(os.Stderr, "unhealthy:", err)
			os.Exit(1)
		}
		return
	}
	pin := os.Getenv("PEER_PIN")
	if pin == "" {
		log.Fatal("PEER_PIN is required")
	}
	transfer, err := loadTransferKey(transferKeyAt)
	if err != nil {
		log.Fatal(err)
	}
	verifier, err := newTinfoilVerifier(pin)
	if err != nil {
		log.Fatal(err)
	}
	s := newServer(transfer, newSocketAttester(attestationSocket), verifier, &http.Client{Timeout: 90 * time.Second})
	log.Printf("listening on %s, transfer key %s, peer pin %s", listenAddr, fingerprint(transfer.PublicKey()), pin)
	log.Fatal(http.ListenAndServe(listenAddr, s.routes()))
}
