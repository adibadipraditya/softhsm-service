// Package main implements a small HTTP crypto/signing service backed by
// SoftHSM2 over PKCS#11. See README.md for the API surface.
package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/miekg/pkcs11"
)

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

type server struct {
	hsm *HSM
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

type keyRequest struct {
	Label string `json:"label"`
	Bits  int    `json:"bits"` // 2048 or 4096 (default 2048)
}

type signRequest struct {
	Label     string `json:"label"`
	Algorithm string `json:"algorithm"` // RSA-SHA256, RSA-PSS-SHA256, RSA-SHA512
	Data      string `json:"data"`      // base64
}

type verifyRequest struct {
	Label     string `json:"label"`
	Algorithm string `json:"algorithm"`
	Data      string `json:"data"`      // base64
	Signature string `json:"signature"` // base64
}

func (s *server) healthz(w http.ResponseWriter, r *http.Request) {
	if err := s.hsm.Health(); err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) createKey(w http.ResponseWriter, r *http.Request) {
	var req keyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Label == "" {
		writeError(w, http.StatusBadRequest, "label is required")
		return
	}
	if req.Bits == 0 {
		req.Bits = 2048
	}
	if req.Bits != 2048 && req.Bits != 4096 {
		writeError(w, http.StatusBadRequest, "bits must be 2048 or 4096")
		return
	}
	exists, err := s.hsm.KeyExists(req.Label)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if exists {
		writeError(w, http.StatusConflict, "label already exists: "+req.Label)
		return
	}
	id, err := uuid.NewV7()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate id: "+err.Error())
		return
	}
	if err := s.hsm.GenerateRSAKey(req.Label, req.Bits, id[:]); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"label": req.Label,
		"type":  "rsa",
		"bits":  req.Bits,
		"id":    id.String(),
	})
}

func (s *server) listKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.hsm.ListKeys()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

func (s *server) publicKey(w http.ResponseWriter, r *http.Request) {
	label := r.PathValue("label")
	pemStr, err := s.hsm.PublicKeyPEM(label)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"label": label, "public_key_pem": pemStr})
}

func (s *server) deleteKey(w http.ResponseWriter, r *http.Request) {
	label := r.PathValue("label")
	if err := s.hsm.DestroyKey(label); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": label})
}

// parseMechanism maps a human-friendly algorithm name to a PKCS#11 mechanism.
func parseMechanism(alg string) (uint, error) {
	switch strings.ToUpper(strings.TrimSpace(alg)) {
	case "", "RSA-SHA256", "SHA256-RSA", "RS256":
		return pkcs11.CKM_SHA256_RSA_PKCS, nil
	case "RSA-PSS-SHA256", "PS256":
		return pkcs11.CKM_SHA256_RSA_PKCS_PSS, nil
	case "RSA-SHA512", "SHA512-RSA", "RS512":
		return pkcs11.CKM_SHA512_RSA_PKCS, nil
	default:
		return 0, errors.New("unsupported algorithm: " + alg)
	}
}

type cryptoRequest struct {
	Label     string `json:"label"`
	Algorithm string `json:"algorithm"` // RSA-OAEP-SHA1 (default), RSA-OAEP-SHA256, RSA-PKCS
	Data      string `json:"data"`      // base64
}

// oaepMechanism builds an RSA-OAEP mechanism with the given hash/MGF.
func oaepMechanism(hashAlg, mgf uint) *pkcs11.Mechanism {
	return pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, &pkcs11.OAEPParams{
		HashAlg:    hashAlg,
		MGF:        mgf,
		SourceType: pkcs11.CKZ_DATA_SPECIFIED,
	})
}

// parseEncryptMechanism maps an algorithm name to an encryption mechanism.
func parseEncryptMechanism(alg string) (*pkcs11.Mechanism, error) {
	switch strings.ToUpper(strings.TrimSpace(alg)) {
	case "", "RSA-OAEP-SHA1", "OAEP-SHA1":
		return oaepMechanism(pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1), nil
	case "RSA-OAEP-SHA256", "OAEP-SHA256":
		return oaepMechanism(pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256), nil
	case "RSA-PKCS", "RSA-PKCS1-V1.5":
		return pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil), nil
	default:
		return nil, errors.New("unsupported algorithm: " + alg)
	}
}

func (s *server) sign(w http.ResponseWriter, r *http.Request) {
	var req signRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	data, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		writeError(w, http.StatusBadRequest, "data must be base64")
		return
	}
	mech, err := parseMechanism(req.Algorithm)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	sig, err := s.hsm.Sign(req.Label, data, mech)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"algorithm": req.Algorithm,
		"signature": base64.StdEncoding.EncodeToString(sig),
	})
}

func (s *server) verify(w http.ResponseWriter, r *http.Request) {
	var req verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	data, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		writeError(w, http.StatusBadRequest, "data must be base64")
		return
	}
	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		writeError(w, http.StatusBadRequest, "signature must be base64")
		return
	}
	mech, err := parseMechanism(req.Algorithm)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.hsm.Verify(req.Label, data, sig, mech); err != nil {
		writeError(w, http.StatusBadRequest, "verification failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"valid": true})
}

func (s *server) encrypt(w http.ResponseWriter, r *http.Request) {
	var req cryptoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	data, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		writeError(w, http.StatusBadRequest, "data must be base64")
		return
	}
	mech, err := parseEncryptMechanism(req.Algorithm)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := s.hsm.Encrypt(req.Label, data, mech)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"algorithm":  req.Algorithm,
		"ciphertext": base64.StdEncoding.EncodeToString(out),
	})
}

func (s *server) decrypt(w http.ResponseWriter, r *http.Request) {
	var req cryptoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	data, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		writeError(w, http.StatusBadRequest, "data must be base64")
		return
	}
	mech, err := parseEncryptMechanism(req.Algorithm)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := s.hsm.Decrypt(req.Label, data, mech)
	if err != nil {
		writeError(w, http.StatusBadRequest, "decrypt failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"plaintext": base64.StdEncoding.EncodeToString(out),
	})
}

func main() {
	module := getenv("PKCS11_MODULE", "/usr/lib/softhsm/libsofthsm2.so")
	token := getenv("SOFTHSM2_TOKEN_LABEL", "mytoken")
	pin := getenv("SOFTHSM2_PIN", "1234")
	port := getenv("PORT", "8080")

	hsm, err := NewHSM(module, token, pin)
	if err != nil {
		log.Fatalf("init HSM: %v", err)
	}
	defer hsm.Close()

	// Wait briefly for the token to become available on first start.
	var lastErr error
	for i := 0; i < 20; i++ {
		if lastErr = hsm.Health(); lastErr == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if lastErr != nil {
		log.Fatalf("HSM not ready: %v", lastErr)
	}

	s := &server{hsm: hsm}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("POST /api/v1/keys", s.createKey)
	mux.HandleFunc("GET /api/v1/keys", s.listKeys)
	mux.HandleFunc("GET /api/v1/keys/{label}/public", s.publicKey)
	mux.HandleFunc("DELETE /api/v1/keys/{label}", s.deleteKey)
	mux.HandleFunc("POST /api/v1/sign", s.sign)
	mux.HandleFunc("POST /api/v1/verify", s.verify)
	mux.HandleFunc("POST /api/v1/encrypt", s.encrypt)
	mux.HandleFunc("POST /api/v1/decrypt", s.decrypt)

	log.Printf("hsm-api listening on :%s (token %q)", port, token)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}
