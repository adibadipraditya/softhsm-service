package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/google/uuid"
	"github.com/miekg/pkcs11"
)

var errNotFound = errors.New("key not found")

// HSM wraps a PKCS#11 module and exposes high-level operations for the API.
type HSM struct {
	ctx   *pkcs11.Ctx
	token string
	pin   string
}

// NewHSM loads and initializes the PKCS#11 module.
func NewHSM(module, token, pin string) (*HSM, error) {
	ctx := pkcs11.New(module)
	if err := ctx.Initialize(); err != nil {
		return nil, fmt.Errorf("initialize module %s: %w", module, err)
	}
	return &HSM{ctx: ctx, token: token, pin: pin}, nil
}

// Close releases the module.
func (h *HSM) Close() {
	h.ctx.Finalize()
	h.ctx.Destroy()
}

// findToken returns the first slot holding a token with the configured label.
func (h *HSM) findToken() (uint, error) {
	slots, err := h.ctx.GetSlotList(true)
	if err != nil {
		return 0, err
	}
	for _, slot := range slots {
		info, err := h.ctx.GetTokenInfo(slot)
		if err != nil {
			continue
		}
		if info.Label == h.token {
			return slot, nil
		}
	}
	return 0, fmt.Errorf("token %q not found", h.token)
}

// withSession opens a session, logs in, runs fn, and cleans up.
func (h *HSM) withSession(fn func(pkcs11.SessionHandle) error) error {
	slot, err := h.findToken()
	if err != nil {
		return err
	}
	session, err := h.ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return err
	}
	defer h.ctx.CloseSession(session)
	if err := h.ctx.Login(session, pkcs11.CKU_USER, h.pin); err != nil {
		return err
	}
	defer h.ctx.Logout(session)
	return fn(session)
}

// Health reports whether the token can be found.
func (h *HSM) Health() error {
	_, err := h.findToken()
	return err
}

// findObject returns the first object matching class+label.
func (h *HSM) findObject(session pkcs11.SessionHandle, class uint, label string) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	if err := h.ctx.FindObjectsInit(session, template); err != nil {
		return 0, err
	}
	defer h.ctx.FindObjectsFinal(session)
	objs, _, err := h.ctx.FindObjects(session, 1)
	if err != nil {
		return 0, err
	}
	if len(objs) == 0 {
		return 0, fmt.Errorf("%w: %q", errNotFound, label)
	}
	return objs[0], nil
}

func (h *HSM) attributeBytes(session pkcs11.SessionHandle, obj pkcs11.ObjectHandle, attr uint) ([]byte, error) {
	t := []*pkcs11.Attribute{pkcs11.NewAttribute(attr, nil)}
	attrs, err := h.ctx.GetAttributeValue(session, obj, t)
	if err != nil {
		return nil, err
	}
	return attrs[0].Value, nil
}

// KeyExists reports whether any object with the given label already exists in
// the token. Used to enforce label uniqueness.
func (h *HSM) KeyExists(label string) (bool, error) {
	exists := false
	err := h.withSession(func(s pkcs11.SessionHandle) error {
		t := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, label)}
		if err := h.ctx.FindObjectsInit(s, t); err != nil {
			return err
		}
		defer h.ctx.FindObjectsFinal(s)
		objs, _, err := h.ctx.FindObjects(s, 1)
		if err != nil {
			return err
		}
		exists = len(objs) > 0
		return nil
	})
	return exists, err
}

// GenerateRSAKey creates a persistent RSA key pair inside the token.
func (h *HSM) GenerateRSAKey(label string, bits int, id []byte) error {
	return h.withSession(func(s pkcs11.SessionHandle) error {
		pub := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, bits),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{0x01, 0x00, 0x01}),
		}
		priv := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id),
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		}
		mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)}
		_, _, err := h.ctx.GenerateKeyPair(s, mech, pub, priv)
		return err
	})
}

// KeyInfo identifies a key by its label and CKA_ID.
type KeyInfo struct {
	Label string `json:"label"`
	ID    string `json:"id"`
}

// ckaIDToString converts a raw CKA_ID to a string: a canonical UUID string for
// 16-byte IDs (UUID v7), otherwise a hex string for legacy short IDs.
func ckaIDToString(id []byte) string {
	if u, err := uuid.FromBytes(id); err == nil {
		return u.String()
	}
	return hex.EncodeToString(id)
}

// ListKeys returns the label and ID of all private keys in the token.
func (h *HSM) ListKeys() ([]KeyInfo, error) {
	var keys []KeyInfo
	err := h.withSession(func(s pkcs11.SessionHandle) error {
		t := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY)}
		if err := h.ctx.FindObjectsInit(s, t); err != nil {
			return err
		}
		defer h.ctx.FindObjectsFinal(s)
		for {
			objs, _, err := h.ctx.FindObjects(s, 100)
			if err != nil {
				return err
			}
			if len(objs) == 0 {
				return nil
			}
			for _, o := range objs {
				label, err := h.attributeBytes(s, o, pkcs11.CKA_LABEL)
				if err != nil {
					return err
				}
				id, err := h.attributeBytes(s, o, pkcs11.CKA_ID)
				if err != nil {
					return err
				}
				keys = append(keys, KeyInfo{
					Label: strings.TrimRight(string(label), "\x00 "),
					ID:    ckaIDToString(id),
				})
			}
		}
	})
	return keys, err
}

// PublicKeyPEM exports an RSA public key as a PEM-encoded PKIX
// SubjectPublicKeyInfo block.
func (h *HSM) PublicKeyPEM(label string) (string, error) {
	var out string
	err := h.withSession(func(s pkcs11.SessionHandle) error {
		obj, err := h.findObject(s, pkcs11.CKO_PUBLIC_KEY, label)
		if err != nil {
			return err
		}
		modulus, err := h.attributeBytes(s, obj, pkcs11.CKA_MODULUS)
		if err != nil {
			return err
		}
		exp, err := h.attributeBytes(s, obj, pkcs11.CKA_PUBLIC_EXPONENT)
		if err != nil {
			return err
		}
		e := 0
		for _, b := range exp {
			e = e<<8 | int(b)
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: e}
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return err
		}
		out = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
		return nil
	})
	return out, err
}

// Sign signs data with the private key using the given mechanism.
func (h *HSM) Sign(label string, data []byte, mech uint) ([]byte, error) {
	var sig []byte
	err := h.withSession(func(s pkcs11.SessionHandle) error {
		priv, err := h.findObject(s, pkcs11.CKO_PRIVATE_KEY, label)
		if err != nil {
			return err
		}
		m := []*pkcs11.Mechanism{pkcs11.NewMechanism(mech, nil)}
		if err := h.ctx.SignInit(s, m, priv); err != nil {
			return err
		}
		sig, err = h.ctx.Sign(s, data)
		return err
	})
	return sig, err
}

// Verify verifies a signature with the public key using the given mechanism.
func (h *HSM) Verify(label string, data, sig []byte, mech uint) error {
	return h.withSession(func(s pkcs11.SessionHandle) error {
		pub, err := h.findObject(s, pkcs11.CKO_PUBLIC_KEY, label)
		if err != nil {
			return err
		}
		m := []*pkcs11.Mechanism{pkcs11.NewMechanism(mech, nil)}
		if err := h.ctx.VerifyInit(s, m, pub); err != nil {
			return err
		}
		return h.ctx.Verify(s, data, sig)
	})
}

// Encrypt encrypts data using the public key with the given mechanism.
func (h *HSM) Encrypt(label string, data []byte, mech *pkcs11.Mechanism) ([]byte, error) {
	var out []byte
	err := h.withSession(func(s pkcs11.SessionHandle) error {
		pub, err := h.findObject(s, pkcs11.CKO_PUBLIC_KEY, label)
		if err != nil {
			return err
		}
		if err := h.ctx.EncryptInit(s, []*pkcs11.Mechanism{mech}, pub); err != nil {
			return err
		}
		out, err = h.ctx.Encrypt(s, data)
		return err
	})
	return out, err
}

// Decrypt decrypts data using the private key with the given mechanism.
func (h *HSM) Decrypt(label string, data []byte, mech *pkcs11.Mechanism) ([]byte, error) {
	var out []byte
	err := h.withSession(func(s pkcs11.SessionHandle) error {
		priv, err := h.findObject(s, pkcs11.CKO_PRIVATE_KEY, label)
		if err != nil {
			return err
		}
		if err := h.ctx.DecryptInit(s, []*pkcs11.Mechanism{mech}, priv); err != nil {
			return err
		}
		out, err = h.ctx.Decrypt(s, data)
		return err
	})
	return out, err
}

// DestroyKey deletes the private and public key objects with the given label.
func (h *HSM) DestroyKey(label string) error {
	return h.withSession(func(s pkcs11.SessionHandle) error {
		for _, class := range []uint{pkcs11.CKO_PRIVATE_KEY, pkcs11.CKO_PUBLIC_KEY} {
			obj, err := h.findObject(s, class, label)
			if err != nil {
				if errors.Is(err, errNotFound) {
					continue
				}
				return err
			}
			if err := h.ctx.DestroyObject(s, obj); err != nil {
				return err
			}
		}
		return nil
	})
}
