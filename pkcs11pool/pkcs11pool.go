// Package pkcs11pool provides a pooled PKCS#11 session manager and crypto.Signer
// implementation for HSM-backed signing operations. It supports EC (P-256, P-384,
// P-521) and RSA keys, session pooling with automatic recovery, key generation,
// ECDH key agreement, and context-aware session checkout.
//
// Usage:
//
//	pool, err := pkcs11pool.New(pkcs11pool.Config{
//	    ModulePath: "/usr/lib/softhsm/libsofthsm2.so",
//	    PIN:        "1234",
//	    SlotID:     0,
//	    PoolSize:   4,
//	})
//	defer pool.Close()
//
//	// Get a crypto.Signer for an existing key:
//	signer, err := pool.Signer(pkcs11pool.KeyByLabel("my-key"))
//
//	// Or use the lower-level Backend interface for keygen/ECDH:
//	kid, pubKey, err := pool.GenerateECKey(ctx, "P-256")
package pkcs11pool

import (
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
)

// Config holds configuration for connecting to a PKCS#11 token.
type Config struct {
	// ModulePath is the path to the PKCS#11 shared library.
	ModulePath string `yaml:"module_path" envconfig:"MODULE_PATH"`
	// SlotID is the slot number (used if TokenLabel is empty).
	SlotID uint `yaml:"slot_id" envconfig:"SLOT_ID"`
	// TokenLabel finds the slot by token label instead of SlotID.
	TokenLabel string `yaml:"token_label" envconfig:"TOKEN_LABEL"`
	// PIN is the user PIN for the token.
	PIN string `yaml:"pin" envconfig:"PIN"`
	// PoolSize is the number of concurrent sessions (default 4).
	PoolSize int `yaml:"pool_size" envconfig:"POOL_SIZE"`
	// ReadWrite opens sessions with CKF_RW_SESSION (required for key generation).
	ReadWrite bool `yaml:"read_write" envconfig:"READ_WRITE"`
}

// KeySelector identifies a key on the token.
type KeySelector struct {
	Label string // CKA_LABEL match
	ID    []byte // CKA_ID match
}

// KeyByLabel returns a KeySelector that finds a key by label.
func KeyByLabel(label string) KeySelector {
	return KeySelector{Label: label}
}

// KeyByID returns a KeySelector that finds a key by CKA_ID.
func KeyByID(id []byte) KeySelector {
	return KeySelector{ID: id}
}

// Curve OIDs for EC key operations.
var (
	oidP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

func curveOID(name string) (asn1.ObjectIdentifier, error) {
	switch name {
	case "P-256":
		return oidP256, nil
	case "P-384":
		return oidP384, nil
	case "P-521":
		return oidP521, nil
	default:
		return nil, fmt.Errorf("pkcs11pool: unsupported curve: %s", name)
	}
}

func oidToCurveName(derParams []byte) (string, error) {
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(derParams, &oid); err != nil {
		return "", fmt.Errorf("pkcs11pool: unmarshal OID: %w", err)
	}
	switch {
	case oid.Equal(oidP256):
		return "P-256", nil
	case oid.Equal(oidP384):
		return "P-384", nil
	case oid.Equal(oidP521):
		return "P-521", nil
	default:
		return "", fmt.Errorf("pkcs11pool: unknown curve OID: %v", oid)
	}
}

func parseCurve(name string) (elliptic.Curve, error) {
	switch name {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("pkcs11pool: unsupported curve: %s", name)
	}
}
