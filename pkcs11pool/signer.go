package pkcs11pool

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io"

	"github.com/miekg/pkcs11"
)

// Signer implements crypto.Signer backed by a pooled PKCS#11 session.
// It checks out a session from the pool for each Sign call and returns it
// after use, allowing concurrent signing across multiple goroutines.
type Signer struct {
	pool      *Pool
	sel       KeySelector
	publicKey crypto.PublicKey
	keyType   uint
}

// NewSigner creates a crypto.Signer for the key identified by sel.
// It resolves the public key once during construction.
func NewSigner(pool *Pool, sel KeySelector) (*Signer, error) {
	session, err := pool.Acquire(context.Background())
	if err != nil {
		return nil, fmt.Errorf("pkcs11pool: signer acquire: %w", err)
	}
	defer pool.Release(session)

	pubHandle, err := pool.FindPublicKey(session, sel)
	if err != nil {
		return nil, err
	}

	kt, err := pool.KeyType(session, pubHandle)
	if err != nil {
		return nil, err
	}

	pubKey, err := pool.ExtractPublicKey(session, pubHandle)
	if err != nil {
		return nil, err
	}

	return &Signer{
		pool:      pool,
		sel:       sel,
		publicKey: pubKey,
		keyType:   kt,
	}, nil
}

// Public returns the public key.
func (s *Signer) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign implements crypto.Signer. It checks out a session from the pool,
// signs the digest, and returns the session. On failure, it attempts
// session recovery and retries once.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	session, err := s.pool.Acquire(context.Background())
	if err != nil {
		return nil, fmt.Errorf("pkcs11pool: acquire: %w", err)
	}

	sig, err := s.signWith(session, digest)
	if err != nil {
		// Attempt session recovery and retry.
		newSession, recoverErr := s.pool.RecoverSession(session)
		if recoverErr != nil {
			// Recovery failed to open a replacement. Return the broken session
			// to the pool so the pool slot is not permanently lost — the next
			// caller will trigger a new recovery attempt and replace it.
			s.pool.Release(session)
			return nil, fmt.Errorf("pkcs11pool: sign failed and recovery failed: sign=%w, recover=%v", err, recoverErr)
		}
		session = newSession
		sig, err = s.signWith(session, digest)
		if err != nil {
			s.pool.Release(session)
			return nil, err
		}
	}
	s.pool.Release(session)
	return sig, nil
}

// Algorithm returns the JWS algorithm name for this key (e.g. "ES256", "RS256").
func (s *Signer) Algorithm() string {
	switch pub := s.publicKey.(type) {
	case *ecdsa.PublicKey:
		switch pub.Curve.Params().BitSize {
		case 384:
			return "ES384"
		case 521:
			return "ES512"
		default:
			return "ES256"
		}
	case *rsa.PublicKey:
		bits := pub.N.BitLen()
		switch {
		case bits >= 4096:
			return "RS512"
		case bits >= 3072:
			return "RS384"
		default:
			return "RS256"
		}
	default:
		return ""
	}
}

func (s *Signer) signWith(session pkcs11.SessionHandle, digest []byte) ([]byte, error) {
	privHandle, err := s.pool.FindPrivateKey(session, s.sel)
	if err != nil {
		return nil, err
	}

	switch s.keyType {
	case pkcs11.CKK_EC:
		return s.pool.SignECDSA(session, privHandle, digest)
	case pkcs11.CKK_RSA:
		return s.pool.SignRSAPKCS(session, privHandle, digest)
	default:
		return nil, fmt.Errorf("pkcs11pool: unsupported key type for signing: %d", s.keyType)
	}
}

// Ensure Signer implements crypto.Signer at compile time.
var _ crypto.Signer = (*Signer)(nil)
