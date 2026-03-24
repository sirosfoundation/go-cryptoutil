// Package brainpool provides [cryptoutil.Extensions] plugins for Brainpool
// elliptic curves (P256r1, P384r1, P512r1) using the gematik brainpool library.
//
// Use [Register] to add brainpool support to an Extensions instance:
//
//	ext := cryptoutil.New()
//	brainpool.Register(ext)
package brainpool

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"

	gematik "github.com/gematik/zero-lab/go/brainpool"
	"github.com/sirosfoundation/go-cryptoutil"
)

// Register adds brainpool certificate parsing, signature verification,
// private key parsing, and algorithm mappings to ext.
func Register(ext *cryptoutil.Extensions) {
	ext.Parsers = append(ext.Parsers, Parser)
	ext.Verifiers = append(ext.Verifiers, Verifier)
	ext.KeyParsers = append(ext.KeyParsers, KeyParser)
	registerAlgorithms(ext.Algorithms)
}

// Parser handles DER certificates with brainpool public keys.
// It delegates to the gematik brainpool library's ParseCertificate, which
// falls back to x509.ParseCertificate for non-brainpool certificates.
func Parser(der []byte) (*x509.Certificate, error) {
	cert, err := gematik.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	// gematik falls back to stdlib for non-brainpool certs.
	// Check if this cert actually has a brainpool key; if not, return
	// ErrNotHandled so the next parser in the chain can try.
	if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		if isBrainpool(pub.Curve) {
			return cert, nil
		}
	}
	// It was a non-brainpool cert that gematik's stdlib fallback parsed.
	// The stdlib already failed (that's why we're here), so this shouldn't
	// normally happen. Return ErrNotHandled to be safe.
	return nil, cryptoutil.ErrNotHandled
}

// Verifier verifies signatures on certificates with brainpool public keys.
// For ECDSA signatures on brainpool curves, it performs signature verification
// directly using crypto/ecdsa.Verify, since Go's x509.Certificate.CheckSignature
// does not recognize brainpool curves.
func Verifier(cert *x509.Certificate, algo x509.SignatureAlgorithm, signed, signature []byte) error {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !isBrainpool(pub.Curve) {
		return cryptoutil.ErrNotHandled
	}

	hash, err := hashForAlgorithm(algo)
	if err != nil {
		return err
	}

	// The signature may be in ASN.1 DER format (from x509/TLS contexts)
	// or in raw r||s format (from XML-DSIG/JWS contexts).
	// Try ASN.1 first, then raw.
	if verifyASN1(pub, hash, signed, signature) {
		return nil
	}
	if verifyRaw(pub, hash, signed, signature) {
		return nil
	}

	return errors.New("cryptoutil/brainpool: ECDSA signature verification failed")
}

// KeyParser parses brainpool EC private keys from DER.
func KeyParser(der []byte) (crypto.PrivateKey, error) {
	key, err := gematik.ParseECPrivateKey(der)
	if err != nil {
		return nil, cryptoutil.ErrNotHandled
	}
	if !isBrainpool(key.Curve) {
		return nil, cryptoutil.ErrNotHandled
	}
	return key, nil
}

func verifyASN1(pub *ecdsa.PublicKey, hash crypto.Hash, signed, sig []byte) bool {
	h := hash.New()
	h.Write(signed)
	digest := h.Sum(nil)
	return ecdsa.VerifyASN1(pub, digest, sig)
}

func verifyRaw(pub *ecdsa.PublicKey, hash crypto.Hash, signed, sig []byte) bool {
	if len(sig) == 0 || len(sig)%2 != 0 {
		return false
	}
	der, err := cryptoutil.ECDSARawToASN1(sig)
	if err != nil {
		return false
	}
	h := hash.New()
	h.Write(signed)
	digest := h.Sum(nil)
	return ecdsa.VerifyASN1(pub, digest, der)
}

func hashForAlgorithm(algo x509.SignatureAlgorithm) (crypto.Hash, error) {
	switch algo {
	case x509.ECDSAWithSHA256:
		return crypto.SHA256, nil
	case x509.ECDSAWithSHA384:
		return crypto.SHA384, nil
	case x509.ECDSAWithSHA512:
		return crypto.SHA512, nil
	case x509.ECDSAWithSHA1:
		return crypto.SHA1, nil
	default:
		return 0, cryptoutil.ErrNotHandled
	}
}

func isBrainpool(curve elliptic.Curve) bool {
	name := curve.Params().Name
	return name == "brainpoolP256r1" || name == "brainpoolP384r1" || name == "brainpoolP512r1"
}

func registerAlgorithms(reg *cryptoutil.AlgorithmRegistry) {
	if reg == nil {
		return
	}
	reg.Register(&cryptoutil.Algorithm{
		Name:    "brainpoolP256r1",
		JWS:     "BP256R1",
		XMLDSIG: "http://www.w3.org/2007/05/xmldsig-more#ecdsa-brainpoolP256r1",
		Hash:    crypto.SHA256,
		KeyType: "EC",
	})
	reg.Register(&cryptoutil.Algorithm{
		Name:    "brainpoolP384r1",
		JWS:     "BP384R1",
		XMLDSIG: "http://www.w3.org/2007/05/xmldsig-more#ecdsa-brainpoolP384r1",
		Hash:    crypto.SHA384,
		KeyType: "EC",
	})
	reg.Register(&cryptoutil.Algorithm{
		Name:    "brainpoolP512r1",
		JWS:     "BP512R1",
		XMLDSIG: "http://www.w3.org/2007/05/xmldsig-more#ecdsa-brainpoolP512r1",
		Hash:    crypto.SHA512,
		KeyType: "EC",
	})
}
