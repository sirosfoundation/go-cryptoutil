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
	"encoding/asn1"
	"errors"
	"math/big"

	gematik "github.com/gematik/zero-lab/go/brainpool"
	"github.com/sirosfoundation/go-cryptoutil"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
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
	if err == nil {
		if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); ok && isBrainpool(pub.Curve) {
			return cert, nil
		}
		// gematik parsed it but it's not brainpool — let others handle it.
		return nil, cryptoutil.ErrNotHandled
	}

	// gematik failed (e.g. brainpool key signed with RSA-PSS that gematik
	// doesn't know). Try stdlib as base, then graft the brainpool public key.
	cert, stdErr := x509.ParseCertificate(der)
	if stdErr == nil {
		if cert.PublicKey != nil {
			// stdlib parsed the public key fine — not a brainpool issue.
			return nil, cryptoutil.ErrNotHandled
		}
		// cert.PublicKey is nil: stdlib couldn't parse the key. Try extracting
		// a brainpool public key from the raw SPKI.
		pub, extractErr := parseBrainpoolSPKI(cert.RawSubjectPublicKeyInfo)
		if extractErr != nil {
			return nil, cryptoutil.ErrNotHandled
		}
		cert.PublicKey = pub
		return cert, nil
	}

	// Both gematik and stdlib failed. Try extracting SPKI from raw DER to check
	// if it's a brainpool cert that neither parser could handle fully.
	spki, spkiErr := extractSPKIFromDER(der)
	if spkiErr != nil {
		return nil, cryptoutil.ErrNotHandled
	}
	pub, extractErr := parseBrainpoolSPKI(spki)
	if extractErr != nil {
		return nil, cryptoutil.ErrNotHandled
	}
	// Construct a minimal certificate with the brainpool public key and raw DER.
	return &x509.Certificate{
		Raw:       der,
		PublicKey: pub,
	}, nil
}

// extractSPKIFromDER extracts the SubjectPublicKeyInfo from a raw DER certificate
// by minimally walking the ASN.1 structure (Certificate → TBSCertificate → SPKI).
func extractSPKIFromDER(der []byte) ([]byte, error) {
	// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
	input := cryptobyte.String(der)
	var certSeq cryptobyte.String
	if !input.ReadASN1(&certSeq, cbasn1.SEQUENCE) {
		return nil, errors.New("not a certificate")
	}
	// TBSCertificate ::= SEQUENCE { ... }
	var tbsSeq cryptobyte.String
	if !certSeq.ReadASN1(&tbsSeq, cbasn1.SEQUENCE) {
		return nil, errors.New("no TBSCertificate")
	}
	// Skip: version (optional explicit tag 0), serialNumber, signature, issuer, validity, subject
	// version
	tbsSeq.SkipOptionalASN1(cbasn1.Tag(0).ContextSpecific().Constructed())
	// serialNumber
	if !tbsSeq.SkipASN1(cbasn1.INTEGER) {
		return nil, errors.New("no serial")
	}
	// signature algorithm
	if !tbsSeq.SkipASN1(cbasn1.SEQUENCE) {
		return nil, errors.New("no sigAlg")
	}
	// issuer
	if !tbsSeq.SkipASN1(cbasn1.SEQUENCE) {
		return nil, errors.New("no issuer")
	}
	// validity
	if !tbsSeq.SkipASN1(cbasn1.SEQUENCE) {
		return nil, errors.New("no validity")
	}
	// subject
	if !tbsSeq.SkipASN1(cbasn1.SEQUENCE) {
		return nil, errors.New("no subject")
	}
	// subjectPublicKeyInfo — read as element (preserves the outer SEQUENCE tag+length)
	var spki cryptobyte.String
	if !tbsSeq.ReadASN1Element(&spki, cbasn1.SEQUENCE) {
		return nil, errors.New("no SPKI")
	}
	return []byte(spki), nil
}

// parseBrainpoolSPKI extracts a brainpool ECDSA public key from a raw
// SubjectPublicKeyInfo DER blob.
func parseBrainpoolSPKI(raw []byte) (*ecdsa.PublicKey, error) {
	var spki struct {
		Algorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.ObjectIdentifier
		}
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(raw, &spki); err != nil {
		return nil, err
	}
	ok, curve := gematik.CurveFromOID(spki.Algorithm.Parameters)
	if !ok {
		return nil, errors.New("not a brainpool curve")
	}
	keyBytes := spki.PublicKey.Bytes
	byteLen := (curve.Params().BitSize + 7) / 8
	if len(keyBytes) != 1+2*byteLen || keyBytes[0] != 0x04 {
		return nil, errors.New("invalid uncompressed EC point")
	}
	x := new(big.Int).SetBytes(keyBytes[1 : 1+byteLen])
	y := new(big.Int).SetBytes(keyBytes[1+byteLen:])
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
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
