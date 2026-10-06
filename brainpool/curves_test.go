package brainpool

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"testing"

	gematik "github.com/gematik/zero-lab/go/brainpool"

	"github.com/sirosfoundation/go-cryptoutil"
)

// The tests in this file pin the externally visible behavior of the plugin
// for every supported curve with real Brainpool keys and certificates, so
// that a change of the underlying gematik library (the removal of
// CurveFromOID in v1.1.0 was the reason for them) can be shown not to change
// what Parser, KeyParser and Verifier accept or reject.

var (
	oidBP256r1    = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 7}
	oidBP256t1    = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 8}
	oidBP384r1    = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 11}
	oidBP384t1    = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 12}
	oidBP512r1    = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 13}
	oidBP512t1    = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 14}
	oidPrime256v1 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidSecp384r1  = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidRSAPSS     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
)

type bpCurve struct {
	name  string
	curve elliptic.Curve
	oid   asn1.ObjectIdentifier
	size  int
}

func bpCurves() []bpCurve {
	return []bpCurve{
		{"brainpoolP256r1", gematik.P256r1(), oidBP256r1, 32},
		{"brainpoolP384r1", gematik.P384r1(), oidBP384r1, 48},
		{"brainpoolP512r1", gematik.P512r1(), oidBP512r1, 64},
	}
}

func genKey(t *testing.T, c bpCurve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(c.curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// spkiDER builds a SubjectPublicKeyInfo with the given algorithm parameters
// (an already DER-encoded element) and public key bits.
func spkiDER(t *testing.T, params asn1.RawValue, point []byte) []byte {
	t.Helper()
	der, err := asn1.Marshal(struct {
		Algorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue
		}
		PublicKey asn1.BitString
	}{
		Algorithm: struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue
		}{asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}, params},
		PublicKey: asn1.BitString{Bytes: point, BitLength: len(point) * 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func oidParam(t *testing.T, oid asn1.ObjectIdentifier) asn1.RawValue {
	t.Helper()
	der, err := asn1.Marshal(oid)
	if err != nil {
		t.Fatal(err)
	}
	return asn1.RawValue{FullBytes: der}
}

func uncompressed(c bpCurve, pub *ecdsa.PublicKey) []byte {
	b := make([]byte, 1+2*c.size)
	b[0] = 4
	pub.X.FillBytes(b[1 : 1+c.size])
	pub.Y.FillBytes(b[1+c.size:])
	return b
}

func assertSameKey(t *testing.T, got any, want *ecdsa.PublicKey, name string) {
	t.Helper()
	pub, ok := got.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("PublicKey is %T, want *ecdsa.PublicKey", got)
	}
	if pub.Curve.Params().Name != name {
		t.Errorf("curve %q, want %q", pub.Curve.Params().Name, name)
	}
	if pub.X.Cmp(want.X) != 0 || pub.Y.Cmp(want.Y) != 0 {
		t.Error("public key does not match the key the certificate was built from")
	}
}

func TestParserEveryCurve(t *testing.T) {
	ext := cryptoutil.New()
	Register(ext)
	for _, c := range bpCurves() {
		t.Run(c.name, func(t *testing.T) {
			key := genKey(t, c)
			der := buildASN1Cert(t, key)

			if _, err := x509.ParseCertificate(der); err == nil {
				t.Fatal("crypto/x509 unexpectedly parses a Brainpool certificate")
			}

			for label, parse := range map[string]func([]byte) (*x509.Certificate, error){
				"Parser":    Parser,
				"Extension": ext.ParseCertificate,
			} {
				cert, err := parse(der)
				if err != nil {
					t.Fatalf("%s: %v", label, err)
				}
				assertSameKey(t, cert.PublicKey, &key.PublicKey, c.name)
				if !bytes.Equal(cert.Raw, der) {
					t.Errorf("%s: Raw differs from the input DER", label)
				}
			}
		})
	}
}

// The certificate is self-signed with ecdsa-with-SHA256, so Verifier must
// accept it for the curve it was signed on and reject a tampered TBS.
func TestVerifierSelfSignedEveryCurve(t *testing.T) {
	for _, c := range bpCurves() {
		t.Run(c.name, func(t *testing.T) {
			key := genKey(t, c)
			cert, err := Parser(buildASN1Cert(t, key))
			if err != nil {
				t.Fatal(err)
			}
			if err := Verifier(cert, x509.ECDSAWithSHA256, cert.RawTBSCertificate, cert.Signature); err != nil {
				t.Fatalf("valid self-signature rejected: %v", err)
			}
			tampered := bytes.Clone(cert.RawTBSCertificate)
			tampered[len(tampered)-1] ^= 0x01
			if err := Verifier(cert, x509.ECDSAWithSHA256, tampered, cert.Signature); err == nil {
				t.Fatal("signature over a tampered TBS was accepted")
			}
			// A key from another curve must not verify the signature.
			other := bpCurves()[(indexOf(c.name)+1)%3]
			otherCert, err := Parser(buildASN1Cert(t, genKey(t, other)))
			if err != nil {
				t.Fatal(err)
			}
			if err := Verifier(otherCert, x509.ECDSAWithSHA256, cert.RawTBSCertificate, cert.Signature); err == nil {
				t.Fatal("signature verified under a different curve's key")
			}
		})
	}
}

func indexOf(name string) int {
	for i, c := range bpCurves() {
		if c.name == name {
			return i
		}
	}
	return -1
}

// A certificate that crypto/x509 (and so the gematik parser) cannot parse but
// whose SPKI is intact is still recognized through the raw-SPKI fallback and
// yields a minimal certificate carrying the key and the raw DER.
func TestParserSPKIFallbackEveryCurve(t *testing.T) {
	for _, c := range bpCurves() {
		t.Run(c.name, func(t *testing.T) {
			key := genKey(t, c)
			der := buildASN1CertOpts(t, key, certOpts{notBefore: "25AB01000000Z"})
			if _, err := gematik.ParseCertificate(der); err == nil {
				t.Fatal("test premise broken: gematik parses the corrupted certificate")
			}
			cert, err := Parser(der)
			if err != nil {
				t.Fatalf("Parser: %v", err)
			}
			assertSameKey(t, cert.PublicKey, &key.PublicKey, c.name)
			if !bytes.Equal(cert.Raw, der) {
				t.Error("Raw differs from the input DER")
			}
		})
	}
}

// A Brainpool key certified with a signature algorithm the stdlib knows but
// gematik's parser may not (RSASSA-PSS, no parameters) must still yield the
// Brainpool key.
func TestParserRSAPSSSignatureEveryCurve(t *testing.T) {
	for _, c := range bpCurves() {
		t.Run(c.name, func(t *testing.T) {
			key := genKey(t, c)
			der := buildASN1CertOpts(t, key, certOpts{sigAlgOID: oidRSAPSS})
			cert, err := Parser(der)
			if err != nil {
				t.Fatalf("Parser: %v", err)
			}
			assertSameKey(t, cert.PublicKey, &key.PublicKey, c.name)
			if !bytes.Equal(cert.Raw, der) {
				t.Error("Raw differs from the input DER")
			}
		})
	}
}

// Curve identification is by exact OID: certificates on anything else must be
// left to other parsers, never mapped onto a Brainpool curve.
func TestParserRejectsOtherCurves(t *testing.T) {
	key256 := genKey(t, bpCurves()[0])
	for name, oid := range map[string]asn1.ObjectIdentifier{
		"brainpoolP256t1 (twisted)": oidBP256t1,
		"brainpoolP384t1 (twisted)": oidBP384t1,
		"brainpoolP512t1 (twisted)": oidBP512t1,
		"prime256v1":                oidPrime256v1,
		"secp384r1":                 oidSecp384r1,
		"unknown OID":               {1, 3, 36, 3, 3, 2, 8, 1, 1, 99},
	} {
		// Both the regular path and the raw-SPKI fallback path (corrupted
		// validity) must leave such a certificate to other parsers.
		for path, nb := range map[string]string{"regular": "", "spki fallback": "25AB01000000Z"} {
			t.Run(name+"/"+path, func(t *testing.T) {
				der := buildASN1CertOpts(t, key256, certOpts{curveOID: oid, notBefore: nb})
				if _, err := Parser(der); !errors.Is(err, cryptoutil.ErrNotHandled) {
					t.Fatalf("got %v, want ErrNotHandled", err)
				}
			})
		}
	}
}

func TestParseBrainpoolSPKI(t *testing.T) {
	for _, c := range bpCurves() {
		key := genKey(t, c)
		point := uncompressed(c, &key.PublicKey)

		t.Run(c.name+"/valid", func(t *testing.T) {
			pub, err := parseBrainpoolSPKI(spkiDER(t, oidParam(t, c.oid), point))
			if err != nil {
				t.Fatal(err)
			}
			assertSameKey(t, pub, &key.PublicKey, c.name)
		})

		t.Run(c.name+"/curve OID must match exactly", func(t *testing.T) {
			// The same point under every other OID must never be accepted
			// as this curve; the other Brainpool r1 OIDs would only
			// succeed with a point of their own size, which this is not.
			for _, oid := range []asn1.ObjectIdentifier{oidBP256t1, oidBP384t1, oidBP512t1, oidPrime256v1, oidSecp384r1, {1, 3, 36, 3, 3, 2, 8, 1, 1, 99}} {
				if pub, err := parseBrainpoolSPKI(spkiDER(t, oidParam(t, oid), point)); err == nil {
					t.Errorf("accepted OID %v as %s", oid, pub.Curve.Params().Name)
				}
			}
		})

		t.Run(c.name+"/malformed point", func(t *testing.T) {
			for name, p := range map[string][]byte{
				"empty":       {},
				"too short":   point[:len(point)-1],
				"too long":    append(bytes.Clone(point), 0),
				"compressed":  append([]byte{2}, point[1:1+c.size]...),
				"wrong tag":   append([]byte{0x05}, point[1:]...),
				"hybrid form": append([]byte{0x06}, point[1:]...),
			} {
				if _, err := parseBrainpoolSPKI(spkiDER(t, oidParam(t, c.oid), p)); err == nil {
					t.Errorf("%s point accepted", name)
				}
			}
		})
	}

	t.Run("point not on the curve", func(t *testing.T) {
		for _, c := range bpCurves() {
			key := genKey(t, c)
			point := uncompressed(c, &key.PublicKey)
			point[len(point)-1] ^= 0x01 // y -> y+-1: off the curve
			if _, err := parseBrainpoolSPKI(spkiDER(t, oidParam(t, c.oid), point)); err == nil {
				t.Errorf("%s: off-curve point accepted", c.name)
			}
			// Coordinate >= p.
			point = uncompressed(c, &key.PublicKey)
			for i := 1; i <= c.size; i++ {
				point[i] = 0xFF
			}
			if _, err := parseBrainpoolSPKI(spkiDER(t, oidParam(t, c.oid), point)); err == nil {
				t.Errorf("%s: out-of-range coordinate accepted", c.name)
			}
		}
	})
	t.Run("explicit domain parameters are not a named curve", func(t *testing.T) {
		key := genKey(t, bpCurves()[0])
		explicit := asn1.RawValue{FullBytes: []byte{0x30, 0x03, 0x02, 0x01, 0x01}}
		if _, err := parseBrainpoolSPKI(spkiDER(t, explicit, uncompressed(bpCurves()[0], &key.PublicKey))); err == nil {
			t.Fatal("explicit parameters accepted")
		}
	})
	t.Run("garbage", func(t *testing.T) {
		if _, err := parseBrainpoolSPKI([]byte{1, 2, 3}); err == nil {
			t.Fatal("garbage accepted")
		}
	})
}

// sec1 builds a SEC 1 ECPrivateKey for key.
func sec1(t *testing.T, c bpCurve, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	pub := uncompressed(c, &key.PublicKey)
	der, err := asn1.Marshal(struct {
		Version       int
		PrivateKey    []byte
		NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
		PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
	}{1, key.D.FillBytes(make([]byte, c.size)), c.oid, asn1.BitString{Bytes: pub, BitLength: len(pub) * 8}})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestKeyParserEveryCurve(t *testing.T) {
	for _, c := range bpCurves() {
		t.Run(c.name, func(t *testing.T) {
			key := genKey(t, c)
			got, err := KeyParser(sec1(t, c, key))
			if err != nil {
				t.Fatal(err)
			}
			priv, ok := got.(*ecdsa.PrivateKey)
			if !ok {
				t.Fatalf("got %T", got)
			}
			if priv.Curve.Params().Name != c.name || priv.D.Cmp(key.D) != 0 {
				t.Error("parsed key differs")
			}
			assertSameKey(t, &priv.PublicKey, &key.PublicKey, c.name)
		})
	}

	t.Run("NIST key is not handled", func(t *testing.T) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := KeyParser(der); !errors.Is(err, cryptoutil.ErrNotHandled) {
			t.Fatalf("got %v, want ErrNotHandled", err)
		}
	})
	t.Run("garbage is not handled", func(t *testing.T) {
		if _, err := KeyParser([]byte{0x30, 0x01, 0x00}); !errors.Is(err, cryptoutil.ErrNotHandled) {
			t.Fatalf("got %v, want ErrNotHandled", err)
		}
	})
}
