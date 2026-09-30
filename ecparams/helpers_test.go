package ecparams

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// paramOpts lets tests build deliberately wrong ECParameters.
type paramOpts struct {
	version    int64
	fieldOID   asn1.ObjectIdentifier
	p, a, b, n *big.Int
	base       []byte // nil: uncompressed generator
	compressed bool
	cofactor   *int64 // nil: omit
	seed       bool
	trailing   bool
}

func defaultOpts(k *knownCurve) paramOpts {
	h := k.h
	return paramOpts{version: 1, fieldOID: oidPrimeField, p: k.p, a: k.a, b: k.b, n: k.n, cofactor: &h}
}

// encodeExplicitParams hand-encodes a SpecifiedECDomain for k.
func encodeExplicitParams(k *knownCurve, o paramOpts) []byte {
	l := k.byteLen()
	base := o.base
	if base == nil {
		switch {
		case o.compressed:
			base = append([]byte{0x02 | byte(k.gy.Bit(0))}, pad(k.gx, l)...)
		default:
			base = append([]byte{0x04}, pad(k.gx, l)...)
			base = append(base, pad(k.gy, l)...)
		}
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(o.version)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(o.fieldOID)
			b.AddASN1BigInt(o.p)
		})
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1OctetString(pad(o.a, l))
			b.AddASN1OctetString(pad(o.b, l))
			if o.seed {
				b.AddASN1BitString([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
			}
		})
		b.AddASN1OctetString(base)
		b.AddASN1BigInt(o.n)
		if o.cofactor != nil {
			b.AddASN1Int64(*o.cofactor)
		}
		if o.trailing {
			b.AddASN1Int64(7)
		}
	})
	out, err := b.Bytes()
	if err != nil {
		panic(err)
	}
	return out
}

func encodeSPKI(alg, point []byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddBytes(alg) })
		b.AddASN1BitString(point)
	})
	out, _ := b.Bytes()
	return out
}

func ecAlgBytes(params []byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1ObjectIdentifier(oidECPublicKey)
	b.AddBytes(params)
	out, _ := b.Bytes()
	return out
}

// explicitSPKI encodes pub as an SPKI with explicit parameters.
func explicitSPKI(k *knownCurve, pub *ecdsa.PublicKey, params []byte) []byte {
	l := k.byteLen()
	pt := append([]byte{0x04}, pad(pub.X, l)...) //nolint:staticcheck // SA1019: raw coordinates needed to encode the test SPKI
	pt = append(pt, pad(pub.Y, l)...)            //nolint:staticcheck // SA1019: see above
	return encodeSPKI(ecAlgBytes(params), pt)
}

var (
	oidECDSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSASHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSASHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidSHA256RSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
)

// sigAlgFor chooses the ECDSA hash matching the curve size.
func sigAlgFor(k *knownCurve) (asn1.ObjectIdentifier, crypto.Hash, x509.SignatureAlgorithm) {
	switch {
	case k.p.BitLen() <= 256:
		return oidECDSASHA256, crypto.SHA256, x509.ECDSAWithSHA256
	case k.p.BitLen() <= 384:
		return oidECDSASHA384, crypto.SHA384, x509.ECDSAWithSHA384
	default:
		return oidECDSASHA512, crypto.SHA512, x509.ECDSAWithSHA512
	}
}

func encodeName(cn string) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(asn1.ObjectIdentifier{2, 5, 4, 3})
				b.AddASN1(cbasn1.UTF8String, func(b *cryptobyte.Builder) { b.AddBytes([]byte(cn)) })
			})
		})
	})
	out, _ := b.Bytes()
	return out
}

// encodeTBS builds a v3 TBSCertificate (with a basicConstraints CA extension)
// around the given raw serial INTEGER content, signature-algorithm OID and SPKI.
func encodeTBS(serial []byte, sigOID asn1.ObjectIdentifier, sigNull bool, spki []byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) { b.AddASN1Int64(2) })
		b.AddASN1(cbasn1.INTEGER, func(b *cryptobyte.Builder) { b.AddBytes(serial) })
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(sigOID)
			if sigNull {
				b.AddASN1NULL()
			}
		})
		b.AddBytes(encodeName("Test CSCA"))
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.UTCTime, func(b *cryptobyte.Builder) { b.AddBytes([]byte("200101000000Z")) })
			b.AddASN1(cbasn1.UTCTime, func(b *cryptobyte.Builder) { b.AddBytes([]byte("400101000000Z")) })
		})
		b.AddBytes(encodeName("Test CSCA"))
		b.AddBytes(spki)
		// extensions [3] { SEQUENCE { basicConstraints critical CA:TRUE } }
		b.AddASN1(cbasn1.Tag(3).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1ObjectIdentifier(asn1.ObjectIdentifier{2, 5, 29, 19})
					b.AddASN1Boolean(true)
					b.AddASN1OctetString([]byte{0x30, 0x03, 0x01, 0x01, 0xff})
				})
			})
		})
	})
	out, err := b.Bytes()
	if err != nil {
		panic(err)
	}
	return out
}

func assemble(tbs []byte, sigOID asn1.ObjectIdentifier, sigNull bool, sig []byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(tbs)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(sigOID)
			if sigNull {
				b.AddASN1NULL()
			}
		})
		b.AddASN1BitString(sig)
	})
	out, _ := b.Bytes()
	return out
}

func hashSum(h crypto.Hash, data []byte) []byte {
	hh := h.New()
	hh.Write(data)
	return hh.Sum(nil)
}

// ecFixture is a self-signed explicit-parameter certificate and its key.
type ecFixture struct {
	k    *knownCurve
	key  *ecdsa.PrivateKey
	der  []byte
	tbs  []byte
	sig  []byte
	algo x509.SignatureAlgorithm
}

// newExplicitCert builds a self-signed certificate whose SPKI carries params
// (hand-encoded). The key is generated on k.
func newExplicitCert(t testing.TB, k *knownCurve, params []byte, serial []byte) *ecFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(k.curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate key on %s: %v", k.name, err)
	}
	sigOID, hash, algo := sigAlgFor(k)
	tbs := encodeTBS(serial, sigOID, false, explicitSPKI(k, &key.PublicKey, params))
	sig, err := ecdsa.SignASN1(rand.Reader, key, hashSum(hash, tbs))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return &ecFixture{k: k, key: key, der: assemble(tbs, sigOID, false, sig), tbs: tbs, sig: sig, algo: algo}
}

func mustCurve(t testing.TB, name string) *knownCurve {
	t.Helper()
	k := curveByName(name)
	if k == nil {
		t.Fatalf("unknown curve %s", name)
	}
	return k
}

// newRSACert builds a self-signed RSA certificate. If dropNull, the RSA
// AlgorithmIdentifier in the SPKI omits the NULL parameters (as some old
// eMRTD PKI does); the signature is computed over that exact TBS.
func newRSACert(t testing.TB, dropNull bool) (der []byte, key *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if dropNull {
		a, err := parseSPKIAlgorithm(spki)
		if err != nil {
			t.Fatal(err)
		}
		var b cryptobyte.Builder
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(a.oid) })
			b.AddBytes(a.keyEl)
		})
		spki, _ = b.Bytes()
	}
	tbs := encodeTBS([]byte{0x01}, oidSHA256RSA, true, spki)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashSum(crypto.SHA256, tbs))
	if err != nil {
		t.Fatal(err)
	}
	return assemble(tbs, oidSHA256RSA, true, sig), key
}

func mustKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(mustCurve(t, "P-256").curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mustMarshalPKIX(t testing.TB, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func sigHash() crypto.Hash { return crypto.SHA256 }

// onKnownCurve reports whether pub is a key on one of the known curves, using
// the raw coordinates (the only way to inspect keys on custom curves).
func onKnownCurve(pub *ecdsa.PublicKey) bool {
	k := curveByName(pub.Curve.Params().Name)
	return k != nil && k.onCurve(pub.X, pub.Y) //nolint:staticcheck // SA1019: raw coordinates needed
}
