package pkcs11pool

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"testing"
)

// A raw r||s whose r happens to start with 0x30 must not be mistaken for DER.
// Before the fix this failed for one signature in 256.
func TestRawSigToASN1DoesNotSniffTheFirstByte(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for i := 0; i < 20000 && !found; i++ {
		digest := sha256.Sum256([]byte{byte(i), byte(i >> 8)})
		r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		raw := make([]byte, 64)
		r.FillBytes(raw[:32])
		s.FillBytes(raw[32:])
		if raw[0] != 0x30 {
			continue
		}
		found = true
		der, err := RawSigToASN1(raw)
		if err != nil {
			t.Fatalf("RawSigToASN1: %v", err)
		}
		if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], der) {
			t.Fatalf("raw signature starting with 0x30 was returned as if it were DER and does not verify")
		}
	}
	if !found {
		t.Skip("no signature with r[0]==0x30 in 20000 draws; statistically ~1e-34")
	}
}

func TestRawSigToASN1ConvertsEveryCurveSize(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P224(), elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		n := (curve.Params().BitSize + 7) / 8
		for i := 0; i < 50; i++ {
			digest := sha256.Sum256([]byte{byte(i)})
			r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
			if err != nil {
				t.Fatal(err)
			}
			raw := make([]byte, 2*n)
			r.FillBytes(raw[:n])
			s.FillBytes(raw[n:])
			der, err := RawSigToASN1(raw)
			if err != nil {
				t.Fatalf("%s: %v", curve.Params().Name, err)
			}
			if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], der) {
				t.Fatalf("%s: converted signature does not verify", curve.Params().Name)
			}
		}
	}
}

func TestRawSigToASN1PassesGenuineDERThrough(t *testing.T) {
	type ecdsaSig struct{ R, S *big.Int }
	// Lengths that are not a raw r||s size, with a valid DER body.
	der, err := asn1.Marshal(ecdsaSig{R: big.NewInt(0x7fffffff), S: big.NewInt(0x12345678)})
	if err != nil {
		t.Fatal(err)
	}
	got, err := RawSigToASN1(der)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(der) {
		t.Errorf("genuine DER was re-encoded")
	}
	if _, err := RawSigToASN1([]byte{0x30, 0x01, 0x02}); err == nil {
		t.Error("an odd-length buffer that is not DER should be rejected")
	}
}

// A P-224 DER signature whose r and s both carry the positive-sign pad is
// exactly 64 bytes, the same as a raw P-256 signature. Only the curve-aware
// conversion can tell them apart; this pins that it does.
func TestRawSigToASN1ForCurveDisambiguatesByCurve(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	type ecdsaSig struct{ R, S *big.Int }
	var der []byte
	var digest [32]byte
	for i := 0; i < 5000; i++ {
		digest = sha256.Sum256([]byte{byte(i), byte(i >> 8)})
		r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		d, err := asn1.Marshal(ecdsaSig{R: r, S: s})
		if err != nil {
			t.Fatal(err)
		}
		if len(d) == 64 {
			der = d
			break
		}
	}
	if der == nil {
		t.Skip("no 64-byte P-224 DER signature in 5000 draws (expected 1 in 4)")
	}
	got, err := RawSigToASN1ForCurve(der, elliptic.P224())
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], got) {
		t.Fatal("64-byte P-224 DER signature was not recognised as DER for P-224")
	}

	// And a genuine raw P-256 signature of the same length is still converted.
	k256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	r, s, _ := ecdsa.Sign(rand.Reader, k256, digest[:])
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	got, err = RawSigToASN1ForCurve(raw, elliptic.P256())
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(&k256.PublicKey, digest[:], got) {
		t.Fatal("raw P-256 signature did not convert")
	}
	if _, err := RawSigToASN1ForCurve(raw[:60], elliptic.P256()); err == nil {
		t.Error("a 60-byte buffer that is neither r||s nor DER should be rejected")
	}
}
