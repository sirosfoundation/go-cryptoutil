package cryptoutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestECDSARawToASN1Roundtrip(t *testing.T) {
	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			msg := []byte("test message for ECDSA roundtrip")
			hash := hashData(msg)

			// Sign → ASN.1
			asn1Sig, err := ecdsa.SignASN1(rand.Reader, key, hash)
			if err != nil {
				t.Fatal(err)
			}

			componentSize := ECDSAComponentSize(tc.curve)

			// ASN.1 → Raw
			raw, err := ECDSAASN1ToRaw(asn1Sig, componentSize)
			if err != nil {
				t.Fatal(err)
			}
			if len(raw) != 2*componentSize {
				t.Fatalf("expected raw length %d, got %d", 2*componentSize, len(raw))
			}

			// Raw → ASN.1
			asn1Again, err := ECDSARawToASN1(raw)
			if err != nil {
				t.Fatal(err)
			}

			// Verify the round-tripped ASN.1 signature
			if !ecdsa.VerifyASN1(&key.PublicKey, hash, asn1Again) {
				t.Fatal("round-tripped ASN.1 signature did not verify")
			}
		})
	}
}

func TestECDSARawToASN1EdgeCases(t *testing.T) {
	// Empty input
	_, err := ECDSARawToASN1(nil)
	if err == nil {
		t.Error("expected error for nil input")
	}

	_, err = ECDSARawToASN1([]byte{})
	if err == nil {
		t.Error("expected error for empty input")
	}

	// Odd length
	_, err = ECDSARawToASN1([]byte{1, 2, 3})
	if err == nil {
		t.Error("expected error for odd-length input")
	}

	// Valid input
	_, err = ECDSARawToASN1([]byte{0, 1, 0, 2})
	if err != nil {
		t.Errorf("unexpected error for valid input: %v", err)
	}
}

func TestECDSAASN1ToRawEdgeCases(t *testing.T) {
	// Invalid ASN.1
	_, err := ECDSAASN1ToRaw([]byte{0xFF, 0xFF}, 32)
	if err == nil {
		t.Error("expected error for invalid ASN.1")
	}
}

func hashData(data []byte) []byte {
	h := make([]byte, 32)
	copy(h, data)
	return h
}
