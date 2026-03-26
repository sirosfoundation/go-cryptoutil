package cryptoutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
)

func TestNormalizeECDSASignature_ValidDER(t *testing.T) {
	// Generate a valid signature
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	data := []byte("test data")
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Encode as proper DER
	sig, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Normalize should return equivalent signature
	normalized, err := NormalizeECDSASignature(sig)
	if err != nil {
		t.Fatalf("NormalizeECDSASignature failed: %v", err)
	}

	// Should be valid DER (may or may not be identical bytes)
	var parsed struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(normalized, &parsed); err != nil {
		t.Fatalf("normalized signature not valid ASN.1: %v", err)
	}
	if parsed.R.Cmp(r) != 0 || parsed.S.Cmp(s) != 0 {
		t.Error("normalized signature has different r/s values")
	}
}

func TestNormalizeECDSASignature_BERWithLeadingZeros(t *testing.T) {
	// Construct a BER-encoded signature with unnecessary leading zeros in r
	// This simulates what YubiKey 5.8 might produce
	r := big.NewInt(123456789)
	s := big.NewInt(987654321)

	// Manually construct BER with extra zero padding in r
	// Normal DER for r=123456789 is 04 bytes: 07 5B CD 15
	// BER might encode it with leading zeros: 00 07 5B CD 15
	rBytes := []byte{0x00, 0x07, 0x5B, 0xCD, 0x15} // BER with unnecessary leading zero
	sBytes := s.Bytes()

	// Construct the ASN.1 SEQUENCE manually with BER integers
	berSig := constructBERSignature(rBytes, sBytes)

	// Go's strict DER parser might reject this or parse it differently
	// NormalizeECDSASignature should handle it
	normalized, err := NormalizeECDSASignature(berSig)
	if err != nil {
		t.Fatalf("NormalizeECDSASignature failed on BER input: %v", err)
	}

	// Verify it parses correctly
	var parsed struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(normalized, &parsed); err != nil {
		t.Fatalf("normalized signature not valid ASN.1: %v", err)
	}

	// The r value should still be correct (leading zeros stripped)
	if parsed.R.Cmp(r) != 0 {
		t.Errorf("r mismatch: got %v, want %v", parsed.R, r)
	}
	if parsed.S.Cmp(s) != 0 {
		t.Errorf("s mismatch: got %v, want %v", parsed.S, s)
	}
}

// constructBERSignature manually constructs an ASN.1 SEQUENCE with the given
// integer bytes. This bypasses Go's asn1.Marshal which produces strict DER.
func constructBERSignature(rBytes, sBytes []byte) []byte {
	// SEQUENCE tag
	const tagSequence = 0x30

	// Encode r as INTEGER
	rInt := encodeASN1Integer(rBytes)
	// Encode s as INTEGER
	sInt := encodeASN1Integer(sBytes)

	// Total content length
	contentLen := len(rInt) + len(sInt)

	// Build SEQUENCE
	result := make([]byte, 0, 2+contentLen)
	result = append(result, tagSequence)
	result = append(result, byte(contentLen))
	result = append(result, rInt...)
	result = append(result, sInt...)

	return result
}

// encodeASN1Integer encodes bytes as an ASN.1 INTEGER (preserving leading zeros)
func encodeASN1Integer(b []byte) []byte {
	const tagInteger = 0x02
	result := make([]byte, 0, 2+len(b))
	result = append(result, tagInteger)
	result = append(result, byte(len(b)))
	result = append(result, b...)
	return result
}

func TestBERTolerantECDSAVerifier_ValidSignature(t *testing.T) {
	// Generate a test certificate and key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create a minimal self-signed cert for testing
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}

	// Sign some data
	data := []byte("test data to sign")
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	sig, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatalf("failed to marshal sig: %v", err)
	}

	// Create verifier and test
	verifier := BERTolerantECDSAVerifier()
	err = verifier(cert, x509.ECDSAWithSHA256, data, sig)
	if err != nil {
		t.Errorf("BERTolerantECDSAVerifier failed: %v", err)
	}
}

func TestBERTolerantECDSAVerifier_ReturnsNotHandledForRSA(t *testing.T) {
	verifier := BERTolerantECDSAVerifier()
	err := verifier(nil, x509.SHA256WithRSA, nil, nil)
	if !errors.Is(err, ErrNotHandled) {
		t.Errorf("expected ErrNotHandled for RSA algorithm, got %v", err)
	}
}

func TestNormalizeECDSASignature_InvalidInput(t *testing.T) {
	tests := []struct {
		name string
		sig  []byte
	}{
		{"empty", []byte{}},
		{"garbage", []byte{0x01, 0x02, 0x03}},
		{"truncated", []byte{0x30, 0x10}}, // SEQUENCE with wrong length
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NormalizeECDSASignature(tt.sig)
			if err == nil {
				t.Error("expected error for invalid input")
			}
		})
	}
}

func TestNormalizeECDSASignature_Idempotent(t *testing.T) {
	// A valid DER signature should normalize to itself (or equivalent)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hash := sha256.Sum256([]byte("data"))
	r, s, _ := ecdsa.Sign(rand.Reader, priv, hash[:])
	sig, _ := asn1.Marshal(struct{ R, S *big.Int }{r, s})

	norm1, err := NormalizeECDSASignature(sig)
	if err != nil {
		t.Fatalf("first normalize failed: %v", err)
	}

	norm2, err := NormalizeECDSASignature(norm1)
	if err != nil {
		t.Fatalf("second normalize failed: %v", err)
	}

	if !bytes.Equal(norm1, norm2) {
		t.Error("normalization is not idempotent")
	}
}
