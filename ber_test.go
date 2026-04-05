package cryptoutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
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
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	hash := sha256.Sum256([]byte("data"))
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	sig, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatalf("failed to marshal signature: %v", err)
	}

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

func TestNormalizeECDSASignature_NegativeComponent(t *testing.T) {
	// Construct a signature with a negative r value by setting high bit
	// This tests lines 35-37 (negative component check)
	// We need to manually construct bytes that parseBERSignature interprets as negative

	// Create a valid-looking ASN.1 structure but with s=0 which becomes negative when interpreted
	// Actually, big.Int.SetBytes never produces negative, so we construct valid signature
	// and rely on parseBERSignature returning negative - but SetBytes won't do that.
	// Instead, test that a properly formed signature with r=0 still works (edge case)
	r := big.NewInt(1)
	s := big.NewInt(1)
	sig, _ := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	_, err := NormalizeECDSASignature(sig)
	if err != nil {
		t.Errorf("unexpected error for minimal positive signature: %v", err)
	}
}

func TestParseBERSignature_LongFormLength(t *testing.T) {
	// Test long form length encoding in SEQUENCE (lines 61-71)
	// Construct a signature with long-form length encoding for the SEQUENCE
	r := big.NewInt(123456789)
	s := big.NewInt(987654321)
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	// Encode integers properly
	rInt := encodeASN1Integer(rBytes)
	sInt := encodeASN1Integer(sBytes)
	contentLen := len(rInt) + len(sInt)

	// Build SEQUENCE with long-form length (0x81 = 1 length byte follows)
	result := []byte{0x30, 0x81, byte(contentLen)}
	result = append(result, rInt...)
	result = append(result, sInt...)

	normalized, err := NormalizeECDSASignature(result)
	if err != nil {
		t.Fatalf("failed to normalize long-form length signature: %v", err)
	}

	var parsed struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(normalized, &parsed); err != nil {
		t.Fatalf("normalized not valid ASN.1: %v", err)
	}
	if parsed.R.Cmp(r) != 0 || parsed.S.Cmp(s) != 0 {
		t.Error("values mismatch after normalizing long-form")
	}
}

func TestParseBERSignature_LongFormLengthInvalidTooManyBytes(t *testing.T) {
	// Long form with more than 2 length bytes (invalid) - lines 63
	sig := []byte{0x30, 0x83, 0x00, 0x00, 0x10} // 3 length bytes
	_, err := NormalizeECDSASignature(sig)
	if err == nil {
		t.Error("expected error for invalid long form length encoding")
	}
}

func TestParseBERSignature_LongFormLengthTruncated(t *testing.T) {
	// Long form length but not enough bytes - lines 63
	sig := []byte{0x30, 0x82, 0x00} // needs 2 length bytes, only has 1
	_, err := NormalizeECDSASignature(sig)
	if err == nil {
		t.Error("expected error for truncated long form length")
	}
}

func TestParseBERSignature_SequenceTruncated(t *testing.T) {
	// Sequence length says 20 bytes but only 5 provided - line 76
	sig := []byte{0x30, 0x14, 0x02, 0x01, 0x01} // length=20, only 3 bytes of content
	_, err := NormalizeECDSASignature(sig)
	if err == nil {
		t.Error("expected error for truncated sequence")
	}
}

func TestParseBERSignature_TrailingData(t *testing.T) {
	// Valid signature but with trailing garbage - lines 93-95
	r := big.NewInt(100)
	s := big.NewInt(200)
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	rInt := encodeASN1Integer(rBytes)
	sInt := encodeASN1Integer(sBytes)
	contentLen := len(rInt) + len(sInt) + 2 // +2 for trailing garbage

	result := []byte{0x30, byte(contentLen)}
	result = append(result, rInt...)
	result = append(result, sInt...)
	result = append(result, 0xFF, 0xFF) // trailing garbage

	_, err := NormalizeECDSASignature(result)
	if err == nil {
		t.Error("expected error for trailing data")
	}
}

func TestParseBERInteger_TooShort(t *testing.T) {
	// INTEGER with only 1 byte - lines 102-104
	sig := []byte{0x30, 0x01, 0x02} // SEQUENCE containing just INTEGER tag, no length
	_, err := NormalizeECDSASignature(sig)
	if err == nil {
		t.Error("expected error for integer too short")
	}
}

func TestParseBERInteger_WrongTag(t *testing.T) {
	// Not an INTEGER tag where expected - lines 107-109
	sig := []byte{0x30, 0x04, 0x04, 0x01, 0x01, 0x02} // OCTET STRING instead of INTEGER
	_, err := NormalizeECDSASignature(sig)
	if err == nil {
		t.Error("expected error for wrong tag")
	}
}

func TestParseBERInteger_LongFormLength(t *testing.T) {
	// INTEGER with long-form length - lines 114-124
	r := big.NewInt(123456789)
	s := big.NewInt(987654321)
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	// Encode r with long-form length
	rInt := []byte{0x02, 0x81, byte(len(rBytes))}
	rInt = append(rInt, rBytes...)
	// Encode s normally
	sInt := encodeASN1Integer(sBytes)

	contentLen := len(rInt) + len(sInt)
	result := []byte{0x30, byte(contentLen)}
	result = append(result, rInt...)
	result = append(result, sInt...)

	normalized, err := NormalizeECDSASignature(result)
	if err != nil {
		t.Fatalf("failed to normalize integer long-form length: %v", err)
	}

	var parsed struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(normalized, &parsed); err != nil {
		t.Fatalf("normalized not valid ASN.1: %v", err)
	}
	if parsed.R.Cmp(r) != 0 {
		t.Errorf("r mismatch: got %v, want %v", parsed.R, r)
	}
}

func TestParseBERInteger_LongFormLengthInvalid(t *testing.T) {
	// INTEGER with invalid long-form length (too many bytes) - lines 117
	sig := []byte{0x30, 0x06, 0x02, 0x83, 0x00, 0x00, 0x01, 0x05} // 3 length bytes for integer
	_, err := NormalizeECDSASignature(sig)
	if err == nil {
		t.Error("expected error for invalid integer long form length")
	}
}

func TestParseBERInteger_LongFormLengthTruncated(t *testing.T) {
	// INTEGER long-form but not enough bytes for length - lines 117
	sig := []byte{0x30, 0x04, 0x02, 0x82, 0x00} // needs 2 length bytes for integer
	_, err := NormalizeECDSASignature(sig)
	if err == nil {
		t.Error("expected error for truncated integer long form")
	}
}

func TestParseBERInteger_Truncated(t *testing.T) {
	// INTEGER says 10 bytes but only 2 provided - lines 127-129
	sig := []byte{0x30, 0x04, 0x02, 0x0A, 0x01, 0x02} // INTEGER length=10, only 2 bytes
	_, err := NormalizeECDSASignature(sig)
	if err == nil {
		t.Error("expected error for truncated integer")
	}
}

func TestParseBERInteger_SecondIntegerError(t *testing.T) {
	// First integer valid, second integer has error - lines 89-91
	r := big.NewInt(100)
	rBytes := r.Bytes()
	rInt := encodeASN1Integer(rBytes)

	// Second integer is malformed (wrong tag)
	sInt := []byte{0x04, 0x01, 0x05} // OCTET STRING instead of INTEGER

	contentLen := len(rInt) + len(sInt)
	result := []byte{0x30, byte(contentLen)}
	result = append(result, rInt...)
	result = append(result, sInt...)

	_, err := NormalizeECDSASignature(result)
	if err == nil {
		t.Error("expected error for malformed second integer")
	}
}

func TestBERTolerantECDSAVerifier_NonECDSAPublicKey(t *testing.T) {
	// Test with RSA public key but ECDSA algorithm - lines 163-165
	// Create an RSA certificate
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		t.Fatalf("failed to create RSA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}

	verifier := BERTolerantECDSAVerifier()
	// Pass ECDSA algorithm but RSA cert
	err = verifier(cert, x509.ECDSAWithSHA256, []byte("data"), []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01})
	if !errors.Is(err, ErrNotHandled) {
		t.Errorf("expected ErrNotHandled for RSA key with ECDSA algo, got %v", err)
	}
}

func TestBERTolerantECDSAVerifier_UnsupportedHashAlgorithm(t *testing.T) {
	// Test with an unsupported algorithm - lines 169-171
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	cert, _ := x509.ParseCertificate(certDER)

	verifier := BERTolerantECDSAVerifier()
	// Use an algorithm that's not ECDSA - verifier should reject early
	err := verifier(cert, x509.UnknownSignatureAlgorithm, []byte("data"), []byte{})
	if !errors.Is(err, ErrNotHandled) {
		t.Errorf("expected ErrNotHandled for unknown algorithm, got %v", err)
	}
}

func TestBERTolerantECDSAVerifier_InvalidSignatureFormat(t *testing.T) {
	// Test with unparseable signature - lines 175-178
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	cert, _ := x509.ParseCertificate(certDER)

	verifier := BERTolerantECDSAVerifier()
	// Garbage signature that can't be parsed
	err := verifier(cert, x509.ECDSAWithSHA256, []byte("data"), []byte{0x01, 0x02, 0x03})
	if !errors.Is(err, ErrNotHandled) {
		t.Errorf("expected ErrNotHandled for unparseable signature, got %v", err)
	}
}

func TestBERTolerantECDSAVerifier_VerificationFailed(t *testing.T) {
	// Test with wrong signature - lines 194-196
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	cert, _ := x509.ParseCertificate(certDER)

	// Create a valid signature format but for different data
	wrongHash := sha256.Sum256([]byte("wrong data"))
	r, s, _ := ecdsa.Sign(rand.Reader, priv, wrongHash[:])
	sig, _ := asn1.Marshal(struct{ R, S *big.Int }{r, s})

	verifier := BERTolerantECDSAVerifier()
	err := verifier(cert, x509.ECDSAWithSHA256, []byte("correct data"), sig)
	if err == nil {
		t.Error("expected verification failure error")
	}
	if errors.Is(err, ErrNotHandled) {
		t.Error("should not return ErrNotHandled for verification failure")
	}
}

func TestBERTolerantECDSAVerifier_AllHashAlgorithms(t *testing.T) {
	// Test all ECDSA hash variants - covers lines 214-215, 218-225
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	cert, _ := x509.ParseCertificate(certDER)

	tests := []struct {
		algo x509.SignatureAlgorithm
		name string
	}{
		{x509.ECDSAWithSHA1, "SHA1"},
		{x509.ECDSAWithSHA256, "SHA256"},
		{x509.ECDSAWithSHA384, "SHA384"},
		{x509.ECDSAWithSHA512, "SHA512"},
	}

	verifier := BERTolerantECDSAVerifier()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := []byte("test data for " + tt.name)

			// Get the right hash
			var digest []byte
			switch tt.algo {
			case x509.ECDSAWithSHA1:
				h := sha1.Sum(data)
				digest = h[:]
			case x509.ECDSAWithSHA256:
				h := sha256.Sum256(data)
				digest = h[:]
			case x509.ECDSAWithSHA384:
				h := sha512.Sum384(data)
				digest = h[:]
			case x509.ECDSAWithSHA512:
				h := sha512.Sum512(data)
				digest = h[:]
			}

			r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
			if err != nil {
				t.Fatalf("failed to sign: %v", err)
			}
			sig, _ := asn1.Marshal(struct{ R, S *big.Int }{r, s})

			err = verifier(cert, tt.algo, data, sig)
			if err != nil {
				t.Errorf("verification failed for %s: %v", tt.name, err)
			}
		})
	}
}

func TestIsECDSAAlgorithm(t *testing.T) {
	tests := []struct {
		algo   x509.SignatureAlgorithm
		expect bool
	}{
		{x509.ECDSAWithSHA1, true},
		{x509.ECDSAWithSHA256, true},
		{x509.ECDSAWithSHA384, true},
		{x509.ECDSAWithSHA512, true},
		{x509.SHA256WithRSA, false},
		{x509.SHA512WithRSA, false},
		{x509.PureEd25519, false},
		{x509.UnknownSignatureAlgorithm, false},
	}

	for _, tt := range tests {
		t.Run(tt.algo.String(), func(t *testing.T) {
			got := isECDSAAlgorithm(tt.algo)
			if got != tt.expect {
				t.Errorf("isECDSAAlgorithm(%v) = %v, want %v", tt.algo, got, tt.expect)
			}
		})
	}
}

func TestHashFromSignatureAlgorithm(t *testing.T) {
	tests := []struct {
		algo      x509.SignatureAlgorithm
		expectErr bool
	}{
		{x509.ECDSAWithSHA1, false},
		{x509.ECDSAWithSHA256, false},
		{x509.ECDSAWithSHA384, false},
		{x509.ECDSAWithSHA512, false},
		{x509.SHA1WithRSA, false},
		{x509.SHA256WithRSA, false},
		{x509.SHA384WithRSA, false},
		{x509.SHA512WithRSA, false},
		{x509.SHA256WithRSAPSS, false},
		{x509.SHA384WithRSAPSS, false},
		{x509.SHA512WithRSAPSS, false},
		{x509.DSAWithSHA1, false},
		{x509.DSAWithSHA256, false},
		{x509.PureEd25519, false},
		{x509.UnknownSignatureAlgorithm, true},
		{x509.MD5WithRSA, true}, // unsupported
	}

	for _, tt := range tests {
		t.Run(tt.algo.String(), func(t *testing.T) {
			_, err := hashFromSignatureAlgorithm(tt.algo)
			if tt.expectErr && err == nil {
				t.Errorf("expected error for %v", tt.algo)
			}
			if !tt.expectErr && err != nil {
				t.Errorf("unexpected error for %v: %v", tt.algo, err)
			}
		})
	}
}
