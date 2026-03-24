package cryptoutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
)

func TestParseCertificateStdlib(t *testing.T) {
	ext := New()
	cert := generateSelfSignedCert(t, elliptic.P256())
	parsed, err := ext.ParseCertificate(cert.Raw)
	if err != nil {
		t.Fatalf("failed to parse standard cert: %v", err)
	}
	if parsed.Subject.CommonName != "test" {
		t.Errorf("expected CN=test, got %q", parsed.Subject.CommonName)
	}
}

func TestParseCertificateWithExtension(t *testing.T) {
	ext := New()
	// Register a parser that handles a fake "custom" cert
	called := false
	ext.Parsers = append(ext.Parsers, func(der []byte) (*x509.Certificate, error) {
		called = true
		// Pretend we can parse it
		return &x509.Certificate{
			Subject: pkix.Name{CommonName: "custom-parsed"},
		}, nil
	})

	// Feed it garbage that stdlib can't parse
	cert, err := ext.ParseCertificate([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	if err != nil {
		t.Fatalf("expected custom parser to succeed, got: %v", err)
	}
	if !called {
		t.Error("custom parser was not called")
	}
	if cert.Subject.CommonName != "custom-parsed" {
		t.Errorf("expected CN=custom-parsed, got %q", cert.Subject.CommonName)
	}
}

func TestParseCertificateErrNotHandled(t *testing.T) {
	ext := New()
	ext.Parsers = append(ext.Parsers, func(der []byte) (*x509.Certificate, error) {
		return nil, ErrNotHandled
	})

	_, err := ext.ParseCertificate([]byte{0xDE, 0xAD})
	if err == nil {
		t.Error("expected error when all parsers return ErrNotHandled")
	}
}

func TestCheckSignatureStdlib(t *testing.T) {
	ext := New()
	cert := generateSelfSignedCert(t, elliptic.P256())

	// Self-signed cert: the TBS is signed by its own key.
	// We can verify by calling CheckSignature on itself.
	err := ext.CheckSignature(cert, cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		t.Fatalf("standard CheckSignature failed: %v", err)
	}
}

func TestCheckSignatureWithExtension(t *testing.T) {
	ext := New()
	verifyCalled := false
	ext.Verifiers = append(ext.Verifiers, func(cert *x509.Certificate, algo x509.SignatureAlgorithm, signed, sig []byte) error {
		verifyCalled = true
		return nil // always succeeds
	})

	// Use a cert that stdlib can't verify (pass wrong data)
	cert := generateSelfSignedCert(t, elliptic.P256())
	err := ext.CheckSignature(cert, cert.SignatureAlgorithm, []byte("wrong data"), cert.Signature)
	if err != nil {
		t.Fatalf("expected extension verifier to succeed, got: %v", err)
	}
	if !verifyCalled {
		t.Error("extension verifier was not called")
	}
}

func TestAlgorithmRegistryForKey(t *testing.T) {
	reg := NewAlgorithmRegistry()

	// EC P-256
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	alg, err := reg.ForKey(&ecKey.PublicKey)
	if err != nil {
		t.Fatalf("ForKey P-256: %v", err)
	}
	if alg.JWS != "ES256" {
		t.Errorf("expected ES256, got %s", alg.JWS)
	}

	// EC P-384
	ecKey384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	alg, err = reg.ForKey(&ecKey384.PublicKey)
	if err != nil {
		t.Fatalf("ForKey P-384: %v", err)
	}
	if alg.JWS != "ES384" {
		t.Errorf("expected ES384, got %s", alg.JWS)
	}

	// JWS convenience
	jws, err := reg.JWSAlgorithm(&ecKey.PublicKey)
	if err != nil {
		t.Fatalf("JWSAlgorithm: %v", err)
	}
	if jws != "ES256" {
		t.Errorf("expected ES256, got %s", jws)
	}

	// XMLDSIG convenience
	xmldsig, err := reg.XMLDSIGAlgorithm(&ecKey.PublicKey)
	if err != nil {
		t.Fatalf("XMLDSIGAlgorithm: %v", err)
	}
	if xmldsig != "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256" {
		t.Errorf("unexpected XMLDSIG: %s", xmldsig)
	}
}

func TestECDSAComponentSize(t *testing.T) {
	tests := []struct {
		curve elliptic.Curve
		want  int
	}{
		{elliptic.P256(), 32},
		{elliptic.P384(), 48},
		{elliptic.P521(), 66},
	}
	for _, tc := range tests {
		got := ECDSAComponentSize(tc.curve)
		if got != tc.want {
			t.Errorf("ECDSAComponentSize(%s) = %d, want %d", tc.curve.Params().Name, got, tc.want)
		}
	}
}

func generateSelfSignedCert(t *testing.T, curve elliptic.Curve) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
