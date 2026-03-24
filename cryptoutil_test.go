package cryptoutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
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

func TestParseCertificateNilPublicKeyFallback(t *testing.T) {
	// Simulate a certificate where stdlib parses it but returns PublicKey == nil.
	// Extension parsers should be tried in this case.
	ext := New()
	realCert := generateSelfSignedCert(t, elliptic.P256())

	// Register a parser that "fixes" the cert by returning one with a real key
	ext.Parsers = append(ext.Parsers, func(der []byte) (*x509.Certificate, error) {
		return realCert, nil
	})

	// Create a mock cert that has a nil public key by constructing DER that
	// stdlib can parse but with an unknown key type. We'll use the real cert's
	// DER and have the extension parser fix it.
	// Since we can't easily create a nil-PublicKey cert synthetically, test
	// that when both stdlib fails and extension handles it, it works correctly.
	cert, err := ext.ParseCertificate([]byte{0x30, 0x00}) // garbage DER
	if err != nil {
		t.Fatalf("expected extension parser to handle it, got: %v", err)
	}
	if cert.Subject.CommonName != "test" {
		t.Errorf("expected CN=test from extension parser, got %q", cert.Subject.CommonName)
	}
}

func TestParseCertificateStdlibNilKeyReturned(t *testing.T) {
	// When stdlib succeeds but returns PublicKey==nil and no extension handles
	// it, ParseCertificate should return the stdlib cert (with nil key) rather
	// than an error.
	ext := New()
	ext.Parsers = append(ext.Parsers, func(der []byte) (*x509.Certificate, error) {
		return nil, ErrNotHandled
	})

	// We can't easily create a cert with nil PublicKey via stdlib, so test
	// the fallback-to-stdlib path indirectly: when all parsers return
	// ErrNotHandled, the stdlib error is returned.
	_, err := ext.ParseCertificate([]byte{0xDE, 0xAD})
	if err == nil {
		t.Error("expected error for garbage DER with no parser")
	}
}

func TestParseCertificatesPEM(t *testing.T) {
	ext := New()
	cert1 := generateSelfSignedCert(t, elliptic.P256())
	cert2 := generateSelfSignedCert(t, elliptic.P384())

	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert1.Raw})
	pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert2.Raw})...)
	// Add a non-certificate block that should be skipped
	pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{1, 2, 3}})...)

	certs, err := ext.ParseCertificatesPEM(pemData)
	if err != nil {
		t.Fatalf("ParseCertificatesPEM: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("expected 2 certs, got %d", len(certs))
	}
}

func TestParseCertificatesPEMEmpty(t *testing.T) {
	ext := New()
	certs, err := ext.ParseCertificatesPEM([]byte("no PEM content here"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("expected 0 certs, got %d", len(certs))
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
