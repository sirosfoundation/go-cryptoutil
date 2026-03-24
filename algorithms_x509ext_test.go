package cryptoutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
)

func TestByXMLDSIG(t *testing.T) {
	reg := NewAlgorithmRegistry()

	tests := []struct {
		uri  string
		name string
	}{
		{"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", "P-256"},
		{"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", "P-384"},
		{"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512", "P-521"},
		{"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "RS256"},
		{"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", "RS384"},
		{"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", "RS512"},
	}
	for _, tc := range tests {
		a := reg.ByXMLDSIG(tc.uri)
		if a == nil {
			t.Errorf("ByXMLDSIG(%q) returned nil", tc.uri)
			continue
		}
		if a.Name != tc.name {
			t.Errorf("ByXMLDSIG(%q).Name = %q, want %q", tc.uri, a.Name, tc.name)
		}
	}

	// Unknown URI
	if a := reg.ByXMLDSIG("http://example.com/unknown"); a != nil {
		t.Errorf("ByXMLDSIG(unknown) = %v, want nil", a)
	}
}

func TestForKeyRSA(t *testing.T) {
	reg := NewAlgorithmRegistry()

	tests := []struct {
		bits    int
		wantJWS string
	}{
		{2048, "RS256"},
		{3072, "RS384"},
		{4096, "RS512"},
	}
	for _, tc := range tests {
		key, err := rsa.GenerateKey(rand.Reader, tc.bits)
		if err != nil {
			t.Fatalf("rsa.GenerateKey(%d): %v", tc.bits, err)
		}
		a, err := reg.ForKey(&key.PublicKey)
		if err != nil {
			t.Fatalf("ForKey RSA-%d: %v", tc.bits, err)
		}
		if a.JWS != tc.wantJWS {
			t.Errorf("ForKey RSA-%d: JWS = %q, want %q", tc.bits, a.JWS, tc.wantJWS)
		}
	}
}

func TestForKeyEdDSA(t *testing.T) {
	reg := NewAlgorithmRegistry()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a, err := reg.ForKey(pub)
	if err != nil {
		t.Fatalf("ForKey Ed25519: %v", err)
	}
	if a.JWS != "EdDSA" {
		t.Errorf("JWS = %q, want EdDSA", a.JWS)
	}
}

func TestForKeyUnsupported(t *testing.T) {
	reg := NewAlgorithmRegistry()
	// Use a type that's not recognized
	_, err := reg.ForKey("not a key")
	if err == nil {
		t.Error("expected error for unsupported key type")
	}
}

func TestForKeyUnsupportedCurve(t *testing.T) {
	reg := &AlgorithmRegistry{
		CurveAlgorithms: make(map[string]*Algorithm),
		xmldsigIndex:    make(map[string]*Algorithm),
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := reg.ForKey(&key.PublicKey)
	if err == nil {
		t.Error("expected error for unregistered curve")
	}
}

func TestCOSEAlgorithm(t *testing.T) {
	reg := NewAlgorithmRegistry()
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cose, err := reg.COSEAlgorithm(&ecKey.PublicKey)
	if err != nil {
		t.Fatalf("COSEAlgorithm: %v", err)
	}
	if cose != -7 {
		t.Errorf("COSE = %d, want -7", cose)
	}
}

func TestCOSEAlgorithmEdDSANoCOSE(t *testing.T) {
	// EdDSA does have COSE -8, so test it works
	reg := NewAlgorithmRegistry()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	cose, err := reg.COSEAlgorithm(pub)
	if err != nil {
		t.Fatalf("COSEAlgorithm EdDSA: %v", err)
	}
	if cose != -8 {
		t.Errorf("COSE = %d, want -8", cose)
	}
}

func TestCOSEAlgorithmNoCOSE(t *testing.T) {
	// Create a custom algorithm with COSE=0
	reg := &AlgorithmRegistry{
		CurveAlgorithms: make(map[string]*Algorithm),
		xmldsigIndex:    make(map[string]*Algorithm),
	}
	reg.Register(&Algorithm{Name: "P-256", KeyType: "EC", COSE: 0, JWS: "test"})
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := reg.COSEAlgorithm(&ecKey.PublicKey)
	if err == nil {
		t.Error("expected error when COSE==0")
	}
}

func TestCurveName(t *testing.T) {
	reg := NewAlgorithmRegistry()
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	name, err := reg.CurveName(&ecKey.PublicKey)
	if err != nil {
		t.Fatalf("CurveName: %v", err)
	}
	if name != "P-256" {
		t.Errorf("CurveName = %q, want P-256", name)
	}
}

func TestCurveNameUnsupported(t *testing.T) {
	reg := &AlgorithmRegistry{
		CurveAlgorithms: make(map[string]*Algorithm),
		xmldsigIndex:    make(map[string]*Algorithm),
	}
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := reg.CurveName(&ecKey.PublicKey)
	if err == nil {
		t.Error("expected error for unregistered curve")
	}
}

func TestXmldsigToX509Algorithm(t *testing.T) {
	tests := []struct {
		uri  string
		want x509.SignatureAlgorithm
	}{
		{"http://www.w3.org/2000/09/xmldsig#rsa-sha1", x509.SHA1WithRSA},
		{"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", x509.SHA256WithRSA},
		{"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", x509.SHA384WithRSA},
		{"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", x509.SHA512WithRSA},
		{"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1", x509.ECDSAWithSHA1},
		{"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", x509.ECDSAWithSHA256},
		{"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", x509.ECDSAWithSHA384},
		{"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512", x509.ECDSAWithSHA512},
		{"http://example.com/unknown", x509.UnknownSignatureAlgorithm},
	}
	for _, tc := range tests {
		got := xmldsigToX509Algorithm(tc.uri)
		if got != tc.want {
			t.Errorf("xmldsigToX509Algorithm(%q) = %v, want %v", tc.uri, got, tc.want)
		}
	}
}

func TestHashToECDSAAlgorithm(t *testing.T) {
	tests := []struct {
		hash crypto.Hash
		want x509.SignatureAlgorithm
	}{
		{crypto.SHA256, x509.ECDSAWithSHA256},
		{crypto.SHA384, x509.ECDSAWithSHA384},
		{crypto.SHA512, x509.ECDSAWithSHA512},
		{crypto.SHA1, x509.ECDSAWithSHA1},
		{crypto.MD5, x509.ECDSAWithSHA256}, // default
	}
	for _, tc := range tests {
		got := hashToECDSAAlgorithm(tc.hash)
		if got != tc.want {
			t.Errorf("hashToECDSAAlgorithm(%v) = %v, want %v", tc.hash, got, tc.want)
		}
	}
}

func TestCheckSignatureXMLDSIG(t *testing.T) {
	ext := New()
	cert := generateSelfSignedCert(t, elliptic.P256())

	// Verify the cert's own signature using the XMLDSIG helper
	err := ext.CheckSignatureXMLDSIG(cert, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
		cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		t.Fatalf("CheckSignatureXMLDSIG: %v", err)
	}
}

func TestCheckSignatureXMLDSIGUnknownURI(t *testing.T) {
	ext := New()
	cert := generateSelfSignedCert(t, elliptic.P256())
	err := ext.CheckSignatureXMLDSIG(cert, "http://example.com/unknown",
		cert.RawTBSCertificate, cert.Signature)
	if err == nil {
		t.Error("expected error for unknown URI")
	}
}

func TestCheckSignatureXMLDSIGExtensionVerifier(t *testing.T) {
	ext := New()
	// Register a custom algorithm URI
	ext.Algorithms.Register(&Algorithm{
		Name:    "custom-algo",
		XMLDSIG: "http://example.com/custom",
		Hash:    crypto.SHA256,
		KeyType: "EC",
	})
	verifyCalled := false
	ext.Verifiers = append(ext.Verifiers, func(cert *x509.Certificate, algo x509.SignatureAlgorithm, signed, sig []byte) error {
		verifyCalled = true
		return nil
	})
	cert := generateSelfSignedCert(t, elliptic.P256())
	err := ext.CheckSignatureXMLDSIG(cert, "http://example.com/custom",
		cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		t.Fatalf("expected extension verifier to handle: %v", err)
	}
	if !verifyCalled {
		t.Error("extension verifier was not called")
	}
}

func TestCheckSignatureXMLDSIGNoVerifier(t *testing.T) {
	ext := New()
	// Register a custom algorithm that won't be handled by stdlib
	ext.Algorithms.Register(&Algorithm{
		Name:    "custom-algo",
		XMLDSIG: "http://example.com/custom-noverify",
		Hash:    crypto.SHA256,
		KeyType: "EC",
	})
	cert := generateSelfSignedCert(t, elliptic.P256())
	err := ext.CheckSignatureXMLDSIG(cert, "http://example.com/custom-noverify",
		cert.RawTBSCertificate, cert.Signature)
	if err == nil {
		t.Error("expected error when no verifier handles it")
	}
}

func TestCheckSignatureVerifierError(t *testing.T) {
	ext := New()
	ext.Verifiers = append(ext.Verifiers, func(cert *x509.Certificate, algo x509.SignatureAlgorithm, signed, sig []byte) error {
		return ErrNotHandled
	})
	cert := generateSelfSignedCert(t, elliptic.P256())
	err := ext.CheckSignature(cert, cert.SignatureAlgorithm, []byte("bad data"), cert.Signature)
	if err == nil {
		t.Error("expected error when all verifiers return ErrNotHandled and stdlib fails")
	}
}

func TestRegisterNonECAlgorithm(t *testing.T) {
	reg := NewAlgorithmRegistry()
	a := &Algorithm{
		Name:    "test-rsa",
		XMLDSIG: "http://example.com/test-rsa",
		KeyType: "RSA",
	}
	reg.Register(a)
	// Should be in xmldsigIndex but not CurveAlgorithms
	if reg.ByXMLDSIG("http://example.com/test-rsa") == nil {
		t.Error("expected algorithm in xmldsigIndex")
	}
	if _, ok := reg.CurveAlgorithms["test-rsa"]; ok {
		t.Error("RSA algorithm should not be in CurveAlgorithms")
	}
}
