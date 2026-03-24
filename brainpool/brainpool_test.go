package brainpool

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"

	gematik "github.com/gematik/zero-lab/go/brainpool"
	"github.com/sirosfoundation/go-cryptoutil"
)

func TestRegister(t *testing.T) {
	ext := cryptoutil.New()
	Register(ext)

	if len(ext.Parsers) != 1 {
		t.Errorf("expected 1 parser, got %d", len(ext.Parsers))
	}
	if len(ext.Verifiers) != 1 {
		t.Errorf("expected 1 verifier, got %d", len(ext.Verifiers))
	}
	if len(ext.KeyParsers) != 1 {
		t.Errorf("expected 1 key parser, got %d", len(ext.KeyParsers))
	}
	// 7 standard + 3 brainpool = 10 algorithms
	if len(ext.Algorithms.All) != 10 {
		t.Errorf("expected 10 algorithms, got %d", len(ext.Algorithms.All))
	}
}

func TestBrainpoolAlgorithmMapping(t *testing.T) {
	ext := cryptoutil.New()
	Register(ext)

	curves := []struct {
		curve   func() interface{ Params() *struct{ Name string } }
		curveFn func() ecdsa.PublicKey
		name    string
		wantJWS string
	}{
		{name: "brainpoolP256r1", wantJWS: "BP256R1"},
		{name: "brainpoolP384r1", wantJWS: "BP384R1"},
		{name: "brainpoolP512r1", wantJWS: "BP512R1"},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			alg, ok := ext.Algorithms.CurveAlgorithms[tc.name]
			if !ok {
				t.Fatalf("curve %s not found in registry", tc.name)
			}
			if alg.JWS != tc.wantJWS {
				t.Errorf("expected JWS=%s, got %s", tc.wantJWS, alg.JWS)
			}
			if alg.KeyType != "EC" {
				t.Errorf("expected KeyType=EC, got %s", alg.KeyType)
			}
		})
	}
}

func TestBrainpoolParseCertificate(t *testing.T) {
	ext := cryptoutil.New()
	Register(ext)

	key, err := ecdsa.GenerateKey(gematik.P256r1(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Create a self-signed certificate with the brainpool key.
	// We can't use x509.CreateCertificate since stdlib doesn't support brainpool,
	// so we use gematik's parser to parse a cert we construct manually.
	// Instead, test via the gematik library itself — generate then parse roundtrip.
	certDER := createBrainpoolCert(t, key)

	// stdlib should fail
	_, stdErr := x509.ParseCertificate(certDER)
	if stdErr == nil {
		t.Fatal("expected stdlib to fail on brainpool cert")
	}

	// Our extension should succeed
	cert, err := ext.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("extension ParseCertificate failed: %v", err)
	}

	ecPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("expected *ecdsa.PublicKey")
	}
	if !isBrainpool(ecPub.Curve) {
		t.Errorf("expected brainpool curve, got %s", ecPub.Curve.Params().Name)
	}
}

func TestBrainpoolVerifySignature(t *testing.T) {
	ext := cryptoutil.New()
	Register(ext)

	key, err := ecdsa.GenerateKey(gematik.P256r1(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	certDER := createBrainpoolCert(t, key)
	cert, err := ext.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	// Sign some data
	data := []byte("hello brainpool world")
	h := crypto.SHA256.New()
	h.Write(data)
	digest := h.Sum(nil)

	sig, err := ecdsa.SignASN1(rand.Reader, key, digest)
	if err != nil {
		t.Fatal(err)
	}

	// Verify via our extension (ASN.1 DER format)
	err = ext.CheckSignature(cert, x509.ECDSAWithSHA256, data, sig)
	if err != nil {
		t.Fatalf("CheckSignature (ASN.1) failed: %v", err)
	}

	// Convert to raw r||s and verify that too
	rawSig, err := cryptoutil.ECDSAASN1ToRaw(sig, 32)
	if err != nil {
		t.Fatal(err)
	}
	err = ext.CheckSignature(cert, x509.ECDSAWithSHA256, data, rawSig)
	if err != nil {
		t.Fatalf("CheckSignature (raw) failed: %v", err)
	}
}

func TestBrainpoolAlgorithmForKey(t *testing.T) {
	ext := cryptoutil.New()
	Register(ext)

	key, err := ecdsa.GenerateKey(gematik.P256r1(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	jws, err := ext.Algorithms.JWSAlgorithm(&key.PublicKey)
	if err != nil {
		t.Fatalf("JWSAlgorithm: %v", err)
	}
	if jws != "BP256R1" {
		t.Errorf("expected BP256R1, got %s", jws)
	}

	xmldsig, err := ext.Algorithms.XMLDSIGAlgorithm(&key.PublicKey)
	if err != nil {
		t.Fatalf("XMLDSIGAlgorithm: %v", err)
	}
	if xmldsig != "http://www.w3.org/2007/05/xmldsig-more#ecdsa-brainpoolP256r1" {
		t.Errorf("unexpected XMLDSIG: %s", xmldsig)
	}
}

// createBrainpoolCert creates a minimal self-signed DER certificate using a brainpool key.
// Since Go stdlib can't create brainpool certs, we use gematik's parser roundtrip:
// build a minimal ASN.1 structure manually.
func createBrainpoolCert(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()

	// Use a stub: create a template and sign with a helper.
	// Actually, the simplest approach: use x509.CreateCertificate with the brainpool key.
	// Go 1.25 still fails on brainpool at the x509 level for parsing,
	// but CreateCertificate might work since it takes a crypto.Signer.
	// Let's try:
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "brainpool-test"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err == nil {
		return der
	}

	// If CreateCertificate fails (likely), we need to build manually.
	// Use gematik's test approach: generate a key, serialize a minimal cert.
	t.Logf("x509.CreateCertificate failed (expected): %v; building minimal cert", err)

	// Build minimal ASN.1 cert structure
	// This is a simplified approach — enough for test parsing
	return buildMinimalBrainpoolCert(t, key)
}

func buildMinimalBrainpoolCert(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	// We need a valid X.509 cert with brainpool key that gematik can parse.
	// Use encoding/asn1 to manually construct the DER.

	// For testing, let's use the gematik library's own test vectors or
	// construct a cert that the gematik parser can handle.
	// The simplest approach: generate a certificate string and sign it.

	// Actually, let me check if gematik has a way to create certs...
	// It doesn't. Let me build the ASN.1 manually.

	// Use a hardcoded test vector approach: generate the key, self-sign,
	// construct manually.

	// For now, trying a different approach: write out just enough ASN.1
	// to be a parseable cert by gematik's ParseCertificate.

	// Construct a minimal X.509v1 certificate
	cert := buildASN1Cert(t, key)

	// Verify gematik can parse it
	parsed, err := gematik.ParseCertificate(cert)
	if err != nil {
		t.Fatalf("gematik couldn't parse our constructed cert: %v", err)
	}
	_ = parsed
	return cert
}

func buildASN1Cert(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()

	// Build a minimal X.509v1 certificate in DER using low-level ASN.1.
	// v1 has no explicit version tag, so the TBS starts with serialNumber.

	oidECPublicKey := asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidBrainpoolP256r1 := asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 7}
	oidECDSAWithSHA256 := asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}

	curveSize := (key.Curve.Params().BitSize + 7) / 8
	switch key.Curve.Params().Name {
	case "brainpoolP384r1":
		oidBrainpoolP256r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 11}
		curveSize = 48
	case "brainpoolP512r1":
		oidBrainpoolP256r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 13}
		curveSize = 64
	}

	// Encode public key point (uncompressed)
	pubBytes := make([]byte, 1+2*curveSize)
	pubBytes[0] = 0x04
	xBytes := key.PublicKey.X.Bytes()
	yBytes := key.PublicKey.Y.Bytes()
	copy(pubBytes[1+curveSize-len(xBytes):1+curveSize], xBytes)
	copy(pubBytes[1+2*curveSize-len(yBytes):1+2*curveSize], yBytes)

	// Marshal signature algorithm
	sigAlg, _ := asn1.Marshal(struct {
		Algorithm asn1.ObjectIdentifier
	}{oidECDSAWithSHA256})

	// Marshal issuer/subject (CN=brainpool-test)
	issuerDER, _ := asn1.Marshal(pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  asn1.ObjectIdentifier{2, 5, 4, 3},
				Value: "brainpool-test",
			},
		},
	})

	// Marshal validity (UTCTime)
	notBefore := asn1.RawValue{Tag: 23, Class: 0, IsCompound: false, Bytes: []byte("250101000000Z")}
	notAfter := asn1.RawValue{Tag: 23, Class: 0, IsCompound: false, Bytes: []byte("350101000000Z")}
	validityDER, _ := asn1.Marshal(struct {
		NotBefore asn1.RawValue
		NotAfter  asn1.RawValue
	}{notBefore, notAfter})

	// Marshal SPKI
	spkiDER, _ := asn1.Marshal(struct {
		Algorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.ObjectIdentifier
		}
		PublicKey asn1.BitString
	}{
		Algorithm: struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.ObjectIdentifier
		}{oidECPublicKey, oidBrainpoolP256r1},
		PublicKey: asn1.BitString{Bytes: pubBytes, BitLength: len(pubBytes) * 8},
	})

	// Marshal serial number
	serialDER, _ := asn1.Marshal(big.NewInt(42))

	// Build TBS as raw SEQUENCE: version | serial | sigAlg | issuer | validity | subject | spki | extensions
	// Use v3 (version 2 in DER) because gematik parser requires explicit version tag
	versionInt, _ := asn1.Marshal(2) // v3 = 2
	versionExplicit := append([]byte{0xa0, byte(len(versionInt))}, versionInt...)

	// Empty extensions: [3] EXPLICIT SEQUENCE {}
	emptyExtSeq := []byte{0x30, 0x00}                                          // SEQUENCE {}
	extensions := append([]byte{0xa3, byte(len(emptyExtSeq))}, emptyExtSeq...) // [3] CONSTRUCTED

	tbsInner := concat(versionExplicit, serialDER, sigAlg, issuerDER, validityDER, issuerDER, spkiDER, extensions)
	tbsDER := wrapSequence(tbsInner)

	// Sign TBS
	h := crypto.SHA256.New()
	h.Write(tbsDER)
	digest := h.Sum(nil)

	sigBytes, err := ecdsa.SignASN1(rand.Reader, key, digest)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Build full certificate: SEQUENCE { tbsDER, sigAlg, BitString(sig) }
	sigBitString, _ := asn1.Marshal(asn1.BitString{Bytes: sigBytes, BitLength: len(sigBytes) * 8})
	certInner := concat(tbsDER, sigAlg, sigBitString)
	certDER := wrapSequence(certInner)

	return certDER
}

func concat(parts ...[]byte) []byte {
	var total int
	for _, p := range parts {
		total += len(p)
	}
	result := make([]byte, 0, total)
	for _, p := range parts {
		result = append(result, p...)
	}
	return result
}

func wrapSequence(content []byte) []byte {
	// ASN.1 SEQUENCE tag = 0x30
	length := len(content)
	if length < 128 {
		return append([]byte{0x30, byte(length)}, content...)
	}
	// Long form length encoding
	lenBytes := marshalLength(length)
	header := append([]byte{0x30}, lenBytes...)
	return append(header, content...)
}

func marshalLength(length int) []byte {
	if length < 128 {
		return []byte{byte(length)}
	}
	// Determine number of bytes needed
	var buf [4]byte
	n := 0
	for v := length; v > 0; v >>= 8 {
		buf[3-n] = byte(v)
		n++
	}
	result := make([]byte, 1+n)
	result[0] = byte(0x80 | n)
	copy(result[1:], buf[4-n:])
	return result
}
