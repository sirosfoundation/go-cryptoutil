package ecparams

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/sirosfoundation/go-cryptoutil"
)

// Zero-padded curve constants (UAE CSCA 02) and non-DER cA BOOLEAN
// (CSCA-UKRAINE): see sirosfoundation/go-cryptoutil#36.

func TestFieldElementEquals(t *testing.T) {
	v := big.NewInt(0x1234)
	for name, tc := range map[string]struct {
		oct  []byte
		want bool
	}{
		"exact":         {[]byte{0x12, 0x34}, true},
		"elided":        {[]byte{0x12, 0x34}, true},
		"one pad":       {[]byte{0x00, 0x12, 0x34}, true},
		"many pad":      {append(make([]byte, 40), 0x12, 0x34), true},
		"different":     {[]byte{0x12, 0x35}, false},
		"padded diff":   {[]byte{0x00, 0x12, 0x35}, false},
		"empty":         {nil, false},
		"all zero":      {[]byte{0, 0, 0}, false},
		"shifted (pad)": {[]byte{0x12, 0x34, 0x00}, false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := fieldElementEquals(tc.oct, v); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPaddedConstantsParseAndVerify(t *testing.T) {
	for _, name := range allCurveNames {
		for _, padN := range []int{1, 3} {
			t.Run(name, func(t *testing.T) {
				k := mustCurve(t, name)
				o := defaultOpts(k)
				o.padAB = padN
				fx := newExplicitCert(t, k, encodeExplicitParams(k, o), []byte{0x05})
				if _, err := x509.ParseCertificate(fx.der); err == nil {
					t.Fatal("test precondition: stdlib parsed the certificate")
				}
				cert, err := registered().ParseCertificate(fx.der)
				if err != nil {
					t.Fatalf("padded A/B on %s rejected: %v", name, err)
				}
				checkParsedFields(t, fx, cert)
				checkSignatures(t, fx, cert)
				// The Verifier path re-derives the key on the table curve.
				_, hash, algo := sigAlgFor(k)
				msg := []byte("padded")
				sig, _ := ecdsa.SignASN1(rand.Reader, fx.key, hashSum(hash, msg))
				if err := Verifier(cert, algo, msg, sig); err != nil {
					t.Errorf("Verifier: %v", err)
				}
				if err := Verifier(cert, algo, []byte("x"), sig); err == nil || errors.Is(err, cryptoutil.ErrNotHandled) {
					t.Errorf("Verifier accepted wrong data: %v", err)
				}
			})
		}
	}
}

func TestPaddedNonMatchingRejected(t *testing.T) {
	plus := func(v *big.Int) *big.Int { return new(big.Int).Add(v, big.NewInt(1)) }
	for _, name := range []string{"P-384", "brainpoolP384r1"} {
		k := mustCurve(t, name)
		cases := map[string]func(o *paramOpts){
			"a+1":         func(o *paramOpts) { o.a = plus(o.a) },
			"b+1":         func(o *paramOpts) { o.b = plus(o.b) },
			"swapped a,b": func(o *paramOpts) { o.a, o.b = o.b, o.a },
			"a zero":      func(o *paramOpts) { o.a = new(big.Int) },
			"wrong order": func(o *paramOpts) { o.n = plus(o.n) },
			"wrong h":     func(o *paramOpts) { h := int64(2); o.cofactor = &h },
			"wrong prime": func(o *paramOpts) { o.p = plus(o.p) },
		}
		for cn, mod := range cases {
			t.Run(name+"/"+cn, func(t *testing.T) {
				o := defaultOpts(k)
				o.padAB = 1
				mod(&o)
				fx := newExplicitCert(t, k, encodeExplicitParams(k, o), []byte{0x01})
				if _, err := Parser(fx.der); !errors.Is(err, cryptoutil.ErrNotHandled) {
					t.Errorf("Parser error = %v, want ErrNotHandled", err)
				}
				if _, err := registered().ParseCertificate(fx.der); err == nil {
					t.Error("padded non-matching parameters accepted")
				}
			})
		}
	}
	// Padding is not accepted on the base point, which is a fixed-size encoding.
	k := mustCurve(t, "P-384")
	o := defaultOpts(k)
	o.base = append([]byte{0x04, 0x00}, append(pad(k.gx, 48), pad(k.gy, 48)...)...)
	fx := newExplicitCert(t, k, encodeExplicitParams(k, o), []byte{0x01})
	if _, err := Parser(fx.der); !errors.Is(err, cryptoutil.ErrNotHandled) {
		t.Errorf("padded base point: %v", err)
	}
}

func bcValues() map[string][]byte {
	return map[string][]byte{
		"01":          {0x30, 0x03, 0x01, 0x01, 0x01},
		"7f":          {0x30, 0x03, 0x01, 0x01, 0x7f},
		"01 pathlen0": {0x30, 0x06, 0x01, 0x01, 0x01, 0x02, 0x01, 0x00},
		"80 pathlen3": {0x30, 0x06, 0x01, 0x01, 0x80, 0x02, 0x01, 0x03},
	}
}

func newNamedCurveCertBC(t *testing.T, bc []byte) (der []byte, key *ecdsa.PrivateKey) {
	t.Helper()
	key = mustKey(t)
	tbs := encodeTBSWithBC([]byte{0x05}, oidECDSASHA256, false, mustMarshalPKIX(t, &key.PublicKey), bc)
	sig, err := ecdsa.SignASN1(rand.Reader, key, hashSum(sigHash(), tbs))
	if err != nil {
		t.Fatal(err)
	}
	return assemble(tbs, oidECDSASHA256, false, sig), key
}

// requireStdlibRejects checks the precondition that crypto/x509 rejects der
// with the given message, and that an Extensions without Register does too.
func requireStdlibRejects(t *testing.T, der []byte, msg string) {
	t.Helper()
	if _, err := x509.ParseCertificate(der); err == nil || !strings.Contains(err.Error(), msg) {
		t.Fatalf("stdlib error = %v, want %q", err, msg)
	}
	if _, err := cryptoutil.New().ParseCertificate(der); err == nil {
		t.Fatal("parsed without Register")
	}
}

func mustSelfSigned(t *testing.T, cert *x509.Certificate) {
	t.Helper()
	if err := registered().CheckSignature(cert, cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Errorf("self-signature: %v", err)
	}
}

func mustNotVerify(t *testing.T, der []byte) {
	t.Helper()
	c, err := registered().ParseCertificate(der)
	if err != nil {
		return // rejected outright
	}
	if err := registered().CheckSignature(c, c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature); err == nil {
		t.Error("tampered certificate verified")
	}
}

func flipped(der []byte, idx int) []byte {
	out := append([]byte(nil), der...)
	out[idx] ^= 1
	return out
}

func TestBERBooleanBasicConstraints(t *testing.T) {
	for name, bc := range bcValues() {
		t.Run(name, func(t *testing.T) {
			der, key := newNamedCurveCertBC(t, bc)
			requireStdlibRejects(t, der, "invalid basic constraints")
			cert, err := registered().ParseCertificate(der)
			if err != nil {
				t.Fatalf("ParseCertificate: %v", err)
			}
			checkBERBooleanCert(t, der, bc, cert)
			if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
				t.Error("public key mismatch")
			}
			mustSelfSigned(t, cert)
		})
	}
}

// checkBERBooleanCert asserts that cA was read as TRUE and that the original
// extension bytes, not the normalised ones, are on the result.
func checkBERBooleanCert(t *testing.T, der, bc []byte, cert *x509.Certificate) {
	t.Helper()
	if !cert.IsCA || !cert.BasicConstraintsValid {
		t.Error("cA not recognized as TRUE")
	}
	if !bytes.Equal(cert.Raw, der) {
		t.Error("Raw was changed")
	}
	if !bytes.Contains(cert.RawTBSCertificate, bc) {
		t.Error("RawTBSCertificate was changed")
	}
	checkBCValue(t, cert, bc)
	if len(bc) == 8 {
		want := int(bc[7])
		if cert.MaxPathLen != want || (want == 0 && !cert.MaxPathLenZero) {
			t.Errorf("MaxPathLen = %d (zero=%v), want %d", cert.MaxPathLen, cert.MaxPathLenZero, want)
		}
	}
}

func checkBCValue(t *testing.T, cert *x509.Certificate, bc []byte) {
	t.Helper()
	for _, e := range cert.Extensions {
		if e.Id.Equal(oidBasicConstraints) {
			if !bytes.Equal(e.Value, bc) {
				t.Errorf("extension value = %x, want original %x", e.Value, bc)
			}
			return
		}
	}
	t.Error("no basicConstraints extension")
}

func TestBERBooleanWithExplicitParameters(t *testing.T) {
	for _, name := range []string{"P-384", "brainpoolP256r1"} {
		t.Run(name, func(t *testing.T) {
			k := mustCurve(t, name)
			o := defaultOpts(k)
			o.padAB = 1
			bc := []byte{0x30, 0x03, 0x01, 0x01, 0x01}
			fx := newExplicitCertBC(t, k, encodeExplicitParams(k, o), []byte{0x05}, bc)
			cert, err := registered().ParseCertificate(fx.der)
			if err != nil {
				t.Fatal(err)
			}
			checkParsedFields(t, fx, cert)
			checkBERBooleanCert(t, fx.der, bc, cert)
			checkSignatures(t, fx, cert)
		})
	}
}

func TestMalformedBasicConstraintsStillRejected(t *testing.T) {
	for name, bc := range map[string][]byte{
		"truncated boolean":      {0x30, 0x02, 0x01, 0x01},
		"boolean length 2":       {0x30, 0x04, 0x01, 0x02, 0x01, 0x01},
		"boolean length 0":       {0x30, 0x02, 0x01, 0x00},
		"not a boolean":          {0x30, 0x03, 0x02, 0x01, 0x01},
		"octet instead of bool":  {0x30, 0x03, 0x04, 0x01, 0x01},
		"trailing inside octets": {0x30, 0x03, 0x01, 0x01, 0x01, 0x05, 0x00},
		"trailing inside seq":    {0x30, 0x05, 0x01, 0x01, 0x01, 0x05, 0x00},
		"not a sequence":         {0x31, 0x03, 0x01, 0x01, 0x01},
		"empty value":            {},
		"length overrun":         {0x30, 0x09, 0x01, 0x01, 0x01},
		"bad pathlen":            {0x30, 0x06, 0x01, 0x01, 0x01, 0x02, 0x02, 0x00},
		"negative pathlen":       {0x30, 0x06, 0x01, 0x01, 0x01, 0x02, 0x01, 0xff},
	} {
		t.Run(name, func(t *testing.T) {
			der, _ := newNamedCurveCertBC(t, bc)
			if _, err := Parser(der); !errors.Is(err, cryptoutil.ErrNotHandled) {
				t.Errorf("Parser error = %v, want ErrNotHandled", err)
			}
			// The plugin never changes the stdlib's verdict on these.
			_, stdErr := x509.ParseCertificate(der)
			if _, err := registered().ParseCertificate(der); (err == nil) != (stdErr == nil) {
				t.Errorf("stdlib error = %v, plugin error = %v", stdErr, err)
			}
		})
	}
}

func TestNormalizeBasicConstraintsShapes(t *testing.T) {
	// No extensions, other extension only, and DER-valid TRUE are all left alone.
	der, _ := newNamedCurveCertBC(t, []byte{0x30, 0x03, 0x01, 0x01, 0xff})
	c, err := splitCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := normalizeBasicConstraints(c.rest); ok {
		t.Error("DER-valid basicConstraints reported as repairable")
	}
	if _, _, ok := normalizeBasicConstraints(nil); ok {
		t.Error("empty rest reported as repairable")
	}
	if _, _, ok := normalizeBasicConstraints([]byte{0x30}); ok {
		t.Error("garbage rest reported as repairable")
	}
	// extensions element that is not a SEQUENCE, or with trailing data
	if _, _, ok := normalizeBasicConstraints([]byte{0xa3, 0x02, 0x05, 0x00}); ok {
		t.Error("non-SEQUENCE extensions reported as repairable")
	}
	if _, _, ok := normalizeBasicConstraints([]byte{0xa3, 0x04, 0x30, 0x00, 0x05, 0x00}); ok {
		t.Error("extensions with trailing data reported as repairable")
	}
	// A different extension with BOOLEAN-looking content is not touched:
	// OID 2.5.29.15 (keyUsage) critical, value 30 03 01 01 01.
	other := []byte{0xa3, 0x13, 0x30, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0x01}
	if _, _, ok := normalizeBasicConstraints(other); ok {
		t.Error("non-basicConstraints extension was repaired")
	}
	// Extension with a truncated extension element.
	if _, _, ok := normalizeBasicConstraints([]byte{0xa3, 0x04, 0x30, 0x02, 0x30, 0x00}); ok {
		t.Error("bad extension reported as repairable")
	}
	// basicConstraints whose critical BOOLEAN is malformed.
	if _, _, ok := normalizeBasicConstraints([]byte{0xa3, 0x0c, 0x30, 0x0a, 0x30, 0x08, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x03, 0xff}); ok {
		t.Error("bad critical BOOLEAN reported as repairable")
	}
	// basicConstraints with trailing junk after the OCTET STRING.
	if _, _, ok := normalizeBasicConstraints([]byte{0xa3, 0x11, 0x30, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0x01, 0x05, 0x00}); ok {
		t.Error("trailing junk in extension reported as repairable")
	}
	// Without a critical flag the extension is still found.
	noCrit := []byte{0xa3, 0x10, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0x01}
	if fixed, orig, ok := normalizeBasicConstraints(noCrit); !ok || fixed[len(fixed)-1] != 0xff || orig[4] != 0x01 {
		t.Errorf("non-critical BER basicConstraints not repaired: %x %x %v", fixed, orig, ok)
	}
}

func readTestPEM(t *testing.T, file string) (der []byte, pemData []byte) {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(data)
	if blk == nil {
		t.Fatal("no PEM block")
	}
	return blk.Bytes, data
}

func checkDigest(t *testing.T, der []byte, want string) {
	t.Helper()
	if got := sha256.Sum256(der); hex.EncodeToString(got[:]) != want {
		t.Fatalf("fixture sha256 = %x, want %s", got, want)
	}
}

// TestRealWorldUAECSCA02 parses the UAE CSCA 02 certificate, whose P-384
// explicit parameters encode A and B with a leading 0x00 (49 octets).
func TestRealWorldUAECSCA02(t *testing.T) {
	der, data := readTestPEM(t, "testdata/csca_are_padded_constants.pem")
	checkDigest(t, der, "d0e477b5de01ee68dedbbf5992e66c7091e7134df0449939f496fe7ca64361fb")
	requireStdlibRejects(t, der, "invalid ECDSA parameters")
	a, err := parseSPKIAlgorithm(mustSplit(t, der).spki)
	if err != nil {
		t.Fatal(err)
	}
	e, err := parseExplicitParams(a.params)
	if err != nil || len(e.a) != 49 || len(e.b) != 49 || e.a[0] != 0 || e.b[0] != 0 {
		t.Fatalf("fixture no longer has 49-octet padded A/B: %v", err)
	}
	certs, err := registered().ParseCertificatesPEM(data)
	if err != nil || len(certs) != 1 {
		t.Fatalf("parse: %v (%d)", err, len(certs))
	}
	cert := certs[0]
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve.Params().Name != "P-384" {
		t.Fatalf("key = %T", cert.PublicKey)
	}
	mustSelfSigned(t, cert)
	if err := Verifier(cert, cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Errorf("Verifier: %v", err)
	}

	// Tampered: any change of the constants, the padded length or the
	// signature is rejected.
	tamperOctets(t, der, e.a, func(b []byte) { b[len(b)-1] ^= 1 })
	tamperOctets(t, der, e.b, func(b []byte) { b[len(b)-1] ^= 1 })
	tamperOctets(t, der, e.b, func(b []byte) { b[0] = 0x01 }) // padding octet becomes significant
	mustNotVerify(t, flipped(der, len(der)-1))
	mustNotVerify(t, flipped(der, bytes.Index(der, []byte("UAE CSCA 02"))))
}

func mustSplit(t *testing.T, der []byte) *certParts {
	t.Helper()
	c, err := splitCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// tamperOctets finds the octets in der (they are a sub-slice of it only by
// value), applies mod to a copy and requires the result to be declined.
func tamperOctets(t *testing.T, der, octets []byte, mod func([]byte)) {
	t.Helper()
	i := bytes.Index(der, octets)
	if i < 0 {
		t.Fatal("constant not found in DER")
	}
	bad := append([]byte(nil), der...)
	mod(bad[i : i+len(octets)])
	if _, err := Parser(bad); !errors.Is(err, cryptoutil.ErrNotHandled) {
		t.Errorf("tampered certificate: error = %v, want ErrNotHandled", err)
	}
	if _, err := registered().ParseCertificate(bad); err == nil {
		t.Error("tampered certificate accepted")
	}
}

// TestRealWorldUkraineCSCA parses CSCA-UKRAINE, whose basicConstraints encodes
// cA as BOOLEAN 0x01.
func TestRealWorldUkraineCSCA(t *testing.T) {
	der, data := readTestPEM(t, "testdata/csca_ukr_ber_boolean.pem")
	checkDigest(t, der, "6a1f5136b12017c1721cf547cc8c5aa5d11383f14cdf2443f94817924f6b6016")
	requireStdlibRejects(t, der, "invalid basic constraints")
	certs, err := registered().ParseCertificatesPEM(data)
	if err != nil || len(certs) != 1 {
		t.Fatalf("parse: %v (%d)", err, len(certs))
	}
	cert := certs[0]
	checkBERBooleanCert(t, der, []byte{0x30, 0x06, 0x01, 0x01, 0x01, 0x02, 0x01, 0x00}, cert)
	if string(cert.RawIssuer) != string(cert.RawSubject) {
		t.Fatal("fixture is not self-issued")
	}
	mustSelfSigned(t, cert)

	// Tampered variants.
	bc := []byte{0x30, 0x06, 0x01, 0x01, 0x01, 0x02, 0x01, 0x00}
	i := bytes.Index(der, bc)
	if i < 0 {
		t.Fatal("basicConstraints value not found")
	}
	// cA replaced by an INTEGER: nothing to repair, never accepted as a repair.
	notBool := append([]byte(nil), der...)
	copy(notBool[i:], []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00})
	if _, err := Parser(notBool); !errors.Is(err, cryptoutil.ErrNotHandled) {
		t.Errorf("non-BOOLEAN cA: %v", err)
	}
	for name, repl := range map[string][]byte{
		"boolean length 2":  {0x30, 0x06, 0x01, 0x02, 0x01, 0x02, 0x01, 0x00},
		"truncated integer": {0x30, 0x06, 0x01, 0x01, 0x01, 0x02, 0x02, 0x00},
	} {
		bad := append([]byte(nil), der...)
		copy(bad[i:], repl)
		if _, err := registered().ParseCertificate(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A repaired certificate whose signature or TBS was altered still fails to verify.
	for _, idx := range []int{len(der) - 1, bytes.Index(der, []byte("CSCA-UKRAINE"))} {
		bad := flipped(der, idx)
		if _, err := registered().ParseCertificate(bad); err != nil {
			t.Fatal(err)
		}
		mustNotVerify(t, bad)
	}
}
