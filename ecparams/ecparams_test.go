package ecparams

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/sirosfoundation/go-cryptoutil"
)

var allCurveNames = []string{"P-224", "P-256", "P-384", "P-521", "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"}

func registered() *cryptoutil.Extensions {
	ext := cryptoutil.New()
	Register(ext)
	return ext
}

func TestKnownCurveConstants(t *testing.T) {
	for _, name := range allCurveNames {
		k := mustCurve(t, name)
		if !k.onCurve(k.gx, k.gy) {
			t.Errorf("%s: generator is not on the curve defined by the table's a, b, p", name)
		}
		if k.h != 1 || k.n.Sign() <= 0 || k.p.BitLen() != k.curve.Params().BitSize {
			t.Errorf("%s: inconsistent table entry", name)
		}
		if k.onCurve(k.gx, new(big.Int).Add(k.gy, big.NewInt(1))) {
			t.Errorf("%s: onCurve accepted a wrong point", name)
		}
		if k.onCurve(new(big.Int).Neg(big.NewInt(1)), k.gy) || k.onCurve(k.p, k.gy) {
			t.Errorf("%s: onCurve accepted an out-of-range coordinate", name)
		}
	}
	if curveByName("nope") != nil {
		t.Error("curveByName found a nonexistent curve")
	}
}

func TestHexIntPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("hexInt should panic on bad input")
		}
	}()
	hexInt("zz")
}

func TestExplicitParametersParseAndVerify(t *testing.T) {
	for _, name := range allCurveNames {
		t.Run(name, func(t *testing.T) {
			k := mustCurve(t, name)
			fx := newExplicitCert(t, k, encodeExplicitParams(k, defaultOpts(k)), []byte{0x05})

			if _, err := x509.ParseCertificate(fx.der); err == nil {
				t.Fatal("test precondition: stdlib unexpectedly parsed the explicit-parameter certificate")
			}
			if _, err := cryptoutil.New().ParseCertificate(fx.der); err == nil {
				t.Fatal("unregistered Extensions must keep rejecting the certificate")
			}
			cert, err := registered().ParseCertificate(fx.der)
			if err != nil {
				t.Fatalf("ParseCertificate: %v", err)
			}
			checkParsedFields(t, fx, cert)
			checkSignatures(t, fx, cert)
		})
	}
}

func checkParsedFields(t *testing.T, fx *ecFixture, cert *x509.Certificate) {
	t.Helper()
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("PublicKey is %T", cert.PublicKey)
	}
	if !pub.Equal(&fx.key.PublicKey) || pub.Curve.Params().Name != fx.k.name {
		t.Error("public key does not match the generated key / curve")
	}
	if cert.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("PublicKeyAlgorithm = %v", cert.PublicKeyAlgorithm)
	}
	if string(cert.Raw) != string(fx.der) || string(cert.RawTBSCertificate) != string(fx.tbs) ||
		string(cert.Signature) != string(fx.sig) || cert.SignatureAlgorithm != fx.algo {
		t.Error("original Raw/TBS/Signature/SignatureAlgorithm were not preserved")
	}
	if !strings.Contains(cert.Subject.String(), "Test CSCA") || !cert.IsCA || cert.SerialNumber.Int64() != 5 {
		t.Errorf("other fields not populated: subject=%q ca=%v serial=%v", cert.Subject, cert.IsCA, cert.SerialNumber)
	}
	if a, err := parseSPKIAlgorithm(cert.RawSubjectPublicKeyInfo); err != nil || a.paramsTag != 0x30 {
		t.Error("RawSubjectPublicKeyInfo is not the original explicit-parameter SPKI")
	}
}

func checkSignatures(t *testing.T, fx *ecFixture, cert *x509.Certificate) {
	t.Helper()
	ext := registered()
	// Self-signature over the ORIGINAL TBS.
	if err := ext.CheckSignature(cert, cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Errorf("self-signature: %v", err)
	}
	// Signatures made by the key (DER and raw r||s) verify via Extensions.
	msg := []byte("hello eMRTD")
	_, hash, algo := sigAlgFor(fx.k)
	sig, err := ecdsa.SignASN1(rand.Reader, fx.key, hashSum(hash, msg))
	if err != nil {
		t.Fatal(err)
	}
	if err := ext.CheckSignature(cert, algo, msg, sig); err != nil {
		t.Errorf("CheckSignature (DER): %v", err)
	}
	raw, err := cryptoutil.ECDSAASN1ToRaw(sig, fx.k.byteLen())
	if err != nil {
		t.Fatal(err)
	}
	if err := ext.CheckSignature(cert, algo, msg, raw); err != nil {
		t.Errorf("CheckSignature (raw): %v", err)
	}
	if err := ext.CheckSignature(cert, algo, []byte("other"), sig); err == nil {
		t.Error("signature over different data verified")
	}
	// Report (not assert) whether stdlib alone could verify, see README.
	t.Logf("stdlib-only CheckSignature: %v", cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature))
}

func TestAlternativeEncodings(t *testing.T) {
	k := mustCurve(t, "P-256")
	cases := map[string]func(o *paramOpts){
		"compressed base point": func(o *paramOpts) { o.compressed = true },
		"with seed":             func(o *paramOpts) { o.seed = true },
		"cofactor omitted":      func(o *paramOpts) { o.cofactor = nil },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			o := defaultOpts(k)
			mod(&o)
			fx := newExplicitCert(t, k, encodeExplicitParams(k, o), []byte{0x01})
			cert, err := registered().ParseCertificate(fx.der)
			if err != nil {
				t.Fatal(err)
			}
			if err := registered().CheckSignature(cert, cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestNonMatchingParametersRejected(t *testing.T) {
	k := mustCurve(t, "P-256")
	bp := mustCurve(t, "brainpoolP256r1")
	one := func(v int64) *int64 { return &v }
	plus := func(v *big.Int) *big.Int { return new(big.Int).Add(v, big.NewInt(1)) }

	wrongG := append([]byte{0x04}, pad(k.gx, 32)...)
	wrongG = append(wrongG, pad(plus(k.gy), 32)...)
	hybrid := append([]byte{0x06}, pad(k.gx, 32)...)
	hybrid = append(hybrid, pad(k.gy, 32)...)
	wrongParity := append([]byte{0x02 | (byte(k.gy.Bit(0)) ^ 1)}, pad(k.gx, 32)...)
	// Another curve's generator on P-256 parameters.
	bpG := append([]byte{0x04}, pad(bp.gx, 32)...)
	bpG = append(bpG, pad(bp.gy, 32)...)

	cases := map[string]func(o *paramOpts){
		"wrong a":             func(o *paramOpts) { o.a = plus(o.a) },
		"wrong b":             func(o *paramOpts) { o.b = plus(o.b) },
		"wrong order":         func(o *paramOpts) { o.n = plus(o.n) },
		"wrong cofactor":      func(o *paramOpts) { o.cofactor = one(2) },
		"wrong generator":     func(o *paramOpts) { o.base = wrongG },
		"hybrid generator":    func(o *paramOpts) { o.base = hybrid },
		"wrong parity":        func(o *paramOpts) { o.base = wrongParity },
		"other curve's G":     func(o *paramOpts) { o.base = bpG },
		"unknown prime":       func(o *paramOpts) { o.p = plus(o.p) },
		"twisted-style (b,a)": func(o *paramOpts) { o.a, o.b = o.b, o.a },
		"binary field":        func(o *paramOpts) { o.fieldOID = []int{1, 2, 840, 10045, 1, 2} },
		"bad version":         func(o *paramOpts) { o.version = 2 },
		"trailing data":       func(o *paramOpts) { o.trailing = true },
		"short base":          func(o *paramOpts) { o.base = []byte{0x04, 1, 2} },
		"garbage base":        func(o *paramOpts) { o.base = make([]byte, 65) },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			o := defaultOpts(k)
			mod(&o)
			fx := newExplicitCert(t, k, encodeExplicitParams(k, o), []byte{0x01})
			if _, err := Parser(fx.der); !errors.Is(err, cryptoutil.ErrNotHandled) {
				t.Errorf("Parser error = %v, want ErrNotHandled", err)
			}
			if cert, err := registered().ParseCertificate(fx.der); err == nil {
				t.Errorf("certificate with non-matching explicit parameters was accepted: %v", cert.PublicKeyAlgorithm)
			}
		})
	}

}

func TestKeyPointNotOnCurveRejected(t *testing.T) {
	k := mustCurve(t, "P-256")
	bp := mustCurve(t, "brainpoolP256r1")
	// Correct P-256 parameters, but the public key is not on P-256.
	other, err := ecdsa.GenerateKey(bp.curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	params := encodeExplicitParams(k, defaultOpts(k))
	spki := encodeSPKI(ecAlgBytes(params), append(append([]byte{0x04}, pad(other.X, 32)...), pad(other.Y, 32)...)) //nolint:staticcheck // SA1019: raw coordinates needed
	der := assemble(encodeTBS([]byte{1}, oidECDSASHA256, false, spki), oidECDSASHA256, false, []byte{1, 2, 3})
	if _, err := Parser(der); !errors.Is(err, cryptoutil.ErrNotHandled) {
		t.Errorf("err = %v", err)
	}
}

func TestOddKeyEncodingsRejected(t *testing.T) {
	k := mustCurve(t, "P-256")
	params := encodeExplicitParams(k, defaultOpts(k))
	for name, pt := range map[string][]byte{
		"compressed": append([]byte{0x02}, pad(k.gx, 32)...),
		"empty":      {},
		"infinity":   {0x00},
		"truncated":  append([]byte{0x04}, pad(k.gx, 32)...),
	} {
		der := assemble(encodeTBS([]byte{1}, oidECDSASHA256, false, encodeSPKI(ecAlgBytes(params), pt)), oidECDSASHA256, false, []byte{1})
		if _, err := Parser(der); !errors.Is(err, cryptoutil.ErrNotHandled) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestTamperedCertificateFailsVerification(t *testing.T) {
	for _, name := range []string{"P-256", "brainpoolP384r1"} {
		t.Run(name, func(t *testing.T) {
			k := mustCurve(t, name)
			fx := newExplicitCert(t, k, encodeExplicitParams(k, defaultOpts(k)), []byte{0x05})

			// Flip a byte of the subject name inside the TBS (keeps it parsable).
			tampered := append([]byte(nil), fx.der...)
			i := strings.LastIndex(string(tampered), "Test CSCA")
			tampered[i] ^= 0x01
			cert, err := registered().ParseCertificate(tampered)
			if err != nil {
				t.Fatalf("tampered certificate should still parse: %v", err)
			}
			if err := registered().CheckSignature(cert, cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err == nil {
				t.Error("tampered TBS verified")
			}

			// Flip a signature byte.
			badSig := append([]byte(nil), fx.der...)
			badSig[len(badSig)-3] ^= 0x01
			cert, err = registered().ParseCertificate(badSig)
			if err != nil {
				t.Fatal(err)
			}
			if err := registered().CheckSignature(cert, cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err == nil {
				t.Error("tampered signature verified")
			}
		})
	}
}

func TestUnregisteredChangesNothing(t *testing.T) {
	k := mustCurve(t, "P-256")
	fx := newExplicitCert(t, k, encodeExplicitParams(k, defaultOpts(k)), []byte{0x80})
	ext := cryptoutil.New()
	if len(ext.Parsers) != 0 || len(ext.Verifiers) != 0 {
		t.Fatal("New() registers extensions")
	}
	if _, err := ext.ParseCertificate(fx.der); err == nil {
		t.Error("explicit-parameter certificate parsed without Register")
	}
	if _, err := ext.ParseCertificatesPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fx.der})); err == nil {
		t.Error("PEM with explicit-parameter certificate parsed without Register")
	}
	Register(ext)
	if len(ext.Parsers) != 1 || len(ext.Verifiers) != 1 {
		t.Errorf("Register added %d parsers, %d verifiers", len(ext.Parsers), len(ext.Verifiers))
	}
	if _, err := ext.ParseCertificate(fx.der); err != nil {
		t.Errorf("after Register: %v", err)
	}
}

func TestStdlibValidCertificatesDeclined(t *testing.T) {
	key, err := ecdsa.GenerateKey(mustCurve(t, "P-256").curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parser(der); !errors.Is(err, cryptoutil.ErrNotHandled) {
		t.Errorf("Parser on a valid certificate: %v", err)
	}
	cert, err := registered().ParseCertificate(der)
	if err != nil || !cert.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Errorf("registered Extensions changed a stdlib-valid certificate: %v", err)
	}
}

func TestNegativeSerial(t *testing.T) {
	// -128 (0x80), and a longer negative value.
	for name, serial := range map[string][]byte{"-128": {0x80}, "long": {0xff, 0x01, 0x02, 0x03}} {
		t.Run("named curve "+name, func(t *testing.T) { checkNegativeSerialNamedCurve(t, serial) })
	}

	t.Run("negative serial and explicit parameters", func(t *testing.T) {
		k := mustCurve(t, "P-256")
		fx := newExplicitCert(t, k, encodeExplicitParams(k, defaultOpts(k)), []byte{0x80})
		cert, err := registered().ParseCertificate(fx.der)
		if err != nil {
			t.Fatal(err)
		}
		if cert.SerialNumber.Int64() != -128 {
			t.Errorf("serial = %v", cert.SerialNumber)
		}
	})
}

func checkNegativeSerialNamedCurve(t *testing.T, serial []byte) {
	t.Helper()
	want := new(big.Int).SetBytes(serial)
	want.Sub(want, new(big.Int).Lsh(big.NewInt(1), uint(8*len(serial))))

	key := mustKey(t)
	tbs := encodeTBS(serial, oidECDSASHA256, false, mustMarshalPKIX(t, &key.PublicKey))
	sig, err := ecdsa.SignASN1(rand.Reader, key, hashSum(sigHash(), tbs))
	if err != nil {
		t.Fatal(err)
	}
	der := assemble(tbs, oidECDSASHA256, false, sig)
	if _, err := x509.ParseCertificate(der); err == nil || !strings.Contains(err.Error(), "negative serial") {
		t.Fatalf("precondition: stdlib error = %v", err)
	}
	if _, err := cryptoutil.New().ParseCertificate(der); err == nil {
		t.Fatal("negative serial accepted without Register")
	}
	cert, err := registered().ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if cert.SerialNumber.Cmp(want) != 0 {
		t.Errorf("serial = %v, want %v", cert.SerialNumber, want)
	}
	if string(cert.Raw) != string(der) || string(cert.RawTBSCertificate) != string(tbs) {
		t.Error("raw bytes not preserved")
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Errorf("self-signature: %v", err)
	}
}

func TestRSAMissingNULL(t *testing.T) {
	der, key := newRSACert(t, true)
	if _, err := x509.ParseCertificate(der); err == nil || !strings.Contains(err.Error(), "missing NULL") {
		t.Fatalf("precondition: stdlib error = %v", err)
	}
	if _, err := cryptoutil.New().ParseCertificate(der); err == nil {
		t.Fatal("accepted without Register")
	}
	cert, err := registered().ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if cert.PublicKeyAlgorithm != x509.RSA || !rsaEqual(cert.PublicKey, &key.PublicKey) {
		t.Error("RSA key not recovered")
	}
	if string(cert.Raw) != string(der) {
		t.Error("Raw not preserved")
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Errorf("self-signature over original TBS: %v", err)
	}

	// A well-formed RSA certificate is left to the stdlib.
	good, _ := newRSACert(t, false)
	if _, err := Parser(good); !errors.Is(err, cryptoutil.ErrNotHandled) {
		t.Errorf("Parser on a valid RSA certificate: %v", err)
	}
}

func TestVerifier(t *testing.T) {
	k := mustCurve(t, "P-256")
	key, _ := ecdsa.GenerateKey(k.curve, rand.Reader)
	cert := &x509.Certificate{PublicKey: &key.PublicKey}
	msg := []byte("m")
	sig, _ := ecdsa.SignASN1(rand.Reader, key, hashSum(sigHash(), msg))

	if err := Verifier(cert, x509.ECDSAWithSHA256, msg, sig); err != nil {
		t.Errorf("valid: %v", err)
	}
	if err := Verifier(cert, x509.ECDSAWithSHA256, []byte("x"), sig); err == nil || errors.Is(err, cryptoutil.ErrNotHandled) {
		t.Errorf("wrong data: %v", err)
	}
	if err := Verifier(cert, x509.ECDSAWithSHA256, msg, nil); err == nil {
		t.Error("empty signature verified")
	}
	if err := Verifier(cert, x509.SHA256WithRSA, msg, sig); !errors.Is(err, cryptoutil.ErrNotHandled) {
		t.Errorf("RSA algorithm: %v", err)
	}
	if err := Verifier(&x509.Certificate{}, x509.ECDSAWithSHA256, msg, sig); !errors.Is(err, cryptoutil.ErrNotHandled) {
		t.Errorf("no key: %v", err)
	}
	if err := Verifier(&x509.Certificate{PublicKey: &ecdsa.PublicKey{}}, x509.ECDSAWithSHA256, msg, sig); !errors.Is(err, cryptoutil.ErrNotHandled) {
		t.Errorf("nil curve: %v", err)
	}
	// Every supported hash is accepted for dispatch.
	for _, a := range []x509.SignatureAlgorithm{x509.ECDSAWithSHA1, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512} {
		if err := Verifier(cert, a, msg, sig); errors.Is(err, cryptoutil.ErrNotHandled) {
			t.Errorf("%v not dispatched", a)
		}
	}
}

func TestMalformedInputsAreDeclinedNotPanics(t *testing.T) {
	k := mustCurve(t, "brainpoolP256r1")
	fx := newExplicitCert(t, k, encodeExplicitParams(k, defaultOpts(k)), []byte{0x01})

	if _, err := Parser(nil); !errors.Is(err, cryptoutil.ErrNotHandled) {
		t.Errorf("nil: %v", err)
	}
	if _, err := Parser(append(append([]byte(nil), fx.der...), 0)); !errors.Is(err, cryptoutil.ErrNotHandled) {
		t.Errorf("trailing data: %v", err)
	}
	// Every truncation and every single-byte corruption must be handled without panicking.
	for i := 0; i < len(fx.der); i++ {
		_, _ = Parser(fx.der[:i])
	}
	for i := range fx.der {
		m := append([]byte(nil), fx.der...)
		m[i] ^= 0xff
		_, _ = Parser(m)
	}
}

func TestSplitAndSPKIErrors(t *testing.T) {
	good := assemble(encodeTBS([]byte{1}, oidECDSASHA256, false, mustMarshalPKIX(t, &mustKey(t).PublicKey)), oidECDSASHA256, false, []byte{1})
	if _, err := splitCertificate(good); err != nil {
		t.Fatalf("good certificate: %v", err)
	}
	for name, der := range map[string][]byte{
		"empty":        {},
		"not a seq":    {0x02, 0x01, 0x01},
		"no tbs":       {0x30, 0x00},
		"no sig":       {0x30, 0x03, 0x30, 0x01, 0x00},
		"empty tbs":    {0x30, 0x0a, 0x30, 0x00, 0x30, 0x03, 0x06, 0x01, 0x00, 0x03, 0x01, 0x00},
		"empty serial": {0x30, 0x0f, 0x30, 0x02, 0x02, 0x00, 0x30, 0x03, 0x06, 0x01, 0x00, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00},
	} {
		if _, err := splitCertificate(der); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	for name, spki := range map[string][]byte{
		"empty":       {},
		"no alg":      {0x30, 0x00},
		"bad oid":     {0x30, 0x04, 0x30, 0x02, 0x05, 0x00},
		"two params":  {0x30, 0x0a, 0x30, 0x08, 0x06, 0x01, 0x2a, 0x05, 0x00, 0x05, 0x00, 0x03, 0x01},
		"no key":      {0x30, 0x05, 0x30, 0x03, 0x06, 0x01, 0x2a},
		"bad bits":    {0x30, 0x08, 0x30, 0x03, 0x06, 0x01, 0x2a, 0x03, 0x01, 0x09},
		"trailing":    append(mustMarshalPKIX(t, &mustKey(t).PublicKey), 0),
		"bad version": encodeSPKI(ecAlgBytes([]byte{0x30, 0x03, 0x02, 0x01, 0x02}), []byte{4}),
	} {
		if a, err := parseSPKIAlgorithm(spki); err == nil && name != "bad version" {
			t.Errorf("%s: no error (%+v)", name, a)
		}
	}
	for name, el := range map[string][]byte{
		"empty":        {},
		"no version":   {0x30, 0x00},
		"no field":     {0x30, 0x03, 0x02, 0x01, 0x01},
		"trailing el":  append(encodeExplicitParams(mustCurve(t, "P-256"), defaultOpts(mustCurve(t, "P-256"))), 0),
		"bad cofactor": {0x30, 0x03, 0x02, 0x01, 0x01},
	} {
		if _, err := matchExplicitParams(el); !errors.Is(err, cryptoutil.ErrNotHandled) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if a := (&spkiAlg{}); a.withNullParams() == nil {
		t.Log("withNullParams on empty alg returned nil")
	}
	if ok, _ := negativeSerial(nil); ok {
		t.Error("empty serial reported negative")
	}
}

// TestRealWorldCSCA parses two public eMRTD CSCA certificates with explicit
// EC domain parameters (see the provenance comments in testdata/).
func TestRealWorldCSCA(t *testing.T) {
	for _, tc := range []struct {
		file, curve string
	}{
		{"testdata/csca_hun_explicit_params.pem", "P-521"},
		{"testdata/csca_deu_explicit_params.pem", "brainpoolP384r1"},
	} {
		t.Run(tc.file, func(t *testing.T) { checkRealWorld(t, tc.file, tc.curve) })
	}
}

func checkRealWorld(t *testing.T, file, curve string) {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(data)
	if blk == nil {
		t.Fatal("no PEM block")
	}
	if _, err := x509.ParseCertificate(blk.Bytes); err == nil || !strings.Contains(err.Error(), "invalid ECDSA parameters") {
		t.Fatalf("stdlib error = %v, want 'invalid ECDSA parameters'", err)
	}
	if _, err := cryptoutil.New().ParseCertificate(blk.Bytes); err == nil {
		t.Fatal("parsed without Register")
	}
	certs, err := registered().ParseCertificatesPEM(data)
	if err != nil || len(certs) != 1 {
		t.Fatalf("parse: %v (%d certs)", err, len(certs))
	}
	cert := certs[0]
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("PublicKey %T", cert.PublicKey)
	}
	if pub.Curve.Params().Name != curve {
		t.Errorf("curve = %s, want %s", pub.Curve.Params().Name, curve)
	}
	if string(cert.RawIssuer) != string(cert.RawSubject) {
		t.Fatal("fixture is not self-issued")
	}
	if err := registered().CheckSignature(cert, cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Errorf("CSCA self-signature over the original TBS: %v", err)
	}
	t.Logf("%s on %s, sha256(DER)=%x", cert.Subject, curve, sha256.Sum256(cert.Raw))
}

func rsaEqual(got any, want *rsa.PublicKey) bool {
	p, ok := got.(*rsa.PublicKey)
	return ok && p.N.Cmp(want.N) == 0 && p.E == want.E
}
