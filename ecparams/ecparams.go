// Package ecparams provides an opt-in [cryptoutil.Extensions] plugin that
// parses real-world X.509 certificates which Go's crypto/x509 rejects, chiefly
// because their SubjectPublicKeyInfo describes the elliptic curve with explicit
// domain parameters (ECParameters ::= specifiedCurve, RFC 3279 / X9.62) instead
// of a named-curve OID. Such certificates are common among ICAO 9303 eMRTD
// CSCA certificates.
//
// Use [Register] to enable it:
//
//	ext := cryptoutil.New()
//	brainpool.Register(ext) // optional
//	ecparams.Register(ext)
//
// # What is accepted
//
//   - Explicit EC parameters whose field, curve coefficients, base point, order
//     and cofactor are exactly those of NIST P-224/P-256/P-384/P-521 or
//     brainpoolP256r1/P384r1/P512r1. The resulting certificate has the matching
//     *ecdsa.PublicKey.
//   - A negative serial number (certificate.SerialNumber is set to the negative
//     value).
//   - An RSA public key whose AlgorithmIdentifier lacks the NULL parameters.
//
// # What is never accepted
//
// Self-described curves are never trusted. Explicit parameters that do not
// match a known curve exactly (including twisted Brainpool curves, curves of
// unknown order, a wrong generator, a wrong cofactor, binary-field curves,
// implicitlyCA, or an encoding that is not strict DER) are declined with
// [cryptoutil.ErrNotHandled], so the certificate stays rejected. The public
// key point must lie on the matched curve.
//
// # Signatures
//
// The returned certificate keeps the original Raw, RawTBSCertificate,
// RawSubjectPublicKeyInfo, Signature and SignatureAlgorithm bytes; nothing is
// re-encoded, so signature checks run over the original TBSCertificate. The
// plugin also registers a [Verifier] for ECDSA signatures made by keys on the
// known curves.
package ecparams

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/sirosfoundation/go-cryptoutil"
)

// Register adds the lenient certificate parser and the ECDSA verifier to ext.
// Nothing changes for an Extensions instance on which Register is not called.
func Register(ext *cryptoutil.Extensions) {
	ext.Parsers = append(ext.Parsers, Parser)
	ext.Verifiers = append(ext.Verifiers, Verifier)
}

var (
	oidECPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidPrimeField  = asn1.ObjectIdentifier{1, 2, 840, 10045, 1, 1}
	oidRSA         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
)

// declined wraps cryptoutil.ErrNotHandled with a reason.
func declined(format string, args ...any) error {
	return fmt.Errorf("%w: ecparams: %s", cryptoutil.ErrNotHandled, fmt.Sprintf(format, args...))
}

// Parser parses a DER certificate that crypto/x509 rejects for one of the
// reasons listed in the package documentation. It returns
// [cryptoutil.ErrNotHandled] for everything else, including explicit EC
// parameters that do not exactly match a known curve.
//
// The certificate is parsed through a "skeleton": a copy of the DER in which
// the offending element (SPKI or serial) is replaced by an innocuous valid one,
// so that crypto/x509 fills in every other field. The original bytes, key and
// serial are then restored on the result.
func Parser(der []byte) (*x509.Certificate, error) {
	c, err := splitCertificate(der)
	if err != nil {
		return nil, declined("%v", err)
	}

	var (
		pub       *ecdsa.PublicKey
		serial    *big.Int
		newSerial = c.serial
		newSPKI   = c.spki
		changed   bool
		ecKey     bool
	)

	if c.serialValue.Sign() < 0 {
		serial = c.serialValue
		newSerial = []byte{0x02, 0x01, 0x01}
		changed = true
	}

	alg, err := parseSPKIAlgorithm(c.spki)
	if err != nil {
		return nil, declined("%v", err)
	}
	switch {
	case alg.oid.Equal(oidECPublicKey) && alg.paramsTag == cbasn1.SEQUENCE:
		k, err := matchExplicitParams(alg.params)
		if err != nil {
			return nil, err
		}
		pub, err = parsePoint(k, alg.keyBits)
		if err != nil {
			return nil, err
		}
		dummy, err := dummySPKI()
		if err != nil {
			return nil, err
		}
		newSPKI = dummy
		changed, ecKey = true, true
	case alg.oid.Equal(oidRSA) && alg.paramsTag == 0:
		newSPKI = alg.withNullParams()
		changed = true
	}
	if !changed {
		return nil, declined("nothing to repair")
	}

	skel := rebuild(c, newSerial, newSPKI)
	cert, err := x509.ParseCertificate(skel)
	if err != nil {
		return nil, declined("certificate is not repairable: %v", err)
	}
	if cert.PublicKey == nil {
		return nil, declined("no usable public key")
	}

	cert.Raw = der
	cert.RawTBSCertificate = c.tbs
	cert.RawSubjectPublicKeyInfo = c.spki
	if serial != nil {
		cert.SerialNumber = serial
	}
	if ecKey {
		cert.PublicKey = pub
		cert.PublicKeyAlgorithm = x509.ECDSA
	}
	return cert, nil
}

// certParts holds the raw elements (tag and length included) of a certificate.
type certParts struct {
	tbs         []byte   // whole TBSCertificate element
	version     []byte   // optional
	serial      []byte   // INTEGER element
	serialValue *big.Int // strictly decoded (DER-minimal) serial number
	sigAlg      []byte   // TBS signature AlgorithmIdentifier
	issuer      []byte
	validity    []byte
	subject     []byte
	spki        []byte
	rest        []byte // issuerUID, subjectUID, extensions
	outerSigAlg []byte
	outerSig    []byte
}

func splitCertificate(der []byte) (*certParts, error) {
	var c certParts
	in := cryptobyte.String(der)
	var cert cryptobyte.String
	if !in.ReadASN1(&cert, cbasn1.SEQUENCE) || !in.Empty() {
		return nil, errors.New("not a DER certificate")
	}
	var tbsEl cryptobyte.String
	if !cert.ReadASN1Element(&tbsEl, cbasn1.SEQUENCE) {
		return nil, errors.New("no TBSCertificate")
	}
	c.tbs = tbsEl
	var outerAlg, outerSig cryptobyte.String
	if !cert.ReadASN1Element(&outerAlg, cbasn1.SEQUENCE) ||
		!cert.ReadASN1Element(&outerSig, cbasn1.BIT_STRING) || !cert.Empty() {
		return nil, errors.New("bad signature fields")
	}
	c.outerSigAlg, c.outerSig = outerAlg, outerSig

	var tbs cryptobyte.String
	if !tbsEl.ReadASN1(&tbs, cbasn1.SEQUENCE) {
		return nil, errors.New("bad TBSCertificate")
	}
	vtag := cbasn1.Tag(0).ContextSpecific().Constructed()
	if tbs.PeekASN1Tag(vtag) {
		var v cryptobyte.String
		if !tbs.ReadASN1Element(&v, vtag) {
			return nil, errors.New("bad version")
		}
		c.version = v
	}
	var serial, sigAlg, issuer, validity, subject, spki cryptobyte.String
	if !tbs.ReadASN1Element(&serial, cbasn1.INTEGER) ||
		!tbs.ReadASN1Element(&sigAlg, cbasn1.SEQUENCE) ||
		!tbs.ReadASN1Element(&issuer, cbasn1.SEQUENCE) ||
		!tbs.ReadASN1Element(&validity, cbasn1.SEQUENCE) ||
		!tbs.ReadASN1Element(&subject, cbasn1.SEQUENCE) ||
		!tbs.ReadASN1Element(&spki, cbasn1.SEQUENCE) {
		return nil, errors.New("bad TBSCertificate fields")
	}
	c.serial, c.sigAlg, c.issuer, c.validity, c.subject, c.spki = serial, sigAlg, issuer, validity, subject, spki
	c.rest = tbs

	// ReadASN1Integer enforces minimal DER INTEGER encoding and two's complement.
	sc := serial
	c.serialValue = new(big.Int)
	if !sc.ReadASN1Integer(c.serialValue) {
		return nil, errors.New("bad serial number")
	}
	return &c, nil
}

// rebuild reassembles the certificate with a replacement serial and SPKI. The
// outer signature fields are copied unchanged.
func rebuild(c *certParts, serial, spki []byte) []byte {
	var tbsBody []byte
	for _, part := range [][]byte{c.version, serial, c.sigAlg, c.issuer, c.validity, c.subject, spki, c.rest} {
		tbsBody = append(tbsBody, part...)
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddBytes(tbsBody) })
		b.AddBytes(c.outerSigAlg)
		b.AddBytes(c.outerSig)
	})
	out, err := b.Bytes()
	if err != nil {
		return nil
	}
	return out
}

// spkiAlg is a decomposed SubjectPublicKeyInfo.
type spkiAlg struct {
	oid       asn1.ObjectIdentifier
	paramsTag cbasn1.Tag // 0 when absent
	params    []byte     // whole parameters element
	keyBits   asn1.BitString
	keyEl     []byte // whole subjectPublicKey element
}

func parseSPKIAlgorithm(spkiEl []byte) (*spkiAlg, error) {
	in := cryptobyte.String(spkiEl)
	var spki, algSeq cryptobyte.String
	if !in.ReadASN1(&spki, cbasn1.SEQUENCE) || !in.Empty() ||
		!spki.ReadASN1(&algSeq, cbasn1.SEQUENCE) {
		return nil, errors.New("malformed SubjectPublicKeyInfo")
	}
	var a spkiAlg
	if !algSeq.ReadASN1ObjectIdentifier(&a.oid) {
		return nil, errors.New("malformed algorithm OID")
	}
	if !algSeq.Empty() {
		var tag cbasn1.Tag
		var p cryptobyte.String
		if !algSeq.ReadAnyASN1Element(&p, &tag) || !algSeq.Empty() {
			return nil, errors.New("malformed algorithm parameters")
		}
		a.paramsTag, a.params = tag, p
	}
	var keyEl cryptobyte.String
	if !spki.ReadASN1Element(&keyEl, cbasn1.BIT_STRING) || !spki.Empty() {
		return nil, errors.New("malformed subjectPublicKey")
	}
	a.keyEl = keyEl
	ks := keyEl
	if !ks.ReadASN1BitString(&a.keyBits) {
		return nil, errors.New("malformed subjectPublicKey bit string")
	}
	return &a, nil
}

// withNullParams returns the SPKI with a NULL parameters element added to the
// algorithm identifier.
func (a *spkiAlg) withNullParams() []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(a.oid)
			b.AddASN1NULL()
		})
		b.AddBytes(a.keyEl)
	})
	out, _ := b.Bytes()
	return out
}

// dummySPKI returns a valid named-curve SPKI used only as a placeholder in the
// skeleton certificate.
func dummySPKI() ([]byte, error) {
	c := curveByName("P-256")
	if c == nil {
		return nil, errors.New("ecparams: P-256 unavailable")
	}
	out, err := x509.MarshalPKIXPublicKey(&ecdsa.PublicKey{Curve: c.curve, X: c.gx, Y: c.gy}) //nolint:staticcheck // SA1019: custom-curve keys (brainpool) can only be built from raw coordinates
	if err != nil {
		return nil, fmt.Errorf("ecparams: placeholder SPKI: %w", err)
	}
	return out, nil
}

// explicitParams is a decoded SpecifiedECDomain (X9.62 ECParameters).
type explicitParams struct {
	p, n    *big.Int
	h       *big.Int // nil when omitted
	a, b    []byte   // FieldElement octet strings
	basePnt []byte
}

// readFieldID reads FieldID ::= SEQUENCE { fieldType OID, parameters INTEGER }
// for a prime field and returns the prime.
func readFieldID(seq *cryptobyte.String) (*big.Int, bool) {
	var fieldID cryptobyte.String
	var fieldType asn1.ObjectIdentifier
	p := new(big.Int)
	ok := seq.ReadASN1(&fieldID, cbasn1.SEQUENCE) &&
		fieldID.ReadASN1ObjectIdentifier(&fieldType) && fieldType.Equal(oidPrimeField) &&
		fieldID.ReadASN1Integer(p) && fieldID.Empty() && p.Sign() > 0
	return p, ok
}

// readCurve reads Curve ::= SEQUENCE { a, b OCTET STRING, seed BIT STRING OPTIONAL }.
func readCurve(seq *cryptobyte.String) (a, b []byte, ok bool) {
	var curve, aOct, bOct cryptobyte.String
	if !seq.ReadASN1(&curve, cbasn1.SEQUENCE) ||
		!curve.ReadASN1(&aOct, cbasn1.OCTET_STRING) ||
		!curve.ReadASN1(&bOct, cbasn1.OCTET_STRING) {
		return nil, nil, false
	}
	if curve.PeekASN1Tag(cbasn1.BIT_STRING) {
		var seed asn1.BitString
		if !curve.ReadASN1BitString(&seed) {
			return nil, nil, false
		}
	}
	return aOct, bOct, curve.Empty()
}

// parseExplicitParams strictly decodes an ECParameters element holding a
// SpecifiedECDomain over a prime field.
func parseExplicitParams(el []byte) (*explicitParams, error) {
	in := cryptobyte.String(el)
	var seq cryptobyte.String
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !in.Empty() {
		return nil, declined("malformed ECParameters")
	}
	var version int64
	if !seq.ReadASN1Integer(&version) || version != 1 {
		return nil, declined("unsupported ECParameters version")
	}
	e := &explicitParams{n: new(big.Int)}
	var ok bool
	if e.p, ok = readFieldID(&seq); !ok {
		return nil, declined("not a prime field")
	}
	if e.a, e.b, ok = readCurve(&seq); !ok {
		return nil, declined("malformed curve coefficients")
	}
	var base cryptobyte.String
	if !seq.ReadASN1(&base, cbasn1.OCTET_STRING) || !seq.ReadASN1Integer(e.n) || e.n.Sign() <= 0 {
		return nil, declined("malformed base point or order")
	}
	e.basePnt = base
	if !seq.Empty() {
		e.h = new(big.Int)
		if !seq.ReadASN1Integer(e.h) {
			return nil, declined("malformed cofactor")
		}
	}
	if !seq.Empty() {
		return nil, declined("trailing data in ECParameters")
	}
	return e, nil
}

// equals reports whether the decoded parameters are exactly those of k.
func (e *explicitParams) equals(k *knownCurve) bool {
	if e.p.Cmp(k.p) != 0 || e.n.Cmp(k.n) != 0 {
		return false
	}
	if e.h != nil && (!e.h.IsInt64() || e.h.Int64() != k.h) {
		return false
	}
	l := k.byteLen()
	return fieldElementEquals(e.a, k.a, l) && fieldElementEquals(e.b, k.b, l) && basePointEquals(e.basePnt, k)
}

// matchExplicitParams decodes an ECParameters element holding a
// SpecifiedECDomain and returns the known curve it equals exactly.
func matchExplicitParams(el []byte) (*knownCurve, error) {
	e, err := parseExplicitParams(el)
	if err != nil {
		return nil, err
	}
	for _, k := range known() {
		if e.equals(k) {
			return k, nil
		}
	}
	return nil, declined("explicit parameters match no known curve")
}

// fieldElementEquals compares an X9.62 FieldElement octet string with v. The
// string may not be longer than the field size; leading zeros may be elided.
func fieldElementEquals(oct []byte, v *big.Int, byteLen int) bool {
	if len(oct) == 0 || len(oct) > byteLen {
		return false
	}
	return new(big.Int).SetBytes(oct).Cmp(v) == 0
}

// basePointEquals compares an encoded base point (uncompressed, or compressed
// with its parity prefix) with the generator of k.
func basePointEquals(pt []byte, k *knownCurve) bool {
	l := k.byteLen()
	switch {
	case len(pt) == 1+2*l && pt[0] == 0x04:
		return bytes.Equal(pt[1:1+l], pad(k.gx, l)) && bytes.Equal(pt[1+l:], pad(k.gy, l))
	case len(pt) == 1+l && (pt[0] == 0x02 || pt[0] == 0x03):
		return bytes.Equal(pt[1:], pad(k.gx, l)) && pt[0]&1 == byte(k.gy.Bit(0))
	}
	return false
}

func pad(v *big.Int, l int) []byte {
	return v.FillBytes(make([]byte, l))
}

// parsePoint decodes the subjectPublicKey as an uncompressed point on k and
// verifies that it lies on the curve.
func parsePoint(k *knownCurve, bits asn1.BitString) (*ecdsa.PublicKey, error) {
	if bits.BitLength%8 != 0 {
		return nil, declined("public key is not a whole number of octets")
	}
	l := k.byteLen()
	pt := bits.Bytes
	if len(pt) != 1+2*l || pt[0] != 0x04 {
		return nil, declined("public key is not an uncompressed point")
	}
	x := new(big.Int).SetBytes(pt[1 : 1+l])
	y := new(big.Int).SetBytes(pt[1+l:])
	if !k.onCurve(x, y) {
		return nil, declined("public key point is not on the curve")
	}
	return &ecdsa.PublicKey{Curve: k.curve, X: x, Y: y}, nil //nolint:staticcheck // SA1019: custom-curve keys (brainpool) can only be built from raw coordinates
}

// Verifier verifies ECDSA signatures made by a certificate key on one of the
// known curves. It accepts ASN.1 DER and raw r||s signatures. It returns
// [cryptoutil.ErrNotHandled] for any other key or algorithm.
func Verifier(cert *x509.Certificate, algo x509.SignatureAlgorithm, signed, signature []byte) error {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve == nil || pub.Params() == nil {
		return cryptoutil.ErrNotHandled
	}
	// A curve name is only a label: resolve the trusted table entry, check the
	// point against the table's parameters, and verify with the table's own
	// curve implementation rather than whatever pub.Curve is.
	k := curveByName(pub.Curve.Params().Name)
	if k == nil {
		return cryptoutil.ErrNotHandled
	}
	if pub.X == nil || pub.Y == nil || !k.onCurve(pub.X, pub.Y) { //nolint:staticcheck // SA1019: raw coordinates needed for custom curves
		return errors.New("cryptoutil/ecparams: public key is not on the claimed curve")
	}
	pub = &ecdsa.PublicKey{Curve: k.curve, X: pub.X, Y: pub.Y} //nolint:staticcheck // SA1019: custom-curve keys can only be built from raw coordinates
	var hash crypto.Hash
	switch algo {
	case x509.ECDSAWithSHA1:
		hash = crypto.SHA1
	case x509.ECDSAWithSHA256:
		hash = crypto.SHA256
	case x509.ECDSAWithSHA384:
		hash = crypto.SHA384
	case x509.ECDSAWithSHA512:
		hash = crypto.SHA512
	default:
		return cryptoutil.ErrNotHandled
	}
	h := hash.New()
	h.Write(signed)
	digest := h.Sum(nil)
	if ecdsa.VerifyASN1(pub, digest, signature) {
		return nil
	}
	if len(signature) > 0 && len(signature)%2 == 0 {
		if der, err := cryptoutil.ECDSARawToASN1(signature); err == nil && ecdsa.VerifyASN1(pub, digest, der) {
			return nil
		}
	}
	return errors.New("cryptoutil/ecparams: ECDSA signature verification failed")
}
