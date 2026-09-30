package ecparams

// Integration test against a real-world CSCA Master List (ICAO 9303 Part 12).
//
// It reads the list at test time; nothing from it is stored in this repository
// and nothing is redistributed. It is opt-in and skipped cleanly otherwise:
//
//	GOCRYPTOUTIL_PKD_MASTERLIST=/path/to/ICAO.ml     read a local file (offline)
//	GOCRYPTOUTIL_PKD_MASTERLIST_URL=https://...      download it (skipped if SKIP_NETWORK_TESTS is set)
//
// The file may be the bare CMS SignedData (.ml/.mls) or a ZIP holding it. The
// public ICAO PKD download (https://pkddownload.icao.int/, reached from
// https://www.icao.int/icao-pkd/icao-master-list) is gated by terms and a
// CAPTCHA, so download it by hand and point the first variable at it. National
// master lists (for example BSI or NPKD) have the same format.

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/sirosfoundation/go-cryptoutil"
	"github.com/sirosfoundation/go-cryptoutil/brainpool"
)

const maxMasterListSize = 64 << 20

func loadMasterList(t *testing.T) []byte {
	t.Helper()
	var data []byte
	switch path, url := os.Getenv("GOCRYPTOUTIL_PKD_MASTERLIST"), os.Getenv("GOCRYPTOUTIL_PKD_MASTERLIST_URL"); {
	case path != "":
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("cannot read GOCRYPTOUTIL_PKD_MASTERLIST (explicitly configured): %v", err)
		}
		data = b
	case url != "":
		if os.Getenv("SKIP_NETWORK_TESTS") != "" {
			t.Skip("SKIP_NETWORK_TESTS is set")
		}
		client := &http.Client{Timeout: 60 * time.Second}
		resp, err := client.Get(url)
		if err != nil {
			t.Skipf("download failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Skipf("download failed: %s", resp.Status)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, maxMasterListSize))
		if err != nil {
			t.Skipf("download failed: %v", err)
		}
		data = b
	default:
		t.Skip("set GOCRYPTOUTIL_PKD_MASTERLIST (or GOCRYPTOUTIL_PKD_MASTERLIST_URL) to run the master list integration test")
	}
	if bytes.HasPrefix(data, []byte("PK\x03\x04")) {
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil || len(zr.File) == 0 {
			t.Fatalf("unreadable ZIP: %v", err)
		}
		rc, err := zr.File[0].Open()
		if err != nil {
			t.Fatalf("unreadable ZIP entry: %v", err)
		}
		defer rc.Close()
		if data, err = io.ReadAll(io.LimitReader(rc, maxMasterListSize)); err != nil {
			t.Fatalf("unreadable ZIP entry: %v", err)
		}
	}
	return data
}

// masterListCertificates extracts every certificate DER from a CSCA Master
// List: ContentInfo { OID, [0] SignedData { version, digestAlgs, encapContentInfo
// { OID, [0] OCTET STRING { SEQUENCE { version, SET OF Certificate } } }, ... } }.
// The CMS signature itself is not verified: only the certificates are used.
func masterListCertificates(data []byte) ([][]byte, error) {
	in := cryptobyte.String(data)
	var ci, sdWrap, sd, encap, eContentWrap, ml, certSet cryptobyte.String
	ctx0 := cbasn1.Tag(0).ContextSpecific().Constructed()
	if !in.ReadASN1(&ci, cbasn1.SEQUENCE) || !ci.SkipASN1(cbasn1.OBJECT_IDENTIFIER) ||
		!ci.ReadASN1(&sdWrap, ctx0) || !sdWrap.ReadASN1(&sd, cbasn1.SEQUENCE) {
		return nil, errors.New("not a CMS ContentInfo/SignedData (BER indefinite lengths are not supported)")
	}
	if !sd.SkipASN1(cbasn1.INTEGER) || !sd.SkipASN1(cbasn1.SET) || !sd.ReadASN1(&encap, cbasn1.SEQUENCE) ||
		!encap.SkipASN1(cbasn1.OBJECT_IDENTIFIER) || !encap.ReadASN1(&eContentWrap, ctx0) {
		return nil, errors.New("no encapsulated content")
	}
	var octets cryptobyte.String
	if !eContentWrap.ReadASN1(&octets, cbasn1.OCTET_STRING) {
		return nil, errors.New("encapsulated content is not an OCTET STRING")
	}
	if !octets.ReadASN1(&ml, cbasn1.SEQUENCE) || !ml.SkipASN1(cbasn1.INTEGER) || !ml.ReadASN1(&certSet, cbasn1.SET) {
		return nil, errors.New("encapsulated content is not a CSCAMasterList")
	}
	var certs [][]byte
	for !certSet.Empty() {
		var c cryptobyte.String
		if !certSet.ReadASN1Element(&c, cbasn1.SEQUENCE) {
			return nil, errors.New("malformed certificate in list")
		}
		certs = append(certs, c)
	}
	return certs, nil
}

func reason(err error) string {
	switch msg := err.Error(); {
	case strings.Contains(msg, "invalid ECDSA parameters"):
		return "explicit EC parameters (invalid ECDSA parameters)"
	case strings.Contains(msg, "negative serial"):
		return "negative serial number"
	case strings.Contains(msg, "missing NULL"):
		return "RSA key missing NULL parameters"
	default:
		return "other: " + strings.SplitN(msg, "\n", 2)[0]
	}
}

// mlTally accumulates the outcome of parsing a master list.
type mlTally struct {
	t                        *testing.T
	ext                      *cryptoutil.Extensions
	stdOK, extOK             int
	selfSigned, selfSignedOK int
	stdFail, stillFail       map[string]int // rejection reasons
	declined, curves         map[string]int
}

func newTally(t *testing.T) *mlTally {
	ext := cryptoutil.New()
	brainpool.Register(ext)
	Register(ext)
	return &mlTally{
		t: t, ext: ext,
		stdFail: map[string]int{}, stillFail: map[string]int{},
		declined: map[string]int{}, curves: map[string]int{},
	}
}

func isExplicitParamsError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "invalid ECDSA parameters")
}

// checkDeclined accepts a failure to parse an explicit-parameter certificate
// only as a deliberate decline (unknown curve, or stdlib strictness about an
// unrelated field).
func (m *mlTally) checkDeclined(i int, der []byte) {
	_, perr := Parser(der)
	msg := fmt.Sprint(perr)
	if !errors.Is(perr, cryptoutil.ErrNotHandled) ||
		(!strings.Contains(msg, "match no known curve") && !strings.Contains(msg, "not repairable")) {
		m.t.Errorf("cert %d: explicit-parameter certificate not parsed and not deliberately declined: %v", i, perr)
	}
	m.declined[strings.TrimPrefix(msg, cryptoutil.ErrNotHandled.Error()+": ecparams: ")]++
}

// checkSelfSigned verifies CSCAs that are self-signed with their own key.
func (m *mlTally) checkSelfSigned(i int, cert *x509.Certificate) {
	if string(cert.RawIssuer) != string(cert.RawSubject) ||
		(len(cert.AuthorityKeyId) != 0 && !bytes.Equal(cert.AuthorityKeyId, cert.SubjectKeyId)) {
		return
	}
	m.selfSigned++
	if err := m.ext.CheckSignature(cert, cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		m.t.Errorf("cert %d (%s): self-signature does not verify: %v", i, cert.Subject, err)
		return
	}
	m.selfSignedOK++
}

func (m *mlTally) process(i int, der []byte) {
	_, stdErr := x509.ParseCertificate(der)
	if stdErr == nil {
		m.stdOK++
	} else {
		m.stdFail[reason(stdErr)]++
	}
	cert, err := m.ext.ParseCertificate(der)
	if err == nil && (cert == nil || cert.PublicKey == nil) {
		err = errors.New("parsed without public key")
	}
	if err != nil {
		m.stillFail[reason(err)]++
		if isExplicitParamsError(stdErr) {
			m.checkDeclined(i, der)
		}
		return
	}
	m.extOK++
	if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		if !onKnownCurve(pub) {
			m.t.Errorf("cert %d (%s): key is not on a known curve", i, cert.Subject)
			return
		}
		if isExplicitParamsError(stdErr) {
			m.curves[pub.Curve.Params().Name]++
		}
	}
	m.checkSelfSigned(i, cert)
}

func TestMasterListIntegration(t *testing.T) {
	certs, err := masterListCertificates(loadMasterList(t))
	if err != nil {
		t.Fatalf("master list: %v", err)
	}
	if len(certs) == 0 {
		t.Fatal("master list holds no certificates")
	}
	m := newTally(t)
	for i, der := range certs {
		m.process(i, der)
	}
	t.Logf("certificates: %d", len(certs))
	t.Logf("stdlib parsable: %d; rejected: %d %s", m.stdOK, len(certs)-m.stdOK, summarize(m.stdFail))
	t.Logf("parsable with extensions: %d; still failing: %d %s", m.extOK, len(certs)-m.extOK, summarize(m.stillFail))
	t.Logf("explicit-parameter keys recovered, by curve: %s", summarize(m.curves))
	t.Logf("deliberately declined explicit-parameter certificates: %s", summarize(m.declined))
	t.Logf("self-signed certificates verified: %d of %d", m.selfSignedOK, m.selfSigned)
}

func summarize(m map[string]int) string {
	if len(m) == 0 {
		return "{}"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s=%d", k, m[k])
	}
	return "{" + strings.Join(parts, "; ") + "}"
}
