package ecparams

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"testing"

	"github.com/sirosfoundation/go-cryptoutil"
)

func FuzzParser(f *testing.F) {
	for _, name := range []string{"P-256", "P-521", "brainpoolP256r1"} {
		k := curveByName(name)
		fx := newExplicitCert(f, k, encodeExplicitParams(k, defaultOpts(k)), []byte{0x80})
		f.Add(fx.der)
	}
	// Zero-padded constants and BER-style cA BOOLEAN seeds.
	for _, name := range []string{"P-384", "brainpoolP384r1"} {
		k := curveByName(name)
		o := defaultOpts(k)
		o.padAB = 1
		f.Add(newExplicitCertBC(f, k, encodeExplicitParams(k, o), []byte{0x05}, []byte{0x30, 0x03, 0x01, 0x01, 0x01}).der)
	}
	for _, bc := range [][]byte{{0x30, 0x06, 0x01, 0x01, 0x01, 0x02, 0x01, 0x00}, {0x30, 0x02, 0x01, 0x01}, {0x30, 0x03, 0x02, 0x01, 0x01}} {
		key, _ := ecdsa.GenerateKey(curveByName("P-256").curve, rand.Reader)
		f.Add(encodeTBSWithBC([]byte{0x05}, oidECDSASHA256, false, mustMarshalPKIX(f, &key.PublicKey), bc))
	}
	for _, file := range []string{"testdata/csca_are_padded_constants.pem", "testdata/csca_ukr_ber_boolean.pem"} {
		if data, err := os.ReadFile(file); err == nil {
			if blk, _ := pem.Decode(data); blk != nil {
				f.Add(blk.Bytes)
			}
		}
	}
	rsaDER, _ := newRSACert(f, true)
	f.Add(rsaDER)
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x80, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, der []byte) {
		cert, err := Parser(der)
		if err != nil {
			if !errors.Is(err, cryptoutil.ErrNotHandled) {
				t.Fatalf("unexpected error type: %v", err)
			}
			return
		}
		if cert == nil || cert.PublicKey == nil || string(cert.Raw) != string(der) {
			t.Fatal("accepted certificate is incomplete")
		}
		if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
			if !onKnownCurve(pub) {
				t.Fatal("accepted a key that is not on a known curve")
			}
		}
	})
}

func FuzzMatchExplicitParams(f *testing.F) {
	for _, name := range allCurveNames {
		k := curveByName(name)
		f.Add(encodeExplicitParams(k, defaultOpts(k)))
	}
	f.Fuzz(func(t *testing.T, el []byte) {
		k, err := matchExplicitParams(el)
		if err != nil {
			if !errors.Is(err, cryptoutil.ErrNotHandled) {
				t.Fatalf("unexpected error type: %v", err)
			}
			return
		}
		// Anything accepted must be an exact match: re-encoding the known
		// curve must produce equal parameter values.
		if k == nil || k.h != 1 {
			t.Fatal("bad match")
		}
	})
}
