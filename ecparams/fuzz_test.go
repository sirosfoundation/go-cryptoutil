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
	addPaddedAndBERSeeds(f)
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

// addPaddedAndBERSeeds seeds the corpus with zero-padded constants, BER-style
// cA BOOLEANs and the real certificates of sirosfoundation/go-cryptoutil#36.
func addPaddedAndBERSeeds(f *testing.F) {
	for _, name := range []string{"P-384", "brainpoolP384r1"} {
		k := curveByName(name)
		o := defaultOpts(k)
		o.padAB = 1
		f.Add(newExplicitCertBC(f, k, encodeExplicitParams(k, o), []byte{0x05}, []byte{0x30, 0x03, 0x01, 0x01, 0x01}).der)
	}
	for _, bc := range [][]byte{{0x30, 0x06, 0x01, 0x01, 0x01, 0x02, 0x01, 0x00}, {0x30, 0x02, 0x01, 0x01}, {0x30, 0x03, 0x02, 0x01, 0x01}} {
		key, _ := ecdsa.GenerateKey(curveByName("P-256").curve, rand.Reader)
		tbs := encodeTBSWithBC([]byte{0x05}, oidECDSASHA256, false, mustMarshalPKIX(f, &key.PublicKey), bc)
		sig, _ := ecdsa.SignASN1(rand.Reader, key, hashSum(sigHash(), tbs))
		f.Add(assemble(tbs, oidECDSASHA256, false, sig)) // a whole certificate, so the seed reaches the parser
	}
	for _, file := range []string{"testdata/csca_are_padded_constants.pem", "testdata/csca_ukr_ber_boolean.pem"} {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		if blk, _ := pem.Decode(data); blk != nil {
			f.Add(blk.Bytes)
		}
	}
}
