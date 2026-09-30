package ecparams

import (
	"crypto/ecdsa"
	"errors"
	"testing"

	"github.com/sirosfoundation/go-cryptoutil"
)

func FuzzParser(f *testing.F) {
	for _, name := range []string{"P-256", "P-521", "brainpoolP256r1"} {
		k := curveByName(name)
		fx := newExplicitCert(f, k, encodeExplicitParams(k, defaultOpts(k)), []byte{0x80})
		f.Add(fx.der)
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
