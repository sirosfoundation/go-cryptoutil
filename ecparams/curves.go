package ecparams

import (
	"crypto/elliptic"
	"math/big"
	"sync"

	gematik "github.com/gematik/zero-lab/go/brainpool"
)

// knownCurve holds the complete, fixed domain parameters of a curve that this
// package is willing to recognize. A certificate's self-described parameters
// are only ever accepted if they equal one of these entries exactly.
type knownCurve struct {
	name   string
	p, a   *big.Int
	b      *big.Int
	gx, gy *big.Int
	n      *big.Int
	h      int64
	curve  elliptic.Curve
}

// byteLen is the size in octets of a field element.
func (k *knownCurve) byteLen() int { return (k.p.BitLen() + 7) / 8 }

// onCurve reports whether (x, y) is a point of the curve: 0 <= x,y < p and
// y^2 = x^3 + a*x + b (mod p). It is used instead of the deprecated
// elliptic.Curve.IsOnCurve so that it works uniformly for every known curve.
func (k *knownCurve) onCurve(x, y *big.Int) bool {
	if x.Sign() < 0 || y.Sign() < 0 || x.Cmp(k.p) >= 0 || y.Cmp(k.p) >= 0 {
		return false
	}
	lhs := new(big.Int).Mul(y, y)
	lhs.Mod(lhs, k.p)
	rhs := new(big.Int).Mul(x, x)
	rhs.Add(rhs, k.a)
	rhs.Mul(rhs, x)
	rhs.Add(rhs, k.b)
	rhs.Mod(rhs, k.p)
	return lhs.Cmp(rhs) == 0
}

func hexInt(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("ecparams: bad hex constant " + s)
	}
	return v
}

// nist builds a table entry for a NIST prime curve (a = -3, h = 1) from the
// standard library's parameters.
func nist(c elliptic.Curve) *knownCurve {
	cp := c.Params()
	return &knownCurve{
		name:  cp.Name,
		p:     cp.P,
		a:     new(big.Int).Sub(cp.P, big.NewInt(3)),
		b:     cp.B,
		gx:    cp.Gx,
		gy:    cp.Gy,
		n:     cp.N,
		h:     1,
		curve: c,
	}
}

// brainpoolR1 builds a table entry for a Brainpool "r1" curve (RFC 5639, h = 1)
// with the coefficients A and B given as hex (the gematik curves are
// isomorphic rcurve wrappers whose Params carry no B, and no curve carries A).
func brainpoolR1(c elliptic.Curve, a, b string) *knownCurve {
	cp := c.Params()
	return &knownCurve{
		name:  cp.Name,
		p:     cp.P,
		a:     hexInt(a),
		b:     hexInt(b),
		gx:    cp.Gx,
		gy:    cp.Gy,
		n:     cp.N,
		h:     1,
		curve: c,
	}
}

// known returns the table of recognized curves. The brainpool implementation
// is the gematik library already used by the sibling brainpool package, which
// provides only the r1 curves of 256, 384 and 512 bits; the smaller brainpool
// curves (P160r1 .. P320r1) and all twisted (t1) curves are not available and
// are therefore never matched.
var known = sync.OnceValue(func() []*knownCurve {
	return []*knownCurve{
		nist(elliptic.P224()),
		nist(elliptic.P256()),
		nist(elliptic.P384()),
		nist(elliptic.P521()),
		brainpoolR1(gematik.P256r1(), "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9",
			"26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6"),
		brainpoolR1(gematik.P384r1(), "7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826",
			"04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11"),
		brainpoolR1(gematik.P512r1(), "7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA",
			"3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723"),
	}
})

// curveByName returns the known curve with the given elliptic.CurveParams name.
func curveByName(name string) *knownCurve {
	for _, k := range known() {
		if k.name == name {
			return k
		}
	}
	return nil
}
