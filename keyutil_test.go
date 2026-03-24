package cryptoutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestParsePrivateKeyPKCS8(t *testing.T) {
	ext := New()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ext.ParsePrivateKey(der)
	if err != nil {
		t.Fatalf("ParsePrivateKey PKCS8: %v", err)
	}
	if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
		t.Errorf("expected *ecdsa.PrivateKey, got %T", parsed)
	}
}

func TestParsePrivateKeyEC(t *testing.T) {
	ext := New()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ext.ParsePrivateKey(der)
	if err != nil {
		t.Fatalf("ParsePrivateKey EC: %v", err)
	}
	if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
		t.Errorf("expected *ecdsa.PrivateKey, got %T", parsed)
	}
}

func TestParsePrivateKeyPKCS1(t *testing.T) {
	ext := New()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	parsed, err := ext.ParsePrivateKey(der)
	if err != nil {
		t.Fatalf("ParsePrivateKey PKCS1: %v", err)
	}
	if _, ok := parsed.(*rsa.PrivateKey); !ok {
		t.Errorf("expected *rsa.PrivateKey, got %T", parsed)
	}
}

func TestParsePrivateKeyExtension(t *testing.T) {
	ext := New()
	called := false
	ext.KeyParsers = append(ext.KeyParsers, func(der []byte) (crypto.PrivateKey, error) {
		called = true
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		return k, nil
	})
	// Feed garbage that no stdlib parser handles
	_, err := ext.ParsePrivateKey([]byte{0xDE, 0xAD})
	if err != nil {
		t.Fatalf("expected extension to handle: %v", err)
	}
	if !called {
		t.Error("extension parser was not called")
	}
}

func TestParsePrivateKeyExtensionNotHandled(t *testing.T) {
	ext := New()
	ext.KeyParsers = append(ext.KeyParsers, func(der []byte) (crypto.PrivateKey, error) {
		return nil, ErrNotHandled
	})
	_, err := ext.ParsePrivateKey([]byte{0xDE, 0xAD})
	if err == nil {
		t.Error("expected error when all parsers fail")
	}
}

func TestParsePrivateKeyPEM(t *testing.T) {
	ext := New()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	parsed, err := ext.ParsePrivateKeyPEM(pemData)
	if err != nil {
		t.Fatalf("ParsePrivateKeyPEM: %v", err)
	}
	if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
		t.Errorf("expected *ecdsa.PrivateKey, got %T", parsed)
	}
}

func TestParsePrivateKeyPEMNoPEM(t *testing.T) {
	ext := New()
	_, err := ext.ParsePrivateKeyPEM([]byte("not PEM data"))
	if err == nil {
		t.Error("expected error for non-PEM data")
	}
}

func TestPublicKeyFromSigner(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := PublicKeyFromSigner(key)
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Errorf("expected *ecdsa.PublicKey, got %T", pub)
	}
}

func TestIsECDSAKey(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)

	if !IsECDSAKey(&ecKey.PublicKey) {
		t.Error("expected true for ECDSA key")
	}
	if IsECDSAKey(&rsaKey.PublicKey) {
		t.Error("expected false for RSA key")
	}
	if IsECDSAKey(edPub) {
		t.Error("expected false for EdDSA key")
	}
}

func TestIsRSAKey(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	if !IsRSAKey(&rsaKey.PublicKey) {
		t.Error("expected true for RSA key")
	}
	if IsRSAKey(&ecKey.PublicKey) {
		t.Error("expected false for ECDSA key")
	}
}

func TestIsEdDSAKey(t *testing.T) {
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if !IsEdDSAKey(edPub) {
		t.Error("expected true for EdDSA key")
	}
	if IsEdDSAKey(&ecKey.PublicKey) {
		t.Error("expected false for ECDSA key")
	}
}
