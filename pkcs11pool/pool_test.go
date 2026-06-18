package pkcs11pool

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// testConfig returns a Config for a SoftHSM test token.
// It creates a temporary token directory and initializes a test token.
func testConfig(t *testing.T) Config {
	t.Helper()

	// Skip if SoftHSM is not available.
	if _, err := exec.LookPath("softhsm2-util"); err != nil {
		t.Skip("softhsm2-util not found; skipping PKCS#11 integration tests")
	}

	modulePath := os.Getenv("SOFTHSM2_MODULE")
	if modulePath == "" {
		// Try common paths.
		for _, p := range []string{
			"/usr/lib/softhsm/libsofthsm2.so",
			"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
			"/usr/local/lib/softhsm/libsofthsm2.so",
		} {
			if _, err := os.Stat(p); err == nil {
				modulePath = p
				break
			}
		}
	}
	if modulePath == "" {
		t.Skip("SoftHSM2 module not found")
	}

	tmpDir := t.TempDir()
	tokenDir := filepath.Join(tmpDir, "tokens")
	if err := os.MkdirAll(tokenDir, 0o700); err != nil {
		t.Fatal(err)
	}

	confFile := filepath.Join(tmpDir, "softhsm2.conf")
	if err := os.WriteFile(confFile, []byte("directories.tokendir = "+tokenDir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOFTHSM2_CONF", confFile)

	// Initialize token.
	cmd := exec.Command("softhsm2-util", "--init-token", "--slot", "0",
		"--label", "test-token", "--pin", "1234", "--so-pin", "5678")
	cmd.Env = append(os.Environ(), "SOFTHSM2_CONF="+confFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("softhsm2-util init failed: %v\n%s", err, out)
	}

	return Config{
		ModulePath: modulePath,
		TokenLabel: "test-token",
		PIN:        "1234",
		PoolSize:   2,
		ReadWrite:  true,
	}
}

func TestNewPool(t *testing.T) {
	cfg := testConfig(t)
	pool, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer pool.Close()

	if pool.PoolSize() != 2 {
		t.Errorf("PoolSize = %d, want 2", pool.PoolSize())
	}
	if pool.Ctx() == nil {
		t.Error("Ctx() is nil")
	}
}

func TestNewPoolDefaultSize(t *testing.T) {
	cfg := testConfig(t)
	cfg.PoolSize = 0 // should default to 4
	pool, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer pool.Close()

	if pool.PoolSize() != 4 {
		t.Errorf("PoolSize = %d, want 4", pool.PoolSize())
	}
}

func TestNewPoolBadModule(t *testing.T) {
	cfg := Config{
		ModulePath: "/nonexistent/module.so",
		PIN:        "1234",
	}
	_, err := New(cfg)
	if err == nil {
		t.Fatal("expected error for bad module path")
	}
}

func TestNewPoolBadTokenLabel(t *testing.T) {
	cfg := testConfig(t)
	cfg.TokenLabel = "nonexistent-token"
	_, err := New(cfg)
	if err == nil {
		t.Fatal("expected error for non-existent token label")
	}
}

func TestAcquireRelease(t *testing.T) {
	cfg := testConfig(t)
	pool, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer pool.Close()

	ctx := context.Background()
	sess, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	pool.Release(sess)
}

func TestAcquireContextCancelled(t *testing.T) {
	cfg := testConfig(t)
	cfg.PoolSize = 1
	pool, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer pool.Close()

	ctx := context.Background()
	// Drain the pool.
	sess, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	// Second acquire should block and then fail on cancelled context.
	ctx2, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err = pool.Acquire(ctx2)
	if err == nil {
		t.Fatal("expected context deadline error")
	}

	pool.Release(sess)
}

func TestAcquireAfterClose(t *testing.T) {
	cfg := testConfig(t)
	pool, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pool.Close()

	_, err = pool.Acquire(context.Background())
	if err == nil {
		t.Fatal("expected error acquiring from closed pool")
	}
}

func TestCloseIdempotent(t *testing.T) {
	cfg := testConfig(t)
	pool, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := pool.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := pool.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestReleaseAfterClose(t *testing.T) {
	cfg := testConfig(t)
	pool, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	sess, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	pool.Close()
	// Release after close should not panic.
	pool.Release(sess)
}

func TestGenerateECKeyAndSign(t *testing.T) {
	cfg := testConfig(t)
	pool, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer pool.Close()

	ctx := context.Background()
	kid, pubBytes, err := pool.GenerateECKey(ctx, "P-256")
	if err != nil {
		t.Fatalf("GenerateECKey: %v", err)
	}
	if kid == "" {
		t.Error("kid is empty")
	}
	if len(pubBytes) == 0 {
		t.Error("pubBytes is empty")
	}

	// Now sign with the key using NewSigner.
	// GenerateECKey stores the kid in CKA_ID (not CKA_LABEL).
	signer, err := NewSigner(pool, KeyByID([]byte(kid)))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	digest := sha256.Sum256([]byte("test data"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Error("signature is empty")
	}

	// Verify the signature.
	pubKey, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("public key is not ECDSA")
	}
	if !ecdsa.VerifyASN1(pubKey, digest[:], sig) {
		t.Error("signature verification failed")
	}
}

func TestSignerAlgorithm(t *testing.T) {
	cfg := testConfig(t)
	pool, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer pool.Close()

	ctx := context.Background()
	kid, _, err := pool.GenerateECKey(ctx, "P-256")
	if err != nil {
		t.Fatalf("GenerateECKey: %v", err)
	}

	signer, err := NewSigner(pool, KeyByID([]byte(kid)))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	if alg := signer.Algorithm(); alg != "ES256" {
		t.Errorf("Algorithm() = %q, want ES256", alg)
	}
}

func TestGenerateECKeyP384(t *testing.T) {
	cfg := testConfig(t)
	pool, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer pool.Close()

	ctx := context.Background()
	kid, _, err := pool.GenerateECKey(ctx, "P-384")
	if err != nil {
		t.Fatalf("GenerateECKey P-384: %v", err)
	}

	signer, err := NewSigner(pool, KeyByID([]byte(kid)))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	if alg := signer.Algorithm(); alg != "ES384" {
		t.Errorf("Algorithm() = %q, want ES384", alg)
	}

	// Sign and verify.
	digest := sha256.Sum256([]byte("p384 test"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	pubKey := signer.Public().(*ecdsa.PublicKey)
	if !ecdsa.VerifyASN1(pubKey, digest[:], sig) {
		t.Error("P-384 signature verification failed")
	}
}

func TestFindKeyNotFound(t *testing.T) {
	cfg := testConfig(t)
	pool, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer pool.Close()

	sess, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer pool.Release(sess)

	_, err = pool.FindPrivateKey(sess, KeyByLabel("nonexistent-key"))
	if err == nil {
		t.Error("expected error for non-existent key")
	}

	_, err = pool.FindPublicKey(sess, KeyByLabel("nonexistent-key"))
	if err == nil {
		t.Error("expected error for non-existent key")
	}
}

func TestNewSignerKeyNotFound(t *testing.T) {
	cfg := testConfig(t)
	pool, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer pool.Close()

	_, err = NewSigner(pool, KeyByLabel("nonexistent"))
	if err == nil {
		t.Error("expected error for nonexistent key")
	}
}

func TestECDH(t *testing.T) {
	cfg := testConfig(t)
	pool, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer pool.Close()

	ctx := context.Background()
	kid, _, err := pool.GenerateECKey(ctx, "P-256")
	if err != nil {
		t.Fatalf("GenerateECKey: %v", err)
	}

	// Generate a peer key in software for ECDH.
	peerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate peer key: %v", err)
	}
	peerPub := elliptic.Marshal(elliptic.P256(), peerKey.PublicKey.X, peerKey.PublicKey.Y)

	secret, err := pool.ECDH(ctx, KeyByID([]byte(kid)), peerPub)
	if err != nil {
		t.Fatalf("ECDH: %v", err)
	}
	if len(secret) == 0 {
		t.Error("ECDH secret is empty")
	}
}

func TestListECKeys(t *testing.T) {
	cfg := testConfig(t)
	pool, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer pool.Close()

	ctx := context.Background()
	// Generate a key so we have something to list.
	_, _, err = pool.GenerateECKey(ctx, "P-256")
	if err != nil {
		t.Fatalf("GenerateECKey: %v", err)
	}

	keys, err := pool.ListECKeys(ctx, []string{"P-256"})
	if err != nil {
		t.Fatalf("ListECKeys: %v", err)
	}
	if len(keys) == 0 {
		t.Error("expected at least one key")
	}
}

func TestRecoverSession(t *testing.T) {
	cfg := testConfig(t)
	pool, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer pool.Close()

	sess, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	// Recover should return a new valid session.
	newSess, err := pool.RecoverSession(sess)
	if err != nil {
		t.Fatalf("RecoverSession: %v", err)
	}
	// Return the recovered session.
	pool.Release(newSess)
}

func TestKeySelectorHelpers(t *testing.T) {
	sel := KeyByLabel("my-key")
	if sel.Label != "my-key" {
		t.Errorf("KeyByLabel: got %q", sel.Label)
	}
	if sel.ID != nil {
		t.Error("KeyByLabel should have nil ID")
	}

	id := []byte{0x01, 0x02}
	sel = KeyByID(id)
	if sel.Label != "" {
		t.Error("KeyByID should have empty Label")
	}
	if len(sel.ID) != 2 || sel.ID[0] != 0x01 {
		t.Error("KeyByID ID mismatch")
	}
}

func TestRawSigToASN1(t *testing.T) {
	// 64-byte P-256 raw signature (r || s, each 32 bytes).
	raw := make([]byte, 64)
	raw[0] = 0x01 // r[0]
	raw[32] = 0x02 // s[0]

	der, err := RawSigToASN1(raw)
	if err != nil {
		t.Fatalf("RawSigToASN1: %v", err)
	}
	if len(der) == 0 {
		t.Error("DER signature is empty")
	}
	// DER should start with SEQUENCE tag.
	if der[0] != 0x30 {
		t.Errorf("expected SEQUENCE tag 0x30, got 0x%02x", der[0])
	}
}

func TestRawSigToASN1OddLength(t *testing.T) {
	// Odd-length should fail.
	_, err := RawSigToASN1([]byte{0x01, 0x02, 0x03})
	if err == nil {
		t.Error("expected error for odd-length raw signature")
	}
}

func TestCurveOIDRoundtrip(t *testing.T) {
	tests := []struct {
		name string
	}{
		{"P-256"},
		{"P-384"},
		{"P-521"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := curveOID(tt.name)
			if err != nil {
				t.Errorf("curveOID(%q): %v", tt.name, err)
			}
			_, err = parseCurve(tt.name)
			if err != nil {
				t.Errorf("parseCurve(%q): %v", tt.name, err)
			}
		})
	}
}

func TestCurveOIDUnsupported(t *testing.T) {
	_, err := curveOID("P-999")
	if err == nil {
		t.Error("expected error for unsupported curve")
	}
	_, err = parseCurve("P-999")
	if err == nil {
		t.Error("expected error for unsupported curve")
	}
}

func TestGenerateECKeyUnsupportedCurve(t *testing.T) {
	cfg := testConfig(t)
	pool, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer pool.Close()

	_, _, err = pool.GenerateECKey(context.Background(), "P-999")
	if err == nil {
		t.Error("expected error for unsupported curve")
	}
}
