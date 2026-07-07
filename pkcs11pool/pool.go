package pkcs11pool

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/miekg/pkcs11"
)

// Pool manages a pool of PKCS#11 sessions against a single token.
type Pool struct {
	cfg    Config
	ctx    *pkcs11.Ctx
	slotID uint
	pool   chan pkcs11.SessionHandle

	mu     sync.Mutex
	closed bool
}

// New creates a Pool by initializing the PKCS#11 module, discovering the slot,
// logging in, and opening PoolSize sessions.
func New(cfg Config) (*Pool, error) {
	ctx := pkcs11.New(cfg.ModulePath)
	if ctx == nil {
		return nil, fmt.Errorf("pkcs11pool: failed to load module: %s", cfg.ModulePath)
	}

	if err := ctx.Initialize(); err != nil {
		return nil, fmt.Errorf("pkcs11pool: initialize: %w", err)
	}

	slotID := cfg.SlotID
	if cfg.TokenLabel != "" {
		slots, err := ctx.GetSlotList(true)
		if err != nil {
			_ = ctx.Finalize()
			return nil, fmt.Errorf("pkcs11pool: get slot list: %w", err)
		}
		found := false
		for _, s := range slots {
			ti, err := ctx.GetTokenInfo(s)
			if err != nil {
				continue
			}
			if strings.TrimSpace(ti.Label) == cfg.TokenLabel {
				slotID = s
				found = true
				break
			}
		}
		if !found {
			_ = ctx.Finalize()
			return nil, fmt.Errorf("pkcs11pool: token with label %q not found", cfg.TokenLabel)
		}
	}

	poolSize := cfg.PoolSize
	if poolSize <= 0 {
		poolSize = 4
	}

	flags := uint(pkcs11.CKF_SERIAL_SESSION)
	if cfg.ReadWrite {
		flags |= pkcs11.CKF_RW_SESSION
	}

	// Open first session and login (login is per-token, shared across sessions).
	first, err := ctx.OpenSession(slotID, flags)
	if err != nil {
		_ = ctx.Finalize()
		return nil, fmt.Errorf("pkcs11pool: open session: %w", err)
	}

	if err := ctx.Login(first, pkcs11.CKU_USER, cfg.PIN); err != nil {
		if !isAlreadyLoggedIn(err) {
			_ = ctx.CloseSession(first)
			_ = ctx.Finalize()
			return nil, fmt.Errorf("pkcs11pool: login: %w", err)
		}
	}

	pool := make(chan pkcs11.SessionHandle, poolSize)
	pool <- first

	// Open remaining sessions (already logged in per-token).
	for i := 1; i < poolSize; i++ {
		sess, err := ctx.OpenSession(slotID, flags)
		if err != nil {
			close(pool)
			for s := range pool {
				_ = ctx.CloseSession(s)
			}
			_ = ctx.Logout(first)
			_ = ctx.Finalize()
			return nil, fmt.Errorf("pkcs11pool: open pool session %d: %w", i, err)
		}
		pool <- sess
	}

	return &Pool{
		cfg:    cfg,
		ctx:    ctx,
		slotID: slotID,
		pool:   pool,
	}, nil
}

// Acquire gets a session from the pool, respecting context cancellation.
func (p *Pool) Acquire(ctx context.Context) (pkcs11.SessionHandle, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return 0, fmt.Errorf("pkcs11pool: pool is closed")
	}
	p.mu.Unlock()

	select {
	case sess, ok := <-p.pool:
		if !ok {
			return 0, fmt.Errorf("pkcs11pool: pool is closed")
		}
		return sess, nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

// Release returns a session to the pool. Safe to call after Close;
// late-released sessions are closed directly.
func (p *Pool) Release(sess pkcs11.SessionHandle) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		if p.ctx != nil {
			_ = p.ctx.CloseSession(sess)
		}
		return
	}
	p.pool <- sess
}

// RecoverSession replaces a broken session with a fresh one.
// Opens a new session first, then closes the broken one, so the pool
// never loses a slot.
func (p *Pool) RecoverSession(broken pkcs11.SessionHandle) (pkcs11.SessionHandle, error) {
	flags := uint(pkcs11.CKF_SERIAL_SESSION)
	if p.cfg.ReadWrite {
		flags |= pkcs11.CKF_RW_SESSION
	}

	sess, err := p.ctx.OpenSession(p.slotID, flags)
	if err != nil {
		return 0, fmt.Errorf("pkcs11pool: recover session: %w", err)
	}
	// Login is per-token; re-login tolerates CKR_USER_ALREADY_LOGGED_IN.
	if err := p.ctx.Login(sess, pkcs11.CKU_USER, p.cfg.PIN); err != nil {
		if !isAlreadyLoggedIn(err) {
			_ = p.ctx.CloseSession(sess)
			return 0, fmt.Errorf("pkcs11pool: recover login: %w", err)
		}
	}
	// Close broken session after replacement is ready.
	_ = p.ctx.CloseSession(broken)
	return sess, nil
}

// Close drains the session pool and releases the PKCS#11 context.
// Sessions that are checked out when Close is called will be cleaned up
// when they are returned via Release.
func (p *Pool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}
	p.closed = true

	close(p.pool)
	var firstSess pkcs11.SessionHandle
	var hasFirst bool
	for s := range p.pool {
		if !hasFirst {
			firstSess = s
			hasFirst = true
			continue
		}
		_ = p.ctx.CloseSession(s)
	}
	// Logout using a valid session before closing it.
	if hasFirst {
		_ = p.ctx.Logout(firstSess)
		_ = p.ctx.CloseSession(firstSess)
	}
	_ = p.ctx.Finalize()
	// Note: p.ctx is kept non-nil so that late Release calls can still
	// close checked-out sessions. The Ctx is finalized but CloseSession
	// on a finalized context is a safe no-op.
	return nil
}

// Ctx returns the underlying PKCS#11 context for advanced operations.
func (p *Pool) Ctx() *pkcs11.Ctx {
	return p.ctx
}

// PoolSize returns the pool capacity.
func (p *Pool) PoolSize() int {
	return cap(p.pool)
}

// --- Key lookup ---

// FindPrivateKey locates a private key by selector in the given session.
func (p *Pool) FindPrivateKey(session pkcs11.SessionHandle, sel KeySelector) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	}
	if sel.Label != "" {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, sel.Label))
	}
	if sel.ID != nil {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, sel.ID))
	}

	if err := p.ctx.FindObjectsInit(session, template); err != nil {
		return 0, fmt.Errorf("pkcs11pool: find init (private): %w", err)
	}
	defer p.ctx.FindObjectsFinal(session) //nolint:errcheck

	handles, _, err := p.ctx.FindObjects(session, 1)
	if err != nil {
		return 0, fmt.Errorf("pkcs11pool: find objects (private): %w", err)
	}
	if len(handles) == 0 {
		return 0, fmt.Errorf("pkcs11pool: private key not found (label=%q, id=%x)", sel.Label, sel.ID)
	}
	return handles[0], nil
}

// FindPublicKey locates a public key by selector in the given session.
func (p *Pool) FindPublicKey(session pkcs11.SessionHandle, sel KeySelector) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
	}
	if sel.Label != "" {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, sel.Label))
	}
	if sel.ID != nil {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, sel.ID))
	}

	if err := p.ctx.FindObjectsInit(session, template); err != nil {
		return 0, fmt.Errorf("pkcs11pool: find init (public): %w", err)
	}
	defer p.ctx.FindObjectsFinal(session) //nolint:errcheck

	handles, _, err := p.ctx.FindObjects(session, 1)
	if err != nil {
		return 0, fmt.Errorf("pkcs11pool: find objects (public): %w", err)
	}
	if len(handles) == 0 {
		return 0, fmt.Errorf("pkcs11pool: public key not found (label=%q, id=%x)", sel.Label, sel.ID)
	}
	return handles[0], nil
}

// --- Public key extraction ---

// KeyType returns the CKA_KEY_TYPE of an object.
func (p *Pool) KeyType(session pkcs11.SessionHandle, handle pkcs11.ObjectHandle) (uint, error) {
	attrs, err := p.ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
	})
	if err != nil {
		return 0, fmt.Errorf("pkcs11pool: get key type: %w", err)
	}
	return bytesToUint(attrs[0].Value), nil
}

// ExtractECPublicKey reads an EC public key from the token.
func (p *Pool) ExtractECPublicKey(session pkcs11.SessionHandle, handle pkcs11.ObjectHandle) (*ecdsa.PublicKey, error) {
	attrs, err := p.ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("pkcs11pool: get EC attrs: %w", err)
	}

	curveName, err := oidToCurveName(attrs[1].Value)
	if err != nil {
		return nil, err
	}
	curve, err := parseCurve(curveName)
	if err != nil {
		return nil, err
	}

	ecPoint := attrs[0].Value
	if len(ecPoint) == 0 {
		return nil, fmt.Errorf("pkcs11pool: empty EC_POINT")
	}

	// PKCS#11 may wrap the EC point in an ASN.1 OCTET STRING. Unwrap if needed.
	ecPoint = unwrapECPoint(ecPoint, curve)

	keyLen := (curve.Params().BitSize + 7) / 8
	expectedLen := 1 + 2*keyLen
	if len(ecPoint) != expectedLen || ecPoint[0] != 0x04 {
		return nil, fmt.Errorf("pkcs11pool: invalid EC point: len=%d, expected=%d", len(ecPoint), expectedLen)
	}

	x := new(big.Int).SetBytes(ecPoint[1 : 1+keyLen])
	y := new(big.Int).SetBytes(ecPoint[1+keyLen:])

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// ExtractRSAPublicKey reads an RSA public key from the token.
func (p *Pool) ExtractRSAPublicKey(session pkcs11.SessionHandle, handle pkcs11.ObjectHandle) (*rsa.PublicKey, error) {
	attrs, err := p.ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("pkcs11pool: get RSA attrs: %w", err)
	}

	n := new(big.Int).SetBytes(attrs[0].Value)
	e := int(new(big.Int).SetBytes(attrs[1].Value).Int64())

	return &rsa.PublicKey{N: n, E: e}, nil
}

// ExtractPublicKey reads either an EC or RSA public key based on the key type.
func (p *Pool) ExtractPublicKey(session pkcs11.SessionHandle, handle pkcs11.ObjectHandle) (crypto.PublicKey, error) {
	kt, err := p.KeyType(session, handle)
	if err != nil {
		return nil, err
	}
	switch kt {
	case pkcs11.CKK_EC:
		return p.ExtractECPublicKey(session, handle)
	case pkcs11.CKK_RSA:
		return p.ExtractRSAPublicKey(session, handle)
	default:
		return nil, fmt.Errorf("pkcs11pool: unsupported key type: %d", kt)
	}
}

// --- EC point helpers ---

// ReadECPoint reads and unwraps an EC point, returning compressed form.
func (p *Pool) ReadECPoint(session pkcs11.SessionHandle, handle pkcs11.ObjectHandle, curveName string) ([]byte, error) {
	attrs, err := p.ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("pkcs11pool: get EC point: %w", err)
	}
	if len(attrs) == 0 || len(attrs[0].Value) == 0 {
		return nil, fmt.Errorf("pkcs11pool: empty EC point")
	}

	curve, err := parseCurve(curveName)
	if err != nil {
		return nil, err
	}

	ecPoint := unwrapECPoint(attrs[0].Value, curve)

	x, y := elliptic.Unmarshal(curve, ecPoint) //nolint:staticcheck
	if x == nil {
		return nil, fmt.Errorf("pkcs11pool: invalid EC point (len=%d)", len(ecPoint))
	}

	return elliptic.MarshalCompressed(curve, x, y), nil
}

// GetKeyCurve reads CKA_EC_PARAMS and returns the curve name (e.g. "P-256").
func (p *Pool) GetKeyCurve(session pkcs11.SessionHandle, handle pkcs11.ObjectHandle) (string, error) {
	attrs, err := p.ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
	})
	if err != nil {
		return "", fmt.Errorf("pkcs11pool: get EC params: %w", err)
	}
	if len(attrs) == 0 || len(attrs[0].Value) == 0 {
		return "", fmt.Errorf("pkcs11pool: empty EC params")
	}
	return oidToCurveName(attrs[0].Value)
}

// --- Signing ---

// SignECDSA signs a pre-hashed digest using CKM_ECDSA and returns ASN.1 DER.
func (p *Pool) SignECDSA(session pkcs11.SessionHandle, privKey pkcs11.ObjectHandle, digest []byte) ([]byte, error) {
	if err := p.ctx.SignInit(session, []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil),
	}, privKey); err != nil {
		return nil, fmt.Errorf("pkcs11pool: SignInit: %w", err)
	}

	rawSig, err := p.ctx.Sign(session, digest)
	if err != nil {
		return nil, fmt.Errorf("pkcs11pool: Sign: %w", err)
	}

	return RawSigToASN1(rawSig)
}

// SignRSAPKCS signs a pre-hashed digest using CKM_RSA_PKCS.
func (p *Pool) SignRSAPKCS(session pkcs11.SessionHandle, privKey pkcs11.ObjectHandle, digest []byte) ([]byte, error) {
	if err := p.ctx.SignInit(session, []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil),
	}, privKey); err != nil {
		return nil, fmt.Errorf("pkcs11pool: RSA SignInit: %w", err)
	}

	sig, err := p.ctx.Sign(session, digest)
	if err != nil {
		return nil, fmt.Errorf("pkcs11pool: RSA Sign: %w", err)
	}
	return sig, nil
}

// --- Key generation ---

// GenerateECKey creates a new EC key pair on the token.
// Returns the kid (hex-encoded SHA-256 prefix of the compressed public key)
// and the compressed public key bytes.
func (p *Pool) GenerateECKey(ctx context.Context, curveName string) (string, []byte, error) {
	session, err := p.Acquire(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("pkcs11pool: acquire session: %w", err)
	}
	defer p.Release(session)

	oid, err := curveOID(curveName)
	if err != nil {
		return "", nil, err
	}
	derOID, err := asn1.Marshal(oid)
	if err != nil {
		return "", nil, fmt.Errorf("pkcs11pool: marshal OID: %w", err)
	}

	// Temporary CKA_ID for creation; updated after we compute kid from pubkey.
	tmpID := make([]byte, 16)
	if _, err := rand.Read(tmpID); err != nil {
		return "", nil, fmt.Errorf("pkcs11pool: random: %w", err)
	}

	pubTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, derOID),
		pkcs11.NewAttribute(pkcs11.CKA_ID, tmpID),
	}
	privTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_ID, tmpID),
	}

	pubHandle, _, err := p.ctx.GenerateKeyPair(
		session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		pubTemplate,
		privTemplate,
	)
	if err != nil {
		return "", nil, fmt.Errorf("pkcs11pool: generate key pair: %w", err)
	}

	pubBytes, err := p.ReadECPoint(session, pubHandle, curveName)
	if err != nil {
		return "", nil, fmt.Errorf("pkcs11pool: read public key: %w", err)
	}

	// Compute kid from public key hash.
	hash := sha256.Sum256(pubBytes)
	kid := hex.EncodeToString(hash[:16])

	// Update CKA_ID on both handles to the computed kid.
	kidBytes := []byte(kid)
	if err := p.ctx.SetAttributeValue(session, pubHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, kidBytes),
	}); err != nil {
		return "", nil, fmt.Errorf("pkcs11pool: update pub CKA_ID: %w", err)
	}

	privHandle, err := p.FindPrivateKey(session, KeyByID(tmpID))
	if err != nil {
		return "", nil, fmt.Errorf("pkcs11pool: find priv by tmp ID: %w", err)
	}
	if err := p.ctx.SetAttributeValue(session, privHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, kidBytes),
	}); err != nil {
		return "", nil, fmt.Errorf("pkcs11pool: update priv CKA_ID: %w", err)
	}

	return kid, pubBytes, nil
}

// --- ECDH ---

// ECDH performs ECDH key agreement using the private key identified by sel
// and the given peer public key (uncompressed or compressed). Returns the raw
// shared secret.
func (p *Pool) ECDH(ctx context.Context, sel KeySelector, peerPubKey []byte) ([]byte, error) {
	session, err := p.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("pkcs11pool: acquire session: %w", err)
	}
	defer p.Release(session)

	privHandle, err := p.FindPrivateKey(session, sel)
	if err != nil {
		return nil, err
	}

	curveName, err := p.GetKeyCurve(session, privHandle)
	if err != nil {
		return nil, err
	}
	curve, err := parseCurve(curveName)
	if err != nil {
		return nil, err
	}

	// Ensure peer key is uncompressed (PKCS#11 requires it).
	ecPoint := peerPubKey
	if len(ecPoint) > 0 && (ecPoint[0] == 0x02 || ecPoint[0] == 0x03) {
		x, y := elliptic.UnmarshalCompressed(curve, ecPoint)
		if x == nil {
			return nil, fmt.Errorf("pkcs11pool: decompress peer key failed")
		}
		ecPoint = elliptic.Marshal(curve, x, y) //nolint:staticcheck
	}

	deriveLen := (curve.Params().BitSize + 7) / 8
	params := pkcs11.NewECDH1DeriveParams(pkcs11.CKD_NULL, nil, ecPoint)

	deriveTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, deriveLen),
	}

	secretHandle, err := p.ctx.DeriveKey(
		session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDH1_DERIVE, params)},
		privHandle,
		deriveTemplate,
	)
	if err != nil {
		return nil, fmt.Errorf("pkcs11pool: ECDH derive: %w", err)
	}

	attrs, err := p.ctx.GetAttributeValue(session, secretHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("pkcs11pool: get derived secret: %w", err)
	}
	if len(attrs) == 0 || len(attrs[0].Value) == 0 {
		return nil, fmt.Errorf("pkcs11pool: empty derived secret")
	}

	// Clean up the derived key object.
	_ = p.ctx.DestroyObject(session, secretHandle)

	return attrs[0].Value, nil
}

// --- Key listing ---

// KeyInfo describes an HSM-managed key.
type KeyInfo struct {
	Kid    string `json:"kid"`
	Curve  string `json:"curve"`
	PubKey []byte `json:"pub_key"` // Compressed EC public key.
}

// ListECKeys returns all EC keys matching the given curves.
// If curves is nil, returns all EC keys.
func (p *Pool) ListECKeys(ctx context.Context, curves []string) ([]KeyInfo, error) {
	session, err := p.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("pkcs11pool: acquire session: %w", err)
	}
	defer p.Release(session)

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
	}

	if err := p.ctx.FindObjectsInit(session, template); err != nil {
		return nil, fmt.Errorf("pkcs11pool: find init: %w", err)
	}

	var keys []KeyInfo
	for {
		handles, _, err := p.ctx.FindObjects(session, 32)
		if err != nil {
			_ = p.ctx.FindObjectsFinal(session)
			return nil, fmt.Errorf("pkcs11pool: find objects: %w", err)
		}
		if len(handles) == 0 {
			break
		}

		for _, h := range handles {
			curveName, err := p.GetKeyCurve(session, h)
			if err != nil {
				continue
			}
			if len(curves) > 0 && !containsStr(curves, curveName) {
				continue
			}

			pubBytes, err := p.ReadECPoint(session, h, curveName)
			if err != nil {
				continue
			}

			attrs, err := p.ctx.GetAttributeValue(session, h, []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
			})
			if err != nil || len(attrs) == 0 {
				continue
			}

			keys = append(keys, KeyInfo{
				// CKA_ID is stored as the ASCII hex kid string (see GenerateECKey);
				// convert bytes back to string directly — no hex re-encoding.
				Kid:    string(attrs[0].Value),
				Curve:  curveName,
				PubKey: pubBytes,
			})
		}
	}

	_ = p.ctx.FindObjectsFinal(session)
	return keys, nil
}

// --- Helpers ---

func unwrapECPoint(ecPoint []byte, curve elliptic.Curve) []byte {
	keyLen := (curve.Params().BitSize + 7) / 8
	expectedLen := 1 + 2*keyLen

	// Already a raw uncompressed point.
	if len(ecPoint) == expectedLen && ecPoint[0] == 0x04 {
		return ecPoint
	}

	// Try ASN.1 OCTET STRING unwrap.
	var rawPoint []byte
	rest, err := asn1.Unmarshal(ecPoint, &rawPoint)
	if err == nil && len(rest) == 0 {
		return rawPoint
	}
	return ecPoint
}

// RawSigToASN1 converts a raw ECDSA signature (r||s) to ASN.1 DER.
// If the input is already ASN.1 (starts with 0x30), it is returned as-is.
func RawSigToASN1(raw []byte) ([]byte, error) {
	// Some HSMs return ASN.1 DER directly.
	if len(raw) > 2 && raw[0] == 0x30 {
		return raw, nil
	}

	if len(raw)%2 != 0 {
		return nil, fmt.Errorf("pkcs11pool: invalid raw signature length: %d", len(raw))
	}

	half := len(raw) / 2
	r := new(big.Int).SetBytes(raw[:half])
	s := new(big.Int).SetBytes(raw[half:])

	type ecdsaSig struct {
		R, S *big.Int
	}
	return asn1.Marshal(ecdsaSig{R: r, S: s})
}

func isAlreadyLoggedIn(err error) bool {
	if pe, ok := err.(pkcs11.Error); ok {
		return pe == pkcs11.CKR_USER_ALREADY_LOGGED_IN
	}
	return false
}

func bytesToUint(b []byte) uint {
	var result uint
	for i := len(b) - 1; i >= 0; i-- {
		result = result<<8 | uint(b[i])
	}
	return result
}

func containsStr(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
