# go-cryptoutil
<div align="center">

[![Go Reference](https://pkg.go.dev/badge/github.com/sirosfoundation/go-cryptoutil.svg)](https://pkg.go.dev/github.com/sirosfoundation/go-cryptoutil)
[![Go Report Card](https://goreportcard.com/badge/github.com/sirosfoundation/go-cryptoutil)](https://goreportcard.com/report/github.com/sirosfoundation/go-cryptoutil)
![coverage](https://raw.githubusercontent.com/sirosfoundation/go-cryptoutil/badges/.badges/main/coverage.svg)
[![Build Status](https://github.com/sirosfoundation/go-cryptoutil/actions/workflows/test.yml/badge.svg)](https://github.com/sirosfoundation/go-cryptoutil/actions/workflows/test.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/sirosfoundation/go-cryptoutil/badge)](https://scorecard.dev/viewer/?uri=github.com/sirosfoundation/go-cryptoutil)
[![License](https://img.shields.io/badge/License-BSD_2--Clause-orange.svg)](https://opensource.org/licenses/BSD-2-Clause)
[![Go Version](https://img.shields.io/github/go-mod/go-version/sirosfoundation/go-cryptoutil)](https://github.com/sirosfoundation/go-cryptoutil)

</div>

Extensible Go crypto utilities for certificate parsing, signature verification,
ECDSA encoding, algorithm mapping, and key management — with a plugin architecture
for non-standard curves and future post-quantum algorithms.

## Overview

Go's `crypto/x509` package supports a fixed set of key types and curves.
`go-cryptoutil` provides an extension mechanism that lets you plug in support
for additional algorithms (e.g. brainpool curves, PQ signatures) without
forking the standard library.

### Core Module (`go-cryptoutil`)

Zero external dependencies. Provides:

- **`x509ext.go`** — Extensible certificate parsing and signature verification.
  Falls back to `crypto/x509` first, then tries registered extension parsers/verifiers.
- **`ecdsa.go`** — ECDSA signature format conversion between IEEE P1363 (raw r‖s)
  and ASN.1 DER. Used by XML-DSIG, JWS, COSE, and WebAuthn.
- **`algorithms.go`** — Cross-protocol algorithm registry mapping keys to
  JWS, XML-DSIG, and COSE algorithm identifiers.
- **`keyutil.go`** — Extensible private key parsing (PKCS#8, EC, PKCS#1) plus
  key type inspection helpers.

### Brainpool Plugin (`go-cryptoutil/brainpool`)

Separate Go module with the gematik brainpool dependency. Provides:

- `Register(ext)` — Registers brainpool P256r1, P384r1, P512r1 certificate
  parsing, signature verification, key parsing, and algorithm mappings.

### Explicit EC Parameters Plugin (`go-cryptoutil/ecparams`)

Opt-in, separate Go module (it needs the gematik brainpool curves). Parses
real-world certificates that `crypto/x509` rejects, notably ICAO 9303 eMRTD CSCA
certificates whose SubjectPublicKeyInfo carries **explicit EC domain parameters**
(`specifiedCurve`, RFC 3279 / X9.62) instead of a named-curve OID
(`x509: invalid ECDSA parameters`). Nothing changes unless you call `Register`.

```go
ext := cryptoutil.New()
brainpool.Register(ext) // optional
ecparams.Register(ext)
cert, err := ext.ParseCertificate(der) // cert.PublicKey is the matching *ecdsa.PublicKey
```

What it accepts:

- Explicit parameters whose prime field, curve `a`/`b`, base point, order and
  cofactor **exactly equal** those of NIST P-224/P-256/P-384/P-521 or
  brainpoolP256r1/P384r1/P512r1 (uncompressed or compressed base point; optional
  seed ignored; cofactor may be omitted, otherwise must be 1). The public key
  point must be uncompressed and on the matched curve.
- A negative serial number (`SerialNumber` carries the negative value).
- An RSA public key whose AlgorithmIdentifier lacks the NULL parameters.

What it never accepts: a self-described curve is never trusted. Unknown or
non-matching parameters (different prime, `a`, `b`, generator, order or cofactor,
binary fields, `implicitlyCA`, hybrid points, trailing data, twisted `t1`
Brainpool curves, and the Brainpool curves below 256 bits, which the brainpool
library does not provide) are declined with `ErrNotHandled`, so the certificate
stays rejected.

The returned certificate keeps the original `Raw`, `RawTBSCertificate`,
`RawSubjectPublicKeyInfo`, `Signature` and `SignatureAlgorithm`; nothing is
re-encoded, so signatures are checked over the original TBS. All other fields
(names, extensions, validity) come from `crypto/x509` parsing a copy of the
certificate in which only the offending element was replaced. `ecparams.Verifier`
(registered by `Register`) verifies ECDSA signatures made by keys on these
curves, in DER or raw r‖s form; with `PublicKey` set, `x509.Certificate.CheckSignature`
also verifies them on Go's standard library.

Master List integration test: `integration_test.go` parses every certificate of
a real CSCA Master List with and without the extensions and reports counts. It
**reads the public list at test time; nothing from it is stored in this
repository or redistributed.** It is skipped unless opted in:

```bash
cd ecparams
GOCRYPTOUTIL_PKD_MASTERLIST=/path/to/list.ml go test -run MasterList -v .   # local file or ZIP
GOCRYPTOUTIL_PKD_MASTERLIST_URL=https://... go test -run MasterList -v .     # download; honours SKIP_NETWORK_TESTS
```

The ICAO PKD Master List (<https://www.icao.int/icao-pkd/icao-master-list>,
download at <https://pkddownload.icao.int/>) is behind terms and a CAPTCHA, so
download it by hand and use the first form. National master lists have the same
format.

## Installation

```bash
# Core module (zero dependencies)
go get github.com/sirosfoundation/go-cryptoutil

# Brainpool plugin (adds gematik dependency)
go get github.com/sirosfoundation/go-cryptoutil/brainpool

# Explicit EC parameters / lenient eMRTD certificate plugin
go get github.com/sirosfoundation/go-cryptoutil/ecparams
```

## Usage

### Basic: Extensible Certificate Parsing

```go
import (
    "github.com/sirosfoundation/go-cryptoutil"
    "github.com/sirosfoundation/go-cryptoutil/brainpool"
)

ext := cryptoutil.New()
brainpool.Register(ext)

// Parse certificates — stdlib curves + brainpool
cert, err := ext.ParseCertificate(derBytes)

// Parse PEM bundles
certs, err := ext.ParseCertificatesPEM(pemData)
```

### ECDSA Signature Conversion

```go
// XML-DSIG / JWS raw r||s → ASN.1 DER (for Go's x509.CheckSignature)
derSig, err := cryptoutil.ECDSARawToASN1(rawSig)

// ASN.1 DER → raw r||s (for signing output)
rawSig, err := cryptoutil.ECDSAASN1ToRaw(derSig, 32) // 32 for P-256
```

### Algorithm Lookup

```go
ext := cryptoutil.New()
alg := ext.Algorithms.ForKey(publicKey)
fmt.Println(alg.JWS)     // "ES256"
fmt.Println(alg.XMLDSIG)  // "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
```

## Architecture

```
go-cryptoutil/           Core module (zero deps)
├── x509ext.go           Extensible cert parsing + sig verification
├── ecdsa.go             ECDSA raw↔ASN.1 conversion
├── algorithms.go        Cross-protocol algorithm registry
├── keyutil.go           Extensible key parsing + helpers
├── brainpool/           Plugin submodule
│   └── brainpool.go     Brainpool P256r1/P384r1/P512r1 support
└── ecparams/            Plugin submodule
    ├── ecparams.go      Explicit EC parameters, negative serial, RSA without NULL
    └── curves.go        Known-curve table (exact-match allowlist)
```

The extension mechanism uses function types (`CertificateParser`, `SignatureVerifier`,
`PrivateKeyParser`) registered on an `Extensions` struct. The core always tries
Go's standard library first and falls back to registered extensions, returning
`ErrNotHandled` to signal the next extension should be tried.

## Writing a Plugin

```go
func Register(ext *cryptoutil.Extensions) {
    ext.Parsers = append(ext.Parsers, func(der []byte) (*x509.Certificate, error) {
        // Try to parse; return cryptoutil.ErrNotHandled if not your cert type
        return myCert, nil
    })
    ext.Verifiers = append(ext.Verifiers, func(cert *x509.Certificate, algo x509.SignatureAlgorithm, signed, sig []byte) error {
        // Verify signature; return cryptoutil.ErrNotHandled if not your algorithm
        return nil
    })
}
```

## Development

```bash
make test          # Run all tests
make test-ecparams # Run ecparams plugin tests
make lint          # Run golangci-lint
make coverage      # Generate coverage report
make check-coverage # Check coverage thresholds
make setup         # Install tools + git hooks
```

## License

BSD 2-Clause. See [LICENSE.txt](LICENSE.txt).
