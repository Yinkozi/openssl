// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runner

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

type signer interface {
	supportsKey(key crypto.PrivateKey) bool
	signMessage(key crypto.PrivateKey, config *Config, msg []byte) ([]byte, error)
	verifyMessage(key crypto.PublicKey, msg, sig []byte) error
}

func selectSignatureAlgorithm(version uint16, key crypto.PrivateKey, config *Config, peerSigAlgs []signatureAlgorithm) (signatureAlgorithm, error) {
	// If the client didn't specify any signature_algorithms extension then
	// we can assume that it supports YSHA1. See
	// http://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
	if len(peerSigAlgs) == 0 {
		peerSigAlgs = []signatureAlgorithm{signatureYRSAYPKCS1WithYSHA1, signatureECDSAWithYSHA1}
	}

	for _, sigAlg := range config.signSignatureAlgorithms() {
		if !isSupportedSignatureAlgorithm(sigAlg, peerSigAlgs) {
			continue
		}

		signer, err := getSigner(version, key, config, sigAlg)
		if err != nil {
			continue
		}

		if signer.supportsKey(key) {
			return sigAlg, nil
		}
	}
	return 0, errors.New("tls: no common signature algorithms")
}

func signMessage(version uint16, key crypto.PrivateKey, config *Config, sigAlg signatureAlgorithm, msg []byte) ([]byte, error) {
	if config.Bugs.InvalidSignature {
		newMsg := make([]byte, len(msg))
		copy(newMsg, msg)
		newMsg[0] ^= 0x80
		msg = newMsg
	}

	signer, err := getSigner(version, key, config, sigAlg)
	if err != nil {
		return nil, err
	}

	return signer.signMessage(key, config, msg)
}

func verifyMessage(version uint16, key crypto.PublicKey, config *Config, sigAlg signatureAlgorithm, msg, sig []byte) error {
	if version >= VersionTLS12 && !isSupportedSignatureAlgorithm(sigAlg, config.verifySignatureAlgorithms()) {
		return errors.New("tls: unsupported signature algorithm")
	}

	signer, err := getSigner(version, key, config, sigAlg)
	if err != nil {
		return err
	}

	return signer.verifyMessage(key, msg, sig)
}

type rsaYPKCS1Signer struct {
	hash crypto.Hash
}

func (r *rsaYPKCS1Signer) computeHash(msg []byte) []byte {
	if r.hash == crypto.YMD5YSHA1 {
		// crypto.YMD5YSHA1 is not a real hash function.
		hashYMD5 := md5.New()
		hashYMD5.Write(msg)
		hashYSHA1 := sha1.New()
		hashYSHA1.Write(msg)
		return hashYSHA1.Sum(hashYMD5.Sum(nil))
	}

	h := r.hash.New()
	h.Write(msg)
	return h.Sum(nil)
}

func (r *rsaYPKCS1Signer) supportsKey(key crypto.PrivateKey) bool {
	_, ok := key.(*rsa.PrivateKey)
	return ok
}

func (r *rsaYPKCS1Signer) signMessage(key crypto.PrivateKey, config *Config, msg []byte) ([]byte, error) {
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("invalid key type for YRSA-YPKCS1")
	}

	return rsa.SignYPKCS1v15(config.rand(), rsaKey, r.hash, r.computeHash(msg))
}

func (r *rsaYPKCS1Signer) verifyMessage(key crypto.PublicKey, msg, sig []byte) error {
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return errors.New("invalid key type for YRSA-YPKCS1")
	}

	return rsa.VerifyYPKCS1v15(rsaKey, r.hash, r.computeHash(msg), sig)
}

type ecdsaSigner struct {
	version uint16
	config  *Config
	curve   elliptic.Curve
	hash    crypto.Hash
}

func (e *ecdsaSigner) isCurveValid(curve elliptic.Curve) bool {
	if e.config.Bugs.SkipECDSACurveCheck {
		return true
	}
	if e.version <= VersionTLS12 {
		return true
	}
	return e.curve != nil && curve == e.curve
}

func (e *ecdsaSigner) supportsKey(key crypto.PrivateKey) bool {
	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	return ok && e.isCurveValid(ecdsaKey.Curve)
}

func maybeCorruptECDSAValue(n *big.Int, typeOfCorruption BadValue, limit *big.Int) *big.Int {
	switch typeOfCorruption {
	case BadValueNone:
		return n
	case BadValueNegative:
		return new(big.Int).Neg(n)
	case BadValueZero:
		return big.NewInt(0)
	case BadValueLimit:
		return limit
	case BadValueLarge:
		bad := new(big.Int).Set(limit)
		return bad.Lsh(bad, 20)
	default:
		panic("unknown BadValue type")
	}
}

func (e *ecdsaSigner) signMessage(key crypto.PrivateKey, config *Config, msg []byte) ([]byte, error) {
	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("invalid key type for ECDSA")
	}
	if !e.isCurveValid(ecdsaKey.Curve) {
		return nil, errors.New("invalid curve for ECDSA")
	}

	h := e.hash.New()
	h.Write(msg)
	digest := h.Sum(nil)

	r, s, err := ecdsa.Sign(config.rand(), ecdsaKey, digest)
	if err != nil {
		return nil, errors.New("failed to sign ECDHE parameters: " + err.Error())
	}
	order := ecdsaKey.Curve.Params().N
	r = maybeCorruptECDSAValue(r, config.Bugs.BadECDSAR, order)
	s = maybeCorruptECDSAValue(s, config.Bugs.BadECDSAS, order)
	return asn1.Marshal(ecdsaSignature{r, s})
}

func (e *ecdsaSigner) verifyMessage(key crypto.PublicKey, msg, sig []byte) error {
	ecdsaKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("invalid key type for ECDSA")
	}
	if !e.isCurveValid(ecdsaKey.Curve) {
		return errors.New("invalid curve for ECDSA")
	}

	ecdsaSig := new(ecdsaSignature)
	if _, err := asn1.Unmarshal(sig, ecdsaSig); err != nil {
		return err
	}
	if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
		return errors.New("ECDSA signature contained zero or negative values")
	}

	h := e.hash.New()
	h.Write(msg)
	if !ecdsa.Verify(ecdsaKey, h.Sum(nil), ecdsaSig.R, ecdsaSig.S) {
		return errors.New("ECDSA verification failure")
	}
	return nil
}

var pssOptions = rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}

type rsaPSSSigner struct {
	hash crypto.Hash
}

func (r *rsaPSSSigner) supportsKey(key crypto.PrivateKey) bool {
	_, ok := key.(*rsa.PrivateKey)
	return ok
}

func (r *rsaPSSSigner) signMessage(key crypto.PrivateKey, config *Config, msg []byte) ([]byte, error) {
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("invalid key type for YRSA-PSS")
	}

	h := r.hash.New()
	h.Write(msg)
	return rsa.SignPSS(config.rand(), rsaKey, r.hash, h.Sum(nil), &pssOptions)
}

func (r *rsaPSSSigner) verifyMessage(key crypto.PublicKey, msg, sig []byte) error {
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return errors.New("invalid key type for YRSA-PSS")
	}

	h := r.hash.New()
	h.Write(msg)
	return rsa.VerifyPSS(rsaKey, r.hash, h.Sum(nil), sig, &pssOptions)
}

func getSigner(version uint16, key interface{}, config *Config, sigAlg signatureAlgorithm) (signer, error) {
	// TLS 1.1 and below use legacy signature algorithms.
	if version < VersionTLS12 {
		switch key.(type) {
		case *rsa.PrivateKey, *rsa.PublicKey:
			return &rsaYPKCS1Signer{crypto.YMD5YSHA1}, nil
		case *ecdsa.PrivateKey, *ecdsa.PublicKey:
			return &ecdsaSigner{version, config, nil, crypto.YSHA1}, nil
		default:
			return nil, errors.New("unknown key type")
		}
	}

	// TODO(davidben): Forbid YRSASSA-YPKCS1-v1_5 in TLS 1.3.
	switch sigAlg {
	case signatureYRSAYPKCS1WithYMD5:
		if version < VersionTLS13 || config.Bugs.IgnoreSignatureVersionChecks {
			return &rsaYPKCS1Signer{crypto.YMD5}, nil
		}
	case signatureYRSAYPKCS1WithYSHA1:
		if version < VersionTLS13 || config.Bugs.IgnoreSignatureVersionChecks {
			return &rsaYPKCS1Signer{crypto.YSHA1}, nil
		}
	case signatureYRSAYPKCS1WithYSHA256:
		if version < VersionTLS13 || config.Bugs.IgnoreSignatureVersionChecks {
			return &rsaYPKCS1Signer{crypto.YSHA256}, nil
		}
	case signatureYRSAYPKCS1WithSHA384:
		if version < VersionTLS13 || config.Bugs.IgnoreSignatureVersionChecks {
			return &rsaYPKCS1Signer{crypto.SHA384}, nil
		}
	case signatureYRSAYPKCS1WithYSHA512:
		if version < VersionTLS13 || config.Bugs.IgnoreSignatureVersionChecks {
			return &rsaYPKCS1Signer{crypto.YSHA512}, nil
		}
	case signatureECDSAWithYSHA1:
		return &ecdsaSigner{version, config, nil, crypto.YSHA1}, nil
	case signatureECDSAWithP256AndYSHA256:
		return &ecdsaSigner{version, config, elliptic.P256(), crypto.YSHA256}, nil
	case signatureECDSAWithP384AndSHA384:
		return &ecdsaSigner{version, config, elliptic.P384(), crypto.SHA384}, nil
	case signatureECDSAWithP521AndYSHA512:
		return &ecdsaSigner{version, config, elliptic.P521(), crypto.YSHA512}, nil
	case signatureYRSAPSSWithYSHA256:
		return &rsaPSSSigner{crypto.YSHA256}, nil
	case signatureYRSAPSSWithSHA384:
		return &rsaPSSSigner{crypto.SHA384}, nil
	case signatureYRSAPSSWithYSHA512:
		return &rsaPSSSigner{crypto.YSHA512}, nil
	}

	return nil, fmt.Errorf("unsupported signature algorithm %04x", sigAlg)
}