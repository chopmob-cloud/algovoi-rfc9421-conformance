// Go runner for the JSON Web Signature corpus (jws_v0).
//
// Independently reproduces every verdict in the frozen corpus, mirroring the
// Python reference runner (runners/python/verify_jws.py) and its decision surface
// (tools/oracle_jws.py) case for case. Parses each compact JWS, applies the JOSE
// security gates in order (reject alg:none, reject any crit, reject alg/key-type
// mismatch such as HS256 keyed with an RSA public key, select the key by kid when
// required), then verifies the RS256 / ES256 / EdDSA signature over
// ASCII(protected)+"."+ASCII(payload). Low-s is NOT enforced (plain JOSE permits a
// high-s ECDSA signature; low-s is a FAPI rule, not a jws_v0 rule). The gate logic
// is re-implemented here from the corpus, not imported, so a pass is genuine
// agreement.
//
// Self-contained: Go standard library only (crypto/rsa PKCS1v15, crypto/ecdsa +
// crypto/elliptic P256 with a hand on-curve check, crypto/ed25519, crypto/sha256,
// encoding/base64, encoding/json, math/big).
//
// Exit 0 iff every case matches. Corpus path: os.Args[1], else the repo corpus
// relative to this source file's directory (runners/go).
//
// Run:  cd runners/go && go run verify_jws_go.go [corpus.json]

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
)

const defaultCorpus = "../../corpus/jws_v0/jws_v0.json"

// RFC 7518 Section 3.1 alg -> the JWK kty a verifier must hold for it.
var algKty = map[string]string{"RS256": "RSA", "ES256": "EC", "EdDSA": "OKP", "HS256": "oct"}

// secp256r1 parameters for the explicit on-curve check.
var (
	p256P, _ = new(big.Int).SetString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
	p256A, _ = new(big.Int).SetString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16)
	p256B, _ = new(big.Int).SetString("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
)

var sections = []string{"jws_compact_parse", "jws_alg_none", "jws_alg_confusion",
	"jws_rs256_verify", "jws_es256_verify", "jws_eddsa_verify", "jws_crit", "jws_kid"}

// Strict base64url decode of one compact segment (unpadded, URL-safe alphabet).
func b64urlDecode(seg string) ([]byte, bool) {
	if b, err := base64.RawURLEncoding.DecodeString(seg); err == nil {
		return b, true
	}
	return nil, false
}

func b64urlBigInt(seg string) (*big.Int, bool) {
	b, ok := b64urlDecode(seg)
	if !ok {
		return nil, false
	}
	return new(big.Int).SetBytes(b), true
}

type parsed struct {
	header       map[string]interface{}
	sig          []byte
	signingInput []byte
}

func parseCompact(token string) (*parsed, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, false
	}
	headerBytes, ok := b64urlDecode(parts[0])
	if !ok {
		return nil, false
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil || header == nil {
		return nil, false
	}
	if _, has := header["alg"]; !has {
		return nil, false
	}
	if _, ok := b64urlDecode(parts[1]); !ok {
		return nil, false
	}
	sig, ok := b64urlDecode(parts[2])
	if !ok {
		return nil, false
	}
	return &parsed{header: header, sig: sig, signingInput: []byte(parts[0] + "." + parts[1])}, true
}

func jstr(m map[string]interface{}, k string) (string, bool) {
	v, ok := m[k].(string)
	return v, ok
}

func selectKey(header map[string]interface{}, keyList []map[string]interface{}, kids []string, selectByKid bool) (map[string]interface{}, bool) {
	if selectByKid {
		kid, ok := header["kid"].(string)
		if !ok {
			return nil, false
		}
		for i, k := range keyList {
			if kids[i] == kid {
				return k, true
			}
		}
		return nil, false
	}
	return keyList[0], true
}

func verifyRs256(jwk map[string]interface{}, signingInput, sig []byte) bool {
	nStr, ok1 := jstr(jwk, "n")
	eStr, ok2 := jstr(jwk, "e")
	if !ok1 || !ok2 {
		return false
	}
	n, ok := b64urlBigInt(nStr)
	if !ok {
		return false
	}
	eBytes, ok := b64urlDecode(eStr)
	if !ok {
		return false
	}
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() || e.Int64() > (1<<31-1) {
		return false
	}
	pub := &rsa.PublicKey{N: n, E: int(e.Int64())}
	hash := sha256.Sum256(signingInput)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], sig) == nil
}

func verifyEs256(jwk map[string]interface{}, signingInput, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	xStr, ok1 := jstr(jwk, "x")
	yStr, ok2 := jstr(jwk, "y")
	if !ok1 || !ok2 {
		return false
	}
	x, ok := b64urlBigInt(xStr)
	if !ok {
		return false
	}
	y, ok := b64urlBigInt(yStr)
	if !ok {
		return false
	}
	// Reject a public key whose point is not on secp256r1 before trusting it.
	lhs := new(big.Int).Mul(y, y)
	rhs := new(big.Int).Mul(x, x)
	rhs.Mul(rhs, x)
	ax := new(big.Int).Mul(p256A, x)
	rhs.Add(rhs, ax)
	rhs.Add(rhs, p256B)
	diff := new(big.Int).Sub(lhs, rhs)
	diff.Mod(diff, p256P)
	if diff.Sign() != 0 {
		return false
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	hash := sha256.Sum256(signingInput)
	return ecdsa.Verify(pub, hash[:], r, s)
}

func verifyEddsa(jwk map[string]interface{}, signingInput, sig []byte) bool {
	xStr, ok := jstr(jwk, "x")
	if !ok {
		return false
	}
	pk, ok := b64urlDecode(xStr)
	if !ok || len(pk) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pk), signingInput, sig)
}

func verdict(token string, keyList []map[string]interface{}, kids []string, selectByKid bool) bool {
	p, ok := parseCompact(token)
	if !ok {
		return false
	}
	alg, _ := p.header["alg"].(string)
	if alg == "none" {
		return false
	}
	if _, has := p.header["crit"]; has {
		return false
	}
	kty, known := algKty[alg]
	if !known {
		return false
	}
	jwk, ok := selectKey(p.header, keyList, kids, selectByKid)
	if !ok {
		return false
	}
	if jk, _ := jstr(jwk, "kty"); jk != kty {
		return false
	}
	switch alg {
	case "RS256":
		return verifyRs256(jwk, p.signingInput, p.sig)
	case "ES256":
		return verifyEs256(jwk, p.signingInput, p.sig)
	case "EdDSA":
		return verifyEddsa(jwk, p.signingInput, p.sig)
	}
	return false
}

func main() {
	path := defaultCorpus
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read corpus %s: %v\n", path, err)
		os.Exit(1)
	}
	var corpus map[string]interface{}
	if err := json.Unmarshal(data, &corpus); err != nil {
		fmt.Fprintf(os.Stderr, "cannot parse corpus %s: %v\n", path, err)
		os.Exit(1)
	}
	keys, _ := corpus["keys"].(map[string]interface{})

	total, matched := 0, 0
	for _, sec := range sections {
		arr, _ := corpus[sec].([]interface{})
		for _, e := range arr {
			c, _ := e.(map[string]interface{})
			note, _ := c["note"].(string)
			expect, _ := c["expect_valid"].(bool)
			token, _ := c["jws"].(string)
			verify, _ := c["verify"].(map[string]interface{})
			selectByKid, _ := verify["select_by_kid"].(bool)
			names, _ := verify["key_names"].([]interface{})
			var keyList []map[string]interface{}
			var kids []string
			for _, nm := range names {
				name, _ := nm.(string)
				jwk, _ := keys[name].(map[string]interface{})
				keyList = append(keyList, jwk)
				kid, _ := jwk["kid"].(string)
				kids = append(kids, kid)
			}
			accept := verdict(token, keyList, kids, selectByKid)
			total++
			if accept == expect {
				matched++
			} else {
				fmt.Printf("FAIL  [%s] %s\n", sec, note)
			}
		}
	}
	fmt.Printf("\ngo (jws): %d/%d cases matched\n", matched, total)
	if matched != total {
		os.Exit(1)
	}
}
