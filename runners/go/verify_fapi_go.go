// Go reference runner for the FAPI 2.0 Message Signing profile corpus
// (fapi_messagesigning_v0).
//
// Independently reproduces every verdict in the frozen corpus. The signing base
// (RFC 9421 Section 2.5), the PROFILE rules (mandated coverage, Content-Digest
// body binding, algorithm restriction) and the PS256/ES256 crypto are
// re-implemented here from the corpus `policy` block, NOT imported from the
// generator's oracle, so a runner passing is genuine agreement rather than an
// echo. This mirrors the Python reference runner (runners/python/verify_fapi.py)
// case for case.
//
// Self-contained: Go standard library only (encoding/json with json.Number for
// strict integer checks, crypto/rsa PSS, crypto/ecdsa + crypto/elliptic P256,
// crypto/sha256, crypto/sha512, crypto/x509 for the RSA SPKI DER,
// encoding/base64, encoding/hex).
//
// Exit 0 iff every case matches. Corpus path: os.Args[1], else the repo corpus
// relative to this source file's directory (runners/go).
//
// Run:  cd runners/go && go run verify_fapi_go.go [corpus.json]

package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
)

// Default assumes invocation from the runners/go directory (as the sibling
// runners are invoked); override with an explicit path argument.
const defaultCorpus = "../../corpus/fapi_messagesigning_v0/fapi_messagesigning_v0.json"

// ---- generic JSON helpers (decoded with UseNumber for exact int checks) ----

func asString(v interface{}) (string, bool) { s, ok := v.(string); return s, ok }

func asMap(v interface{}) (map[string]interface{}, bool) {
	m, ok := v.(map[string]interface{})
	return m, ok
}

func asList(v interface{}) []interface{} {
	if s, ok := v.([]interface{}); ok {
		return s
	}
	return nil
}

func strSlice(v interface{}) []string {
	out := []string{}
	for _, e := range asList(v) {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// numString returns the verbatim string form of a JSON integer (e.g. 200 ->
// "200"), mirroring Python's str(status). Non-integer numbers and non-numbers
// yield (,, false).
func numString(v interface{}) (string, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return "", false
	}
	if _, err := n.Int64(); err != nil {
		return "", false
	}
	return n.String(), true
}

func b64decode(s string) ([]byte, bool) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, true
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, true
	}
	return nil, false
}

func lowerSet(items []string) map[string]bool {
	m := map[string]bool{}
	for _, it := range items {
		m[strings.ToLower(it)] = true
	}
	return m
}

// ---- profile rules (re-derived from policy, mirroring verify_fapi.py) ----

// buildSigningBase hand-builds the RFC 9421 Section 2.5 signing base by direct
// concatenation. Returns (base, true) when buildable, ("", false) when a covered
// component's value is missing (build impossible). mode is always "rfc9421" in
// this corpus, so "@signature-params" is always appended.
func buildSigningBase(in map[string]interface{}, paramsRaw string) (string, bool) {
	var lines []string
	for _, comp := range strSlice(in["covered_components"]) {
		name := strings.ToLower(comp)
		var val string
		switch name {
		case "@method":
			v, ok := asString(in["method"])
			if !ok {
				return "", false
			}
			val = v
		case "@target-uri":
			v, ok := asString(in["target_uri"])
			if !ok {
				return "", false
			}
			val = v
		case "@status":
			v, ok := numString(in["status"])
			if !ok {
				return "", false
			}
			val = v
		case "@authority":
			v, ok := asString(in["authority"])
			if !ok {
				return "", false
			}
			val = v
		case "@path":
			v, ok := asString(in["path"])
			if !ok {
				return "", false
			}
			val = v
		default:
			headers, ok := asMap(in["headers"])
			if !ok {
				return "", false
			}
			hv, ok := headers[name]
			if !ok {
				return "", false
			}
			s, ok := hv.(string)
			if !ok {
				return "", false
			}
			val = s
		}
		lines = append(lines, "\""+name+"\": "+val)
	}
	lines = append(lines, "\"@signature-params\": "+paramsRaw)
	return strings.Join(lines, "\n"), true
}

// coverageOK: accept iff every required component (lowercased) is present in the
// covered set (lowercased).
func coverageOK(messageType string, covered []string, policy map[string]interface{}) bool {
	key := "required_covered_response"
	if messageType == "request" {
		key = "required_covered_request"
	}
	have := lowerSet(covered)
	for _, r := range strSlice(policy[key]) {
		if !have[strings.ToLower(r)] {
			return false
		}
	}
	return true
}

// contentDigestOK: reject if content-digest not covered; the header algorithm
// (before the first "=") must be an allowed digest algorithm; and the header
// must equal <alg>=:<base64(digest of body)>:.
func contentDigestOK(bodyB64, header string, covered []string, policy map[string]interface{}) bool {
	if !lowerSet(covered)["content-digest"] {
		return false
	}
	parts := strings.SplitN(header, "=", 2)
	if len(parts) != 2 {
		return false
	}
	algorithm := strings.ToLower(strings.TrimSpace(parts[0]))
	if !lowerSet(strSlice(policy["content_digest_algorithms"]))[algorithm] {
		return false
	}
	body, ok := b64decode(bodyB64)
	if !ok {
		return false
	}
	var digest []byte
	switch algorithm {
	case "sha-256":
		h := sha256.Sum256(body)
		digest = h[:]
	case "sha-512":
		h := sha512.Sum512(body)
		digest = h[:]
	default:
		return false
	}
	expect := algorithm + "=:" + base64.StdEncoding.EncodeToString(digest) + ":"
	return strings.TrimSpace(header) == expect
}

// ps256OK: verify an RSASSA-PSS/SHA-256 (salt 32) signature over base using the
// public key in the PKIX/SPKI DER.
func ps256OK(base, sig, spkiDER []byte) bool {
	pubAny, err := x509.ParsePKIXPublicKey(spkiDER)
	if err != nil {
		return false
	}
	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return false
	}
	hash := sha256.Sum256(base)
	err = rsa.VerifyPSS(pub, crypto.SHA256, hash[:], sig, &rsa.PSSOptions{SaltLength: 32})
	return err == nil
}

// es256OK: verify an ECDSA/P-256/SHA-256 signature given a 64-byte raw r||s.
// Under require_low_s a signature with s > n/2 is rejected (malleability).
func es256OK(base, sigRaw, pubUncompressed []byte, requireLowS bool, policy map[string]interface{}) bool {
	if len(sigRaw) != 64 {
		return false
	}
	r := new(big.Int).SetBytes(sigRaw[:32])
	s := new(big.Int).SetBytes(sigRaw[32:])

	curve := elliptic.P256()
	n := curve.Params().N
	if pn, ok := policy["p256_n"].(string); ok {
		if parsed, good := new(big.Int).SetString(strings.TrimSpace(pn), 10); good {
			n = parsed
		}
	}
	if requireLowS {
		half := new(big.Int).Rsh(n, 1) // n / 2
		if s.Cmp(half) > 0 {
			return false
		}
	}

	x, y := elliptic.Unmarshal(curve, pubUncompressed)
	if x == nil {
		return false
	}
	pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	return ecdsa.Verify(pub, sha256Sum(base), r, s)
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// ---- driver ----

type result struct {
	section string
	note    string
	matched bool
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
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var corpus map[string]interface{}
	if err := dec.Decode(&corpus); err != nil {
		fmt.Fprintf(os.Stderr, "cannot parse corpus %s: %v\n", path, err)
		os.Exit(1)
	}

	policy, _ := asMap(corpus["policy"])

	var results []result
	add := func(section, note string, matched bool) {
		results = append(results, result{section, note, matched})
	}

	// 1. fapi_signing_base
	for _, e := range asList(corpus["fapi_signing_base"]) {
		c, _ := asMap(e)
		note, _ := c["note"].(string)
		okFlag, _ := c["ok"].(bool)
		in, _ := asMap(c["in"])
		paramsRaw, _ := c["signature_params_raw"].(string)
		b64, _ := c["signing_base_b64"].(string)
		decoded, dok := b64decode(b64)
		built, buildable := buildSigningBase(in, paramsRaw)
		var matched bool
		if !buildable {
			matched = !okFlag
		} else {
			matched = okFlag && dok && built == string(decoded)
		}
		add("fapi_signing_base", note, matched)
	}

	// 2. fapi_required_coverage
	for _, e := range asList(corpus["fapi_required_coverage"]) {
		c, _ := asMap(e)
		note, _ := c["note"].(string)
		expect, _ := c["expect_accept"].(bool)
		mt, _ := c["message_type"].(string)
		got := coverageOK(mt, strSlice(c["covered_components"]), policy)
		add("fapi_required_coverage", note, got == expect)
	}

	// 3. fapi_content_digest
	for _, e := range asList(corpus["fapi_content_digest"]) {
		c, _ := asMap(e)
		note, _ := c["note"].(string)
		expect, _ := c["expect_accept"].(bool)
		bodyB64, _ := c["body_b64"].(string)
		header, _ := c["content_digest"].(string)
		got := contentDigestOK(bodyB64, header, strSlice(c["covered_components"]), policy)
		add("fapi_content_digest", note, got == expect)
	}

	// 4. fapi_alg
	for _, e := range asList(corpus["fapi_alg"]) {
		c, _ := asMap(e)
		note, _ := c["note"].(string)
		expect, _ := c["expect_accept"].(bool)
		alg, _ := c["alg"].(string)
		got := lowerSet(strSlice(policy["allowed_algs"]))[strings.ToLower(alg)]
		add("fapi_alg", note, got == expect)
	}

	// 5. fapi_ps256_verify
	for _, e := range asList(corpus["fapi_ps256_verify"]) {
		c, _ := asMap(e)
		note, _ := c["note"].(string)
		expect, _ := c["expect_valid"].(bool)
		base, bok := b64decode(c["signing_base_b64"].(string))
		sigHex, _ := c["sig_hex"].(string)
		spkiHex, _ := c["pub_spki_hex"].(string)
		sig, e1 := hex.DecodeString(sigHex)
		spki, e2 := hex.DecodeString(spkiHex)
		valid := bok && e1 == nil && e2 == nil && ps256OK(base, sig, spki)
		add("fapi_ps256_verify", note, valid == expect)
	}

	// 6. fapi_es256_verify
	for _, e := range asList(corpus["fapi_es256_verify"]) {
		c, _ := asMap(e)
		note, _ := c["note"].(string)
		expect, _ := c["expect_valid"].(bool)
		base, bok := b64decode(c["signing_base_b64"].(string))
		sigHex, _ := c["sig_raw_hex"].(string)
		pubHex, _ := c["pub_uncompressed_hex"].(string)
		requireLowS, _ := c["require_low_s"].(bool)
		sigRaw, e1 := hex.DecodeString(sigHex)
		pub, e2 := hex.DecodeString(pubHex)
		valid := bok && e1 == nil && e2 == nil && es256OK(base, sigRaw, pub, requireLowS, policy)
		add("fapi_es256_verify", note, valid == expect)
	}

	matched := 0
	for _, r := range results {
		if r.matched {
			matched++
		} else {
			fmt.Printf("FAIL  [%s] %s\n", r.section, r.note)
		}
	}
	total := len(results)
	fmt.Printf("\ngo (fapi): %d/%d cases matched\n", matched, total)
	if matched != total {
		os.Exit(1)
	}
}
