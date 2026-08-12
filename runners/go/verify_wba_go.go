// Go reference runner for the Web Bot Auth profile corpus (webbotauth_v0).
//
// Independently reproduces every verdict in the frozen corpus. The PROFILE rules
// (signing base, coverage completeness, freshness window, directory keyid
// resolution, Signature-Agent SSRF, Ed25519 verification) are re-implemented here
// from the corpus `policy` block, NOT imported from the generator's oracle, so a
// runner passing is genuine agreement rather than an echo. This mirrors the
// Python reference runner (runners/python/verify_wba.py) and the independent KAT
// gate (tools/check_kat_wba.py) case for case.
//
// Self-contained: Go standard library only (encoding/json, crypto/ed25519,
// encoding/base64, encoding/hex, net/netip, net/url).
//
// Exit 0 iff every case matches. Corpus path: os.Args[1], else the repo corpus
// relative to this source file's directory (runners/go).
//
// Run:  cd runners/go && go run verify_wba_go.go [corpus.json]

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strings"
)

// Default assumes invocation from the runners/go directory (as the sibling
// runners are invoked); override with an explicit path argument.
const defaultCorpus = "../../corpus/webbotauth_v0/webbotauth_v0.json"

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

// asInt returns (n, true) only when v is a JSON integer, mirroring Python's
// isinstance(x, int): floats (e.g. 15.0) and non-numbers are rejected.
func asInt(v interface{}) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	if err != nil {
		return 0, false
	}
	return i, true
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

func b64decode(s string) ([]byte, bool) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, true
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, true
	}
	return nil, false
}

// ---- profile rules (re-derived from policy, per RULES 1-6) ----

// buildSigningBase hand-builds the RFC 9421 Section 2.5 signing base by direct
// concatenation. Returns (base, true) when buildable, ("", false) when a covered
// component's value is missing (build impossible).
func buildSigningBase(in map[string]interface{}, paramsRaw string) (string, bool) {
	var lines []string
	for _, comp := range strSlice(in["covered_components"]) {
		name := strings.ToLower(comp)
		var val string
		switch name {
		case "@authority":
			v, ok := asString(in["authority"])
			if !ok {
				return "", false
			}
			val = v
		case "@method":
			v, ok := asString(in["method"])
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

func coverageOK(covered, required []string) bool {
	have := map[string]bool{}
	for _, c := range covered {
		have[strings.ToLower(c)] = true
	}
	for _, r := range required {
		if !have[strings.ToLower(r)] {
			return false
		}
	}
	return true
}

func freshnessOK(c map[string]interface{}, skew int64) bool {
	created, ok1 := asInt(c["created"])
	expires, ok2 := asInt(c["expires"])
	now, ok3 := asInt(c["now"])
	if !(ok1 && ok2 && ok3) {
		return false
	}
	if expires <= created {
		return false
	}
	return (created-skew) <= now && now < expires
}

func directoryOK(dir []interface{}, keyid string) bool {
	for _, e := range dir {
		j, ok := asMap(e)
		if !ok {
			continue
		}
		kid, _ := j["kid"].(string)
		if kid == keyid {
			kty, _ := j["kty"].(string)
			crv, _ := j["crv"].(string)
			x, _ := j["x"].(string)
			return kty == "OKP" && crv == "Ed25519" && x != ""
		}
	}
	return false
}

func ssrfOK(rawURL, resolvedIP string, requireHTTPS bool, deniedCIDRs []string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if requireHTTPS && u.Scheme != "https" {
		return false
	}
	if u.User != nil { // userinfo present ("user@host")
		return false
	}
	host := u.Hostname() // strips [] from IPv6 literals
	if host == "" {
		return false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		// Not an IP literal: fall back to the resolved address.
		if resolvedIP == "" {
			return false
		}
		addr, err = netip.ParseAddr(resolvedIP)
		if err != nil {
			return false
		}
	}
	for _, cidr := range deniedCIDRs {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		// Same IP version only, mirroring the Python reference.
		if p.Addr().Is4() == addr.Is4() && p.Contains(addr) {
			return false
		}
	}
	return true
}

func ed25519OK(base []byte, sigHex, pkHex string) bool {
	pub, err := hex.DecodeString(pkHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), base, sig)
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
	required := strSlice(policy["required_covered_components"])
	skew, _ := asInt(policy["clock_skew_seconds"]) // 0 if absent
	ssrf, _ := asMap(policy["ssrf"])
	requireHTTPS := true
	if v, ok := ssrf["require_https"].(bool); ok {
		requireHTTPS = v
	}
	deniedCIDRs := strSlice(ssrf["denied_cidrs"])

	var results []result
	add := func(section, note string, matched bool) {
		results = append(results, result{section, note, matched})
	}

	// 1. wba_signing_base
	for _, e := range asList(corpus["wba_signing_base"]) {
		c, _ := asMap(e)
		note, _ := c["note"].(string)
		okFlag, _ := c["ok"].(bool)
		in, _ := asMap(c["in"])
		paramsRaw, _ := c["signature_params_raw"].(string)
		decoded, dok := b64decode(c["signing_base_b64"].(string))
		built, buildable := buildSigningBase(in, paramsRaw)
		var matched bool
		if !buildable {
			matched = !okFlag
		} else {
			matched = okFlag && dok && built == string(decoded)
		}
		add("wba_signing_base", note, matched)
	}

	// 2. wba_coverage
	for _, e := range asList(corpus["wba_coverage"]) {
		c, _ := asMap(e)
		note, _ := c["note"].(string)
		expect, _ := c["expect_accept"].(bool)
		got := coverageOK(strSlice(c["covered_components"]), required)
		add("wba_coverage", note, got == expect)
	}

	// 3. wba_freshness
	for _, e := range asList(corpus["wba_freshness"]) {
		c, _ := asMap(e)
		note, _ := c["note"].(string)
		expect, _ := c["expect_accept"].(bool)
		got := freshnessOK(c, skew)
		add("wba_freshness", note, got == expect)
	}

	// 4. wba_directory
	for _, e := range asList(corpus["wba_directory"]) {
		c, _ := asMap(e)
		note, _ := c["note"].(string)
		expect, _ := c["expect_accept"].(bool)
		keyid, _ := c["keyid"].(string)
		got := directoryOK(asList(c["directory"]), keyid)
		add("wba_directory", note, got == expect)
	}

	// 5. wba_directory_ssrf
	for _, e := range asList(corpus["wba_directory_ssrf"]) {
		c, _ := asMap(e)
		note, _ := c["note"].(string)
		expect, _ := c["expect_fetch_allowed"].(bool)
		rawURL, _ := c["signature_agent_url"].(string)
		resolvedIP, _ := c["resolved_ip"].(string)
		got := ssrfOK(rawURL, resolvedIP, requireHTTPS, deniedCIDRs)
		add("wba_directory_ssrf", note, got == expect)
	}

	// 6. wba_ed25519_verify
	for _, e := range asList(corpus["wba_ed25519_verify"]) {
		c, _ := asMap(e)
		note, _ := c["note"].(string)
		expect, _ := c["expect_valid"].(bool)
		base, ok := b64decode(c["signing_base_b64"].(string))
		sigHex, _ := c["sig_hex"].(string)
		pkHex, _ := c["pk_hex"].(string)
		valid := ok && ed25519OK(base, sigHex, pkHex)
		add("wba_ed25519_verify", note, valid == expect)
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
	fmt.Printf("\ngo (wba): %d/%d cases matched\n", matched, total)
	if matched != total {
		os.Exit(1)
	}
}
