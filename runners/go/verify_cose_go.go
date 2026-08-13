// Go runner for the COSE_Sign1 corpus (cose_v0).
//
// Independently reproduces every verdict in the frozen corpus, mirroring the
// Python reference runner (runners/python/verify_cose.py) and its decision surface
// (tools/oracle_cose.py) case for case. Parses each COSE_Sign1 (CBOR array of 4,
// tagged 18 or untagged), applies the COSE security gates in order (protected
// header deterministically encoded per RFC 8949 Section 4.2, alg (label 1) present
// in the protected header, an unknown crit (label 2) label rejected, alg/key-type
// match), builds the Sig_structure ["Signature1", protected, h'', payload] in
// deterministic CBOR and verifies the ES256 / EdDSA / PS256 signature. For the
// deterministic-CBOR section it decides whether the datum is RFC 8949 Section 4.2
// canonical. Low-s is NOT enforced (a COSE base rule, not a FAPI rule).
//
// The CBOR codec is hand-rolled (a minimal decoder plus an RFC 8949 Section 4.2
// canonical encoder) so the deterministic judgement and the Sig_structure bytes are
// byte-identical to the frozen corpus, independent of any CBOR library's default
// map-key ordering (bytewise-lexicographic, not length-first).
//
// Self-contained: Go standard library only (crypto/rsa PSS, crypto/ecdsa +
// crypto/elliptic P256 with a hand on-curve check, crypto/ed25519, crypto/sha256).
//
// Run:  cd runners/go && go run verify_cose_go.go [corpus.json]

package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sort"
)

const defaultCorpus = "../../corpus/cose_v0/cose_v0.json"

const coseSign1Tag = 18

var algKty = map[int64]string{-7: "EC2", -8: "OKP", -37: "RSA"}
var knownLabels = map[int64]bool{1: true, 2: true, 3: true, 4: true, 5: true}

var (
	p256P, _ = new(big.Int).SetString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
	p256A, _ = new(big.Int).SetString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16)
	p256B, _ = new(big.Int).SetString("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
)

var sections = []string{"cose_sig_structure", "cose_deterministic_cbor", "cose_protected_header",
	"cose_es256_verify", "cose_eddsa_verify", "cose_ps256_verify", "cose_crit"}

// ---------------------------------------------------------------------------
// Minimal CBOR decode (permissive) + RFC 8949 Section 4.2 canonical encode
// ---------------------------------------------------------------------------

const (
	tInt = iota
	tBytes
	tText
	tArray
	tMap
	tNull
	tTag
	tBool
)

type cval struct {
	t   int
	i   int64
	b   []byte
	s   string
	arr []cval
	m   [][2]cval
	tag uint64
}

func decode(buf []byte, pos int) (cval, int, error) {
	if pos >= len(buf) {
		return cval{}, 0, errors.New("truncated")
	}
	ib := buf[pos]
	pos++
	major := int(ib >> 5)
	ai := ib & 0x1f
	var arg uint64
	switch {
	case ai < 24:
		arg = uint64(ai)
	case ai == 24:
		if pos+1 > len(buf) {
			return cval{}, 0, errors.New("truncated arg")
		}
		arg = uint64(buf[pos])
		pos++
	case ai == 25:
		if pos+2 > len(buf) {
			return cval{}, 0, errors.New("truncated arg")
		}
		arg = uint64(buf[pos])<<8 | uint64(buf[pos+1])
		pos += 2
	case ai == 26:
		if pos+4 > len(buf) {
			return cval{}, 0, errors.New("truncated arg")
		}
		for i := 0; i < 4; i++ {
			arg = arg<<8 | uint64(buf[pos+i])
		}
		pos += 4
	case ai == 27:
		if pos+8 > len(buf) {
			return cval{}, 0, errors.New("truncated arg")
		}
		for i := 0; i < 8; i++ {
			arg = arg<<8 | uint64(buf[pos+i])
		}
		pos += 8
	case ai == 31:
		if major < 2 || major > 5 {
			return cval{}, 0, errors.New("indefinite not allowed here")
		}
		return decodeIndefinite(buf, pos, major)
	default:
		return cval{}, 0, errors.New("reserved additional info")
	}

	switch major {
	case 0:
		return cval{t: tInt, i: int64(arg)}, pos, nil
	case 1:
		return cval{t: tInt, i: -1 - int64(arg)}, pos, nil
	case 2:
		if pos+int(arg) > len(buf) {
			return cval{}, 0, errors.New("truncated bstr")
		}
		v := append([]byte(nil), buf[pos:pos+int(arg)]...)
		return cval{t: tBytes, b: v}, pos + int(arg), nil
	case 3:
		if pos+int(arg) > len(buf) {
			return cval{}, 0, errors.New("truncated tstr")
		}
		return cval{t: tText, s: string(buf[pos : pos+int(arg)])}, pos + int(arg), nil
	case 4:
		items := make([]cval, 0, arg)
		for i := uint64(0); i < arg; i++ {
			v, np, err := decode(buf, pos)
			if err != nil {
				return cval{}, 0, err
			}
			items = append(items, v)
			pos = np
		}
		return cval{t: tArray, arr: items}, pos, nil
	case 5:
		pairs := make([][2]cval, 0, arg)
		for i := uint64(0); i < arg; i++ {
			k, p1, err := decode(buf, pos)
			if err != nil {
				return cval{}, 0, err
			}
			v, p2, err := decode(buf, p1)
			if err != nil {
				return cval{}, 0, err
			}
			pairs = append(pairs, [2]cval{k, v})
			pos = p2
		}
		return cval{t: tMap, m: pairs}, pos, nil
	case 6:
		inner, np, err := decode(buf, pos)
		if err != nil {
			return cval{}, 0, err
		}
		return cval{t: tTag, tag: arg, arr: []cval{inner}}, np, nil
	case 7:
		switch ai {
		case 22:
			return cval{t: tNull}, pos, nil
		case 20:
			return cval{t: tBool, i: 0}, pos, nil
		case 21:
			return cval{t: tBool, i: 1}, pos, nil
		}
		return cval{}, 0, errors.New("unsupported simple/float")
	}
	return cval{}, 0, errors.New("bad major")
}

func decodeIndefinite(buf []byte, pos, major int) (cval, int, error) {
	if major == 2 || major == 3 {
		var acc []byte
		var sb bytes.Buffer
		for {
			if pos >= len(buf) {
				return cval{}, 0, errors.New("truncated indefinite")
			}
			if buf[pos] == 0xff {
				pos++
				break
			}
			chunk, np, err := decode(buf, pos)
			if err != nil {
				return cval{}, 0, err
			}
			if major == 2 {
				if chunk.t != tBytes {
					return cval{}, 0, errors.New("bad chunk")
				}
				acc = append(acc, chunk.b...)
			} else {
				if chunk.t != tText {
					return cval{}, 0, errors.New("bad chunk")
				}
				sb.WriteString(chunk.s)
			}
			pos = np
		}
		if major == 2 {
			return cval{t: tBytes, b: acc}, pos, nil
		}
		return cval{t: tText, s: sb.String()}, pos, nil
	}
	if major == 4 {
		items := []cval{}
		for {
			if pos >= len(buf) {
				return cval{}, 0, errors.New("truncated indefinite")
			}
			if buf[pos] == 0xff {
				pos++
				break
			}
			v, np, err := decode(buf, pos)
			if err != nil {
				return cval{}, 0, err
			}
			items = append(items, v)
			pos = np
		}
		return cval{t: tArray, arr: items}, pos, nil
	}
	pairs := [][2]cval{}
	for {
		if pos >= len(buf) {
			return cval{}, 0, errors.New("truncated indefinite")
		}
		if buf[pos] == 0xff {
			pos++
			break
		}
		k, p1, err := decode(buf, pos)
		if err != nil {
			return cval{}, 0, err
		}
		v, p2, err := decode(buf, p1)
		if err != nil {
			return cval{}, 0, err
		}
		pairs = append(pairs, [2]cval{k, v})
		pos = p2
	}
	return cval{t: tMap, m: pairs}, pos, nil
}

func head(major int, n uint64) []byte {
	base := byte(major << 5)
	switch {
	case n < 24:
		return []byte{base | byte(n)}
	case n < 0x100:
		return []byte{base | 24, byte(n)}
	case n < 0x10000:
		return []byte{base | 25, byte(n >> 8), byte(n)}
	case n < 0x100000000:
		return []byte{base | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	default:
		out := make([]byte, 9)
		out[0] = base | 27
		for i := 0; i < 8; i++ {
			out[8-i] = byte(n >> (8 * i))
		}
		return out
	}
}

func encode(v cval) ([]byte, error) {
	switch v.t {
	case tInt:
		if v.i >= 0 {
			return head(0, uint64(v.i)), nil
		}
		return head(1, uint64(-1-v.i)), nil
	case tBytes:
		return append(head(2, uint64(len(v.b))), v.b...), nil
	case tText:
		return append(head(3, uint64(len(v.s))), []byte(v.s)...), nil
	case tArray:
		out := head(4, uint64(len(v.arr)))
		for _, it := range v.arr {
			e, err := encode(it)
			if err != nil {
				return nil, err
			}
			out = append(out, e...)
		}
		return out, nil
	case tMap:
		type kv struct{ k, val []byte }
		pairs := make([]kv, 0, len(v.m))
		for _, p := range v.m {
			ke, err := encode(p[0])
			if err != nil {
				return nil, err
			}
			ve, err := encode(p[1])
			if err != nil {
				return nil, err
			}
			pairs = append(pairs, kv{ke, ve})
		}
		sort.SliceStable(pairs, func(i, j int) bool { return bytes.Compare(pairs[i].k, pairs[j].k) < 0 })
		out := head(5, uint64(len(pairs)))
		for _, p := range pairs {
			out = append(out, p.k...)
			out = append(out, p.val...)
		}
		return out, nil
	case tNull:
		return []byte{0xf6}, nil
	}
	return nil, errors.New("cannot canonically encode")
}

func isDeterministic(buf []byte) bool {
	v, np, err := decode(buf, 0)
	if err != nil || np != len(buf) || v.t == tTag {
		return false
	}
	enc, err := encode(v)
	if err != nil {
		return false
	}
	return bytes.Equal(enc, buf)
}

func mapGet(m cval, key int64) (cval, bool) {
	for _, p := range m.m {
		if p[0].t == tInt && p[0].i == key {
			return p[1], true
		}
	}
	return cval{}, false
}

// ---------------------------------------------------------------------------
// COSE_Sign1 parse + gates
// ---------------------------------------------------------------------------

type sign1 struct {
	protected []byte
	phdr      cval
	payload   []byte
	sig       []byte
}

func parseSign1(buf []byte) (*sign1, bool) {
	top, _, err := decode(buf, 0)
	if err != nil {
		return nil, false
	}
	arr := top
	if top.t == tTag {
		if top.tag != coseSign1Tag {
			return nil, false
		}
		arr = top.arr[0]
	}
	if arr.t != tArray || len(arr.arr) != 4 {
		return nil, false
	}
	protected, uhdr, payload, sig := arr.arr[0], arr.arr[1], arr.arr[2], arr.arr[3]
	if protected.t != tBytes || uhdr.t != tMap || sig.t != tBytes {
		return nil, false
	}
	if payload.t != tBytes && payload.t != tNull {
		return nil, false
	}
	var phdr cval
	if len(protected.b) == 0 {
		phdr = cval{t: tMap}
	} else {
		if !isDeterministic(protected.b) {
			return nil, false
		}
		dec, _, err := decode(protected.b, 0)
		if err != nil || dec.t != tMap {
			return nil, false
		}
		phdr = dec
	}
	pl := []byte{}
	if payload.t == tBytes {
		pl = payload.b
	}
	return &sign1{protected: protected.b, phdr: phdr, payload: pl, sig: sig.b}, true
}

func sigStructure(protectedBytes, payloadBytes []byte) []byte {
	out, _ := encode(cval{t: tArray, arr: []cval{
		{t: tText, s: "Signature1"},
		{t: tBytes, b: protectedBytes},
		{t: tBytes, b: []byte{}},
		{t: tBytes, b: payloadBytes},
	}})
	return out
}

// ---------------------------------------------------------------------------
// Signature verification per algorithm
// ---------------------------------------------------------------------------

func verifyEs256(key map[string]string, preimage, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	xb, err1 := hex.DecodeString(key["x"])
	yb, err2 := hex.DecodeString(key["y"])
	if err1 != nil || err2 != nil {
		return false
	}
	x := new(big.Int).SetBytes(xb)
	y := new(big.Int).SetBytes(yb)
	lhs := new(big.Int).Mul(y, y)
	rhs := new(big.Int).Mul(x, x)
	rhs.Mul(rhs, x)
	rhs.Add(rhs, new(big.Int).Mul(p256A, x))
	rhs.Add(rhs, p256B)
	diff := new(big.Int).Sub(lhs, rhs)
	diff.Mod(diff, p256P)
	if diff.Sign() != 0 {
		return false
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	h := sha256.Sum256(preimage)
	return ecdsa.Verify(pub, h[:], r, s)
}

func verifyEddsa(key map[string]string, preimage, sig []byte) bool {
	pk, err := hex.DecodeString(key["x"])
	if err != nil || len(pk) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pk), preimage, sig)
}

func verifyPs256(key map[string]string, preimage, sig []byte) bool {
	nb, err1 := hex.DecodeString(key["n"])
	eb, err2 := hex.DecodeString(key["e"])
	if err1 != nil || err2 != nil {
		return false
	}
	e := new(big.Int).SetBytes(eb)
	if !e.IsInt64() || e.Int64() > (1<<31-1) {
		return false
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(e.Int64())}
	h := sha256.Sum256(preimage)
	return rsa.VerifyPSS(pub, crypto.SHA256, h[:], sig, &rsa.PSSOptions{SaltLength: 32}) == nil
}

func verdict(buf []byte, key map[string]string) bool {
	p, ok := parseSign1(buf)
	if !ok {
		return false
	}
	alg, ok := mapGet(p.phdr, 1)
	if !ok || alg.t != tInt {
		return false
	}
	if crit, has := mapGet(p.phdr, 2); has {
		if crit.t != tArray || len(crit.arr) == 0 {
			return false
		}
		for _, label := range crit.arr {
			if label.t != tInt || !knownLabels[label.i] {
				return false
			}
		}
	}
	kty, known := algKty[alg.i]
	if !known || key["kty"] != kty {
		return false
	}
	preimage := sigStructure(p.protected, p.payload)
	switch alg.i {
	case -7:
		return verifyEs256(key, preimage, p.sig)
	case -8:
		return verifyEddsa(key, preimage, p.sig)
	case -37:
		return verifyPs256(key, preimage, p.sig)
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
	var corpus map[string]json.RawMessage
	if err := json.Unmarshal(data, &corpus); err != nil {
		fmt.Fprintf(os.Stderr, "cannot parse corpus %s: %v\n", path, err)
		os.Exit(1)
	}
	var keys map[string]map[string]string
	json.Unmarshal(corpus["keys"], &keys)

	total, matched := 0, 0
	for _, sec := range sections {
		var cases []map[string]json.RawMessage
		if corpus[sec] == nil {
			continue
		}
		json.Unmarshal(corpus[sec], &cases)
		for _, c := range cases {
			var note string
			json.Unmarshal(c["note"], &note)
			var expect bool
			json.Unmarshal(c["expect_valid"], &expect)
			var accept bool
			if sec == "cose_deterministic_cbor" {
				var h string
				json.Unmarshal(c["cbor_hex"], &h)
				b, _ := hex.DecodeString(h)
				accept = isDeterministic(b)
			} else {
				var h, keyName string
				json.Unmarshal(c["cose_hex"], &h)
				json.Unmarshal(c["key"], &keyName)
				b, _ := hex.DecodeString(h)
				accept = verdict(b, keys[keyName])
			}
			total++
			if accept == expect {
				matched++
			} else {
				fmt.Printf("FAIL  [%s] %s\n", sec, note)
			}
		}
	}
	fmt.Printf("\ngo (cose): %d/%d cases matched\n", matched, total)
	if matched != total {
		os.Exit(1)
	}
}
