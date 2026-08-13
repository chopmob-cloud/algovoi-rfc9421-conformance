// Go runner for the post-quantum ML-DSA-65 corpus (pqc_mldsa_v0).
//
// Independently reproduces every verdict in the frozen corpus, mirroring the
// Python reference runner (runners/python/verify_pqc_mldsa.py) and its decision
// surface (tools/oracle_pqc_mldsa.py) case for case: decode the hex public key,
// message and signature, reject a wrong-length public key (must be 1952) or
// signature (must be 3309) before any verify, then verify the FIPS-204 ML-DSA-65
// signature over the exact message bytes with the EMPTY context string.
//
// The ML-DSA implementation is Cloudflare CIRCL's sign/mldsa/mldsa65 (module
// github.com/cloudflare/circl, pinned v1.6.5), a FIPS-204 implementation
// independent of the reference liboqs. mldsa65.Verify takes an explicit context
// argument; nil selects the empty context (the pure ML-DSA variant). A round-3
// Dilithium library would fail the valid controls; that is the built-in tripwire.
//
// This runner needs one external module, so a KAF cell copies it into a clean
// module directory (go mod init + go get github.com/cloudflare/circl@v1.6.5) and
// then `go run`s it; it does not share the module of the sibling stdlib runners.
//
// Exit 0 iff every case matches. Corpus path: os.Args[1], else $ALGOVOI_PQC_MLDSA,
// else the repo corpus relative to this source file's directory.

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const defaultCorpus = "../../corpus/pqc_mldsa_v0/pqc_mldsa_v0.json"

var sections = []string{"mldsa65_verify", "mldsa65_malformed", "mldsa65_acvp_kat"}

const pkLen = 1952
const sigLen = 3309

func verdict(pkHex, msgHex, sigHex string) bool {
	pk, err1 := hex.DecodeString(pkHex)
	msg, err2 := hex.DecodeString(msgHex)
	sig, err3 := hex.DecodeString(sigHex)
	if err1 != nil || err2 != nil || err3 != nil {
		return false
	}
	if len(pk) != pkLen || len(sig) != sigLen {
		return false
	}
	var pub mldsa65.PublicKey
	if err := pub.UnmarshalBinary(pk); err != nil {
		return false
	}
	// nil context = the empty context string (pure ML-DSA variant).
	return mldsa65.Verify(&pub, msg, nil, sig)
}

func main() {
	path := defaultCorpus
	if len(os.Args) > 1 {
		path = os.Args[1]
	} else if e := os.Getenv("ALGOVOI_PQC_MLDSA"); e != "" {
		path = e
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

	total, matched := 0, 0
	for _, sec := range sections {
		arr, _ := corpus[sec].([]interface{})
		for _, e := range arr {
			c, _ := e.(map[string]interface{})
			note, _ := c["note"].(string)
			expect, _ := c["expect_valid"].(bool)
			pk, _ := c["public_key"].(string)
			msg, _ := c["message"].(string)
			sig, _ := c["signature"].(string)
			accept := verdict(pk, msg, sig)
			total++
			if accept == expect {
				matched++
			} else {
				fmt.Printf("FAIL  [%s] %s\n", sec, note)
			}
		}
	}
	fmt.Printf("\ngo (pqc_mldsa): %d/%d cases matched\n", matched, total)
	if matched != total {
		os.Exit(1)
	}
}
