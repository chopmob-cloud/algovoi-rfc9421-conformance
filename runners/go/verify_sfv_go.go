// Go runner for the Structured Field Values corpus (sfv_v0).
//
// Independently reproduces every verdict in the frozen corpus: parse `input` as
// its declared field type (item|list|dictionary), and if it parses, serialize it
// canonically (RFC 8941 Section 4.1) and compare to the frozen `canonical`. A
// case matches iff parse_ok == expect_parse_ok and, when ok, the canonical bytes
// are equal.
//
// Parsing and canonical serialization use the third-party RFC 8941 library
// github.com/dunglas/httpsfv (Kevin Dunglas), so a pass is genuine agreement with
// an independent implementation, not an echo of the generator's oracle. This is
// built in an isolated temp module by tools/run_consensus_sfv.sh and
// kaf/run_cells_sfv.sh (go mod init + go get), so it does not disturb the
// stdlib-only wba runner in this same directory.
//
// Corpus path: os.Args[1], else ../../corpus/sfv_v0/sfv_v0.json. Exit 0 iff every
// case matches, else 1.

package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/dunglas/httpsfv"
)

const defaultCorpus = "../../corpus/sfv_v0/sfv_v0.json"

var sections = []string{
	"sfv_item", "sfv_list", "sfv_dictionary",
	"sfv_parameters", "sfv_canonical", "sfv_reject",
}

type sfvCase struct {
	FieldType     string `json:"field_type"`
	Input         string `json:"input"`
	ExpectParseOK bool   `json:"expect_parse_ok"`
	Note          string `json:"note"`
	Canonical     string `json:"canonical"`
}

// verdict parses `input` as its field type and, if it parses, returns the
// canonical serialization. httpsfv takes header values as []string; a single
// field value is passed as one element.
func verdict(fieldType, input string) (bool, string) {
	switch fieldType {
	case "item":
		v, err := httpsfv.UnmarshalItem([]string{input})
		if err != nil {
			return false, ""
		}
		s, err := httpsfv.Marshal(v)
		if err != nil {
			return false, ""
		}
		return true, s
	case "list":
		v, err := httpsfv.UnmarshalList([]string{input})
		if err != nil {
			return false, ""
		}
		s, err := httpsfv.Marshal(v)
		if err != nil {
			return false, ""
		}
		return true, s
	case "dictionary":
		v, err := httpsfv.UnmarshalDictionary([]string{input})
		if err != nil {
			return false, ""
		}
		s, err := httpsfv.Marshal(v)
		if err != nil {
			return false, ""
		}
		return true, s
	}
	return false, ""
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

	total := 0
	matched := 0
	var fails []string
	for _, sec := range sections {
		raw, ok := corpus[sec]
		if !ok {
			continue
		}
		var cases []sfvCase
		if err := json.Unmarshal(raw, &cases); err != nil {
			continue
		}
		for _, c := range cases {
			ok, canon := verdict(c.FieldType, c.Input)
			match := (ok == c.ExpectParseOK) && (!ok || canon == c.Canonical)
			total++
			if match {
				matched++
			} else {
				fails = append(fails, "["+sec+"] "+c.Note)
			}
		}
	}
	for _, f := range fails {
		fmt.Printf("FAIL  %s\n", f)
	}
	fmt.Printf("\ngo (sfv): %d/%d cases matched\n", matched, total)
	if matched != total {
		os.Exit(1)
	}
}
