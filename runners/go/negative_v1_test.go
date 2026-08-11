package ecdsa

// Go runner for the rfc9421_negative_v1 CORE cross-language battery. Lives in the
// ecdsa package because it imports core (verifier) and exercises both the core
// primitives and the ECDSA add-on, mirroring the Python reference runner so all
// four languages produce identical verdicts per case.
//
// Corpus path: ALGOVOI_NEGATIVE_V1 env override, else defaultNegativeV1Path.

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	verifier "github.com/chopmob-cloud/algovoi-rfc9421-verifier-go/verifier"
)

// Default assumes the algovoi-rfc9421-conformance repo is checked out alongside
// this one; override with ALGOVOI_NEGATIVE_V1. The test skips if neither resolves.
const defaultNegativeV1Path = `../../algovoi-rfc9421-conformance/corpus/rfc9421_negative_v1/rfc9421_negative_v1.json`

type nv1In struct {
	CoveredComponents []string               `json:"covered_components"`
	Method            *string                `json:"method"`
	Authority         *string                `json:"authority"`
	Path              *string                `json:"path"`
	TargetURI         *string                `json:"target_uri"`
	Scheme            *string                `json:"scheme"`
	Status            *json.Number           `json:"status"`
	Headers           map[string]string      `json:"headers"`
	Parameters        map[string]interface{} `json:"parameters"`
}

type nv1Corpus struct {
	SigningBase []struct {
		In                 nv1In   `json:"in"`
		Mode               string  `json:"mode"`
		OK                 bool    `json:"ok"`
		SigningBaseB64     string  `json:"signing_base_b64"`
		SignatureParamsRaw *string `json:"signature_params_raw"`
		Note               string  `json:"note"`
	} `json:"signing_base"`
	SignatureInputParse []struct {
		Header string `json:"header"`
		OK     bool   `json:"ok"`
		Note   string `json:"note"`
	} `json:"signature_input_parse"`
	SignatureValueParse []struct {
		Header string `json:"header"`
		OK     bool   `json:"ok"`
		Note   string `json:"note"`
	} `json:"signature_value_parse"`
	Keygate []struct {
		PkHex      string `json:"pk_hex"`
		SmallOrder bool   `json:"small_order"`
		Rejected   *string `json:"rejected"`
		Note       string `json:"note"`
	} `json:"keygate"`
	Ed25519Verify []struct {
		SigningBaseB64 string `json:"signing_base_b64"`
		SigHex         string `json:"sig_hex"`
		PkHex          string `json:"pk_hex"`
		ExpectValid    bool   `json:"expect_valid"`
		Note           string `json:"note"`
	} `json:"ed25519_verify"`
	EcdsaVerify []struct {
		Curve             string `json:"curve"`
		MsgHex            string `json:"msg_hex"`
		PubUncompressedHex string `json:"pub_uncompressed_hex"`
		SigRawHex         string `json:"sig_raw_hex"`
		ExpectValid       bool   `json:"expect_valid"`
		StrictLowS        bool   `json:"strict_low_s"`
		Note              string `json:"note"`
	} `json:"ecdsa_verify"`
}

func loadNegativeV1(t *testing.T) *nv1Corpus {
	t.Helper()
	path := os.Getenv("ALGOVOI_NEGATIVE_V1")
	if path == "" {
		path = defaultNegativeV1Path
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("rfc9421_negative_v1 corpus not available (%v); set ALGOVOI_NEGATIVE_V1 to the corpus path to run", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var c nv1Corpus
	if err := dec.Decode(&c); err != nil {
		t.Fatalf("decode corpus: %v", err)
	}
	return &c
}

func TestNegativeV1SigningBase(t *testing.T) {
	c := loadNegativeV1(t)
	for _, sc := range c.SigningBase {
		in := verifier.SigningBaseInput{
			CoveredComponents:  sc.In.CoveredComponents,
			Method:             sc.In.Method,
			Authority:          sc.In.Authority,
			Path:               sc.In.Path,
			TargetURI:          sc.In.TargetURI,
			Scheme:             sc.In.Scheme,
			Headers:            sc.In.Headers,
			Parameters:         sc.In.Parameters,
			Mode:               sc.Mode,
			SignatureParamsRaw: sc.SignatureParamsRaw,
		}
		if sc.In.Status != nil {
			n, _ := sc.In.Status.Int64()
			v := int(n)
			in.Status = &v
		}
		got, err := verifier.BuildSigningBase(in)
		if sc.OK {
			want, _ := base64.StdEncoding.DecodeString(sc.SigningBaseB64)
			if err != nil || got != string(want) {
				t.Errorf("signing_base [%s]: err=%v match=%v", sc.Note, err, got == string(want))
			}
		} else if err == nil {
			t.Errorf("signing_base [%s]: expected error, got none", sc.Note)
		}
	}
}

func TestNegativeV1SignatureInputParse(t *testing.T) {
	c := loadNegativeV1(t)
	for _, sc := range c.SignatureInputParse {
		_, err := verifier.ParseSignatureInput(sc.Header)
		if (err == nil) != sc.OK {
			t.Errorf("sig_input_parse [%s]: ok=%v want %v", sc.Note, err == nil, sc.OK)
		}
	}
}

func TestNegativeV1SignatureValueParse(t *testing.T) {
	c := loadNegativeV1(t)
	for _, sc := range c.SignatureValueParse {
		_, _, err := verifier.ParseSignatureValue(sc.Header)
		if (err == nil) != sc.OK {
			t.Errorf("sig_value_parse [%s]: ok=%v want %v", sc.Note, err == nil, sc.OK)
		}
	}
}

func TestNegativeV1Keygate(t *testing.T) {
	c := loadNegativeV1(t)
	for _, sc := range c.Keygate {
		pk, _ := hex.DecodeString(sc.PkHex)
		rejected := verifier.CheckEd25519PublicKey(pk) != nil
		wantRejected := sc.Rejected != nil
		if rejected != wantRejected {
			t.Errorf("keygate [%s]: rejected=%v want %v", sc.Note, rejected, wantRejected)
		}
		if verifier.IsSmallOrder(pk) != sc.SmallOrder {
			t.Errorf("keygate [%s]: small_order mismatch", sc.Note)
		}
	}
}

func TestNegativeV1Ed25519Verify(t *testing.T) {
	c := loadNegativeV1(t)
	for _, sc := range c.Ed25519Verify {
		baseBytes, _ := base64.StdEncoding.DecodeString(sc.SigningBaseB64)
		sig, _ := hex.DecodeString(sc.SigHex)
		ok, err := verifier.VerifySignature(string(baseBytes), sig, sc.PkHex, "ed25519")
		valid := err == nil && ok
		if valid != sc.ExpectValid {
			t.Errorf("ed25519_verify [%s]: valid=%v want %v (err=%v)", sc.Note, valid, sc.ExpectValid, err)
		}
	}
}

func TestNegativeV1EcdsaVerify(t *testing.T) {
	c := loadNegativeV1(t)
	for _, sc := range c.EcdsaVerify {
		msg, _ := hex.DecodeString(sc.MsgHex)
		sig, _ := hex.DecodeString(sc.SigRawHex)
		SetStrictLowS(sc.StrictLowS)
		fn := VerifyP256
		if sc.Curve == "p384" {
			fn = VerifyP384
		}
		ok, err := fn(string(msg), sig, sc.PubUncompressedHex)
		SetStrictLowS(false)
		valid := err == nil && ok
		if valid != sc.ExpectValid {
			t.Errorf("ecdsa_verify [%s/%s]: valid=%v want %v (err=%v)", sc.Curve, sc.Note, valid, sc.ExpectValid, err)
		}
	}
}
