<?php
// PHP runner for the post-quantum ML-DSA-65 corpus (pqc_mldsa_v0).
//
// Independent PHP port of the Python reference runner
// (runners/python/verify_pqc_mldsa.py) and its decision surface
// (tools/oracle_pqc_mldsa.py): decode the hex public key, message and signature,
// reject a wrong-length public key (must be 1952) or signature (must be 3309)
// before any verify, then verify the FIPS-204 ML-DSA-65 signature over the exact
// message bytes with the EMPTY context string (the pure ML-DSA variant).
//
// PHP's ext-openssl is built against an OpenSSL that predates ML-DSA (FIPS 204
// landed in OpenSSL 3.5) and exposes no ML-DSA API, and there is no mature pure
// PHP FIPS-204 library, so this runner binds liboqs (the C reference the C runner
// already uses) through ext-ffi (bundled with PHP 8.x). It calls exactly the
// liboqs C API the C runner does: OQS_SIG_new("ML-DSA-65") + OQS_SIG_verify.
// OQS_SIG_new returns NULL if the installed liboqs is an old build that exposes
// only round-3 "Dilithium3" and not "ML-DSA-65"; that is the built-in tripwire.
//
// Requires ext-ffi (enabled) and a system liboqs shared library (0.14.0 minimal,
// the same build the C cell makes) exposing the ML-DSA-65 mechanism.
//
// Corpus path: argv[1], else $ALGOVOI_PQC_MLDSA, else the sibling repo default.

const PK_LEN = 1952;
const SIG_LEN = 3309;
const MECHANISM = "ML-DSA-65";
const OQS_SUCCESS = 0;

const SECTIONS = ["mldsa65_verify", "mldsa65_malformed", "mldsa65_acvp_kat"];

// hex -> binary string; null on odd length or a bad digit. An empty string
// decodes to a real 0-byte value (not a decode failure), so the empty-message
// case is a real 0-byte message.
function hexdec_bytes(?string $s): ?string {
    if ($s === null) return null;
    if (strlen($s) % 2 !== 0) return null;
    if ($s === "") return "";
    if (!ctype_xdigit($s)) return null;
    return hex2bin($s);
}

// Copy a binary string into a freshly allocated FFI unsigned char[] buffer and
// return it. A zero-length value gets a 1-byte buffer whose pointer is passed
// with length 0 (liboqs never reads it).
function to_buf(FFI $ffi, string $bytes) {
    $n = strlen($bytes);
    $buf = $ffi->new("unsigned char[" . ($n > 0 ? $n : 1) . "]", false);
    for ($i = 0; $i < $n; $i++) {
        $buf[$i] = ord($bytes[$i]);
    }
    return $buf;
}

function verdict(FFI $ffi, $sig, ?string $pkHex, ?string $msgHex, ?string $sigHex): bool {
    $pk = hexdec_bytes($pkHex);
    $msg = hexdec_bytes($msgHex);
    $s = hexdec_bytes($sigHex);
    if ($pk === null || $msg === null || $s === null) return false;
    if (strlen($pk) !== PK_LEN || strlen($s) !== SIG_LEN) return false;
    // A C array cdata decays to a pointer when passed to a pointer parameter, so
    // the buffers go straight through to OQS_SIG_verify.
    $pkBuf = to_buf($ffi, $pk);
    $msgBuf = to_buf($ffi, $msg);
    $sigBuf = to_buf($ffi, $s);
    $rc = $ffi->OQS_SIG_verify(
        $sig,
        $msgBuf, strlen($msg),
        $sigBuf, strlen($s),
        $pkBuf
    );
    return $rc === OQS_SUCCESS;
}

$path = $argv[1] ?? getenv("ALGOVOI_PQC_MLDSA")
       ?: __DIR__ . "/../../corpus/pqc_mldsa_v0/pqc_mldsa_v0.json";
$corpus = json_decode(file_get_contents($path), true);

// Thin FFI binding to the liboqs C API. Only the three symbols the verify path
// needs are declared; OQS_SIG is an opaque struct pointer because the fixed
// FIPS-204 lengths are hard-coded, so no struct fields are read.
$ffi = FFI::cdef(
    "typedef struct OQS_SIG OQS_SIG;\n" .
    "OQS_SIG *OQS_SIG_new(const char *method_name);\n" .
    "void OQS_SIG_free(OQS_SIG *sig);\n" .
    "int OQS_SIG_verify(const OQS_SIG *sig, const unsigned char *message, size_t message_len, const unsigned char *signature, size_t signature_len, const unsigned char *public_key);\n",
    "liboqs.so"
);

$sig = $ffi->OQS_SIG_new(MECHANISM);
if (FFI::isNull($sig)) {
    fwrite(STDERR, "liboqs has no ML-DSA-65 (old/Dilithium build)\n");
    exit(2);
}

$results = [];
foreach (SECTIONS as $sec) {
    foreach (($corpus[$sec] ?? []) as $c) {
        $accept = verdict($ffi, $sig, $c["public_key"], $c["message"], $c["signature"]);
        $results[] = [$sec, $c["note"], $accept === $c["expect_valid"]];
    }
}
$ffi->OQS_SIG_free($sig);

$fails = 0;
foreach ($results as [$section, $note, $ok]) {
    if (!$ok) { echo "FAIL  [$section] $note\n"; $fails++; }
}
$total = count($results);
echo "\nphp (pqc_mldsa): " . ($total - $fails) . "/$total cases matched\n";
exit($fails === 0 ? 0 : 1);
