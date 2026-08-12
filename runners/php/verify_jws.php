<?php
// PHP runner for the JSON Web Signature corpus (jws_v0).
//
// Independent PHP port of the Python reference runner (runners/python/verify_jws.py)
// and its decision surface (tools/oracle_jws.py). Parses each compact JWS, applies
// the JOSE security gates in order (reject alg:none, reject any crit, reject
// alg/key-type mismatch such as HS256 keyed with an RSA public key, select the key
// by kid when required), then verifies the RS256 / ES256 / EdDSA signature over
// ASCII(protected)+"."+ASCII(payload). Low-s is NOT enforced (plain JOSE permits a
// high-s ECDSA signature; low-s is a FAPI rule, not a jws_v0 rule).
//
// RS256 (RSASSA-PKCS1v15 SHA-256) and ES256 (ECDSA P-256, raw r||s re-encoded to
// DER; openssl rejects an off-curve public point at load) via ext-openssl; EdDSA
// (Ed25519) via ext-sodium. Public keys are rebuilt from the JWK material with a
// small hand-rolled DER encoder. Needs ext-openssl + ext-sodium (both bundled).
//
// Corpus path: argv[1], else the sibling repo default.

const DEFAULT_PATH = __DIR__ . "/../../corpus/jws_v0/jws_v0.json";

const SECTIONS = ["jws_compact_parse", "jws_alg_none", "jws_alg_confusion",
    "jws_rs256_verify", "jws_es256_verify", "jws_eddsa_verify", "jws_crit", "jws_kid"];

// RFC 7518 Section 3.1 alg -> the JWK kty a verifier must hold for it.
const ALG_KTY = ["RS256" => "RSA", "ES256" => "EC", "EdDSA" => "OKP", "HS256" => "oct"];

const P256_SPKI_PREFIX = "3059301306072a8648ce3d020106082a8648ce3d030107034200";

// Strict base64url decode of one compact segment (unpadded, URL-safe alphabet).
function b64url(string $seg) {
    if ($seg !== "" && !preg_match('/^[A-Za-z0-9_-]*$/', $seg)) return null;
    if (strlen($seg) % 4 === 1) return null;
    $b = base64_decode(strtr($seg, "-_", "+/"), true);
    return $b === false ? null : $b;
}

// ---- minimal DER encoder (for rebuilding the RSA public key from n, e) ----
function der_len(int $n): string {
    if ($n < 128) return chr($n);
    $bytes = "";
    while ($n > 0) { $bytes = chr($n & 0xff) . $bytes; $n >>= 8; }
    return chr(0x80 | strlen($bytes)) . $bytes;
}
function der_uint(string $b): string {
    $b = ltrim($b, "\x00");
    if ($b === "") $b = "\x00";
    if (ord($b[0]) & 0x80) $b = "\x00" . $b;
    return "\x02" . der_len(strlen($b)) . $b;
}
function der_seq(string $content): string { return "\x30" . der_len(strlen($content)) . $content; }
function der_bitstring(string $content): string {
    return "\x03" . der_len(strlen($content) + 1) . "\x00" . $content;
}

function rsa_pem_from_ne(string $n, string $e): string|false {
    $pkcs1 = der_seq(der_uint($n) . der_uint($e));
    // AlgorithmIdentifier: rsaEncryption (1.2.840.113549.1.1.1) + NULL
    $alg = der_seq(hex2bin("06092a864886f70d0101010500"));
    $spki = der_seq($alg . der_bitstring($pkcs1));
    return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
}

function der_int_raw(string $b): string {
    $b = ltrim($b, "\x00");
    if ($b === "") $b = "\x00";
    if (ord($b[0]) & 0x80) $b = "\x00" . $b;
    return "\x02" . chr(strlen($b)) . $b;
}

function parse_compact(string $token) {
    $parts = explode(".", $token);
    if (count($parts) !== 3) return null;
    $header_bytes = b64url($parts[0]);
    if ($header_bytes === null) return null;
    $header = json_decode($header_bytes, true);
    if (json_last_error() !== JSON_ERROR_NONE || !is_array($header)) return null;
    // A JSON object decodes to an associative array; a JSON array (list) must be rejected.
    if ($header !== [] && array_is_list($header)) return null;
    if (!array_key_exists("alg", $header)) return null;
    if (b64url($parts[1]) === null) return null;
    $sig = b64url($parts[2]);
    if ($sig === null) return null;
    return [$header, $sig, $parts[0] . "." . $parts[1]];
}

function select_key(array $header, array $keys, bool $select_by_kid) {
    if ($select_by_kid) {
        $kid = $header["kid"] ?? null;
        if ($kid === null) return null;
        foreach ($keys as $k) if ($k["kid"] === $kid) return $k["jwk"];
        return null;
    }
    return $keys[0]["jwk"];
}

function verify_rs256(array $jwk, string $signing_input, string $sig): bool {
    $n = b64url($jwk["n"] ?? "");
    $e = b64url($jwk["e"] ?? "");
    if ($n === null || $e === null) return false;
    $pem = rsa_pem_from_ne($n, $e);
    if ($pem === false) return false;
    $key = openssl_pkey_get_public($pem);
    if ($key === false) return false;
    return openssl_verify($signing_input, $sig, $key, OPENSSL_ALGO_SHA256) === 1;
}

function verify_es256(array $jwk, string $signing_input, string $sig): bool {
    if (strlen($sig) !== 64) return false;
    $x = b64url($jwk["x"] ?? "");
    $y = b64url($jwk["y"] ?? "");
    if ($x === null || $y === null || strlen($x) !== 32 || strlen($y) !== 32) return false;
    $uncompressed = "\x04" . $x . $y;
    // openssl rejects a public point that is not on secp256r1 at load.
    $spki = hex2bin(P256_SPKI_PREFIX) . $uncompressed;
    $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
    $key = openssl_pkey_get_public($pem);
    if ($key === false) return false;
    $der = der_int_raw(substr($sig, 0, 32)) . der_int_raw(substr($sig, 32, 32));
    $der = "\x30" . chr(strlen($der)) . $der;
    return openssl_verify($signing_input, $der, $key, OPENSSL_ALGO_SHA256) === 1;
}

function verify_eddsa(array $jwk, string $signing_input, string $sig): bool {
    $pk = b64url($jwk["x"] ?? "");
    if ($pk === null || strlen($pk) !== 32 || strlen($sig) !== 64) return false;
    try {
        return sodium_crypto_sign_verify_detached($sig, $signing_input, $pk);
    } catch (\Throwable $e) {
        return false;
    }
}

function verdict(string $token, array $keys, bool $select_by_kid): bool {
    $parsed = parse_compact($token);
    if ($parsed === null) return false;
    [$header, $sig, $signing_input] = $parsed;
    $alg = $header["alg"];
    if ($alg === "none") return false;
    if (array_key_exists("crit", $header)) return false;
    if (!array_key_exists($alg, ALG_KTY)) return false;
    $jwk = select_key($header, $keys, $select_by_kid);
    if ($jwk === null) return false;
    if (($jwk["kty"] ?? null) !== ALG_KTY[$alg]) return false;
    return match ($alg) {
        "RS256" => verify_rs256($jwk, $signing_input, $sig),
        "ES256" => verify_es256($jwk, $signing_input, $sig),
        "EdDSA" => verify_eddsa($jwk, $signing_input, $sig),
        default => false,
    };
}

$path = $argv[1] ?? DEFAULT_PATH;
$corpus = json_decode(file_get_contents($path), true);
$material = $corpus["keys"];
$results = [];
foreach (SECTIONS as $sec) {
    foreach (($corpus[$sec] ?? []) as $c) {
        $keys = [];
        foreach ($c["verify"]["key_names"] as $n) {
            $keys[] = ["kid" => $material[$n]["kid"] ?? null, "jwk" => $material[$n]];
        }
        $accept = verdict($c["jws"], $keys, $c["verify"]["select_by_kid"]);
        $results[] = [$sec, $c["note"], $accept === $c["expect_valid"]];
    }
}
$fails = 0;
foreach ($results as [$section, $note, $ok]) {
    if (!$ok) { echo "FAIL  [$section] $note\n"; $fails++; }
}
$total = count($results);
echo "\nphp (jws): " . ($total - $fails) . "/$total cases matched\n";
exit($fails === 0 ? 0 : 1);
