<?php
// PHP runner for the FAPI 2.0 Message Signing corpus (fapi_messagesigning_v0).
//
// Independent PHP port of runners/python/verify_fapi.py. Reproduces every verdict
// in the frozen corpus: the RFC 9421 s2.5 signing base, the PROFILE rules
// (mandated covered-component completeness, Content-Digest (RFC 9530) body
// binding, PS256/ES256 algorithm restriction) and the PS256 / ES256 crypto, all
// re-derived here from the corpus `policy` (read at RUNTIME), NOT imported from
// any oracle, so a runner passing is genuine agreement. Byte-identical verdicts
// to the Python authority and the other runners.
//
// PHP's openssl_verify has no RSA-PSS mode, so PS256 (rsa-pss-sha256) is verified
// with a self-contained EMSA-PSS-VERIFY (RFC 8017) over the RSA public op
// (ext-gmp), mirroring the sibling runners/php/negative_v1.php with the hash
// changed to SHA-256 (mHash=sha256, sLen=32, MGF1-SHA256, emBits=modBits-1).
// ES256 (ECDSA P-256) uses openssl_verify with OPENSSL_ALGO_SHA256 over a
// DER-encoded signature assembled from the raw 64-byte r||s, with the low-s
// malleability gate applied fail-closed first (ext-gmp, policy.p256_n).
//
// Corpus path: argv[1], else the sibling repo default. Needs ext-gmp + ext-openssl.

const DEFAULT_PATH = "../../corpus/fapi_messagesigning_v0/fapi_messagesigning_v0.json";

class SigningBaseError extends Exception {}

// ================= signing base (port of build_signing_base, s2.5) =================
function fapi_signing_base(array $in, ?string $spr): string {
    $headers = [];
    foreach (($in["headers"] ?? []) as $k => $v) $headers[strtolower($k)] = $v;

    $strOr = function (string $f, string $m) use ($in) {
        if (!isset($in[$f]) || $in[$f] === null) throw new SigningBaseError($m);
        return $in[$f];
    };

    $lines = [];
    foreach ($in["covered_components"] as $component) {
        $c = strtolower($component);
        switch ($c) {
            case "@method":
                $value = $strOr("method", "@method covered but method not supplied");
                break;
            case "@target-uri":
                $value = $strOr("target_uri", "@target-uri covered but target_uri not supplied");
                break;
            case "@status":
                if (!isset($in["status"]) || $in["status"] === null) throw new SigningBaseError("@status covered but status not supplied");
                $value = (string)$in["status"];
                break;
            case "@authority":
                $value = $strOr("authority", "@authority covered but authority not supplied");
                break;
            case "@path":
                $value = $strOr("path", "@path covered but path not supplied");
                break;
            default:
                if (str_starts_with($c, "@")) throw new SigningBaseError("unsupported derived component: $component");
                if (!array_key_exists($c, $headers)) throw new SigningBaseError("covered header $component not present");
                $value = $headers[$c];
        }
        $lines[] = "\"$c\": $value";
    }
    $lines[] = "\"@signature-params\": $spr";
    return implode("\n", $lines);
}

// ================= profile rules =================
function coverage_ok(string $message_type, array $covered, array $policy): bool {
    $key = $message_type === "request" ? "required_covered_request" : "required_covered_response";
    $have = array_map('strtolower', $covered);
    foreach ($policy[$key] as $r) {
        if (!in_array(strtolower($r), $have, true)) return false;
    }
    return true;
}

function content_digest_ok(string $body_b64, string $header_value, array $covered, array $policy): bool {
    $coveredLower = array_map('strtolower', $covered);
    if (!in_array("content-digest", $coveredLower, true)) return false;
    $parts = explode("=", $header_value, 2);
    if (count($parts) < 2) return false;
    $algorithm = strtolower(trim($parts[0]));
    if (!in_array($algorithm, $policy["content_digest_algorithms"], true)) return false;
    $body = base64_decode($body_b64);
    $digest = $algorithm === "sha-256" ? hash("sha256", $body, true) : hash("sha512", $body, true);
    $expect = "$algorithm=:" . base64_encode($digest) . ":";
    return trim($header_value) === $expect;
}

// ================= PS256 verify (RSA-PSS SHA-256, EMSA-PSS-VERIFY RFC 8017) =======
function mgf1_sha256(string $seed, int $len): string {
    $out = ""; $c = 0;
    while (strlen($out) < $len) { $out .= hash("sha256", $seed . pack("N", $c), true); $c++; }
    return substr($out, 0, $len);
}
function emsa_pss_verify_sha256(string $M, string $EM, int $emBits, int $sLen): bool {
    $hLen = 32; $emLen = intdiv($emBits + 7, 8);
    if ($emLen < $hLen + $sLen + 2) return false;
    if (substr($EM, -1) !== "\xbc") return false;
    $maskedDB = substr($EM, 0, $emLen - $hLen - 1);
    $H = substr($EM, $emLen - $hLen - 1, $hLen);
    $topBits = 8 * $emLen - $emBits;
    if ((ord($maskedDB[0]) & ((0xFF << (8 - $topBits)) & 0xFF)) !== 0) return false;
    $DB = $maskedDB ^ mgf1_sha256($H, $emLen - $hLen - 1);
    $DB[0] = chr(ord($DB[0]) & (0xFF >> $topBits));
    $psLen = $emLen - $hLen - $sLen - 2;
    for ($i = 0; $i < $psLen; $i++) if ($DB[$i] !== "\x00") return false;
    if ($DB[$psLen] !== "\x01") return false;
    $salt = $sLen > 0 ? substr($DB, -$sLen) : "";
    $mHash = hash("sha256", $M, true);
    $Hprime = hash("sha256", str_repeat("\x00", 8) . $mHash . $salt, true);
    return hash_equals($H, $Hprime);
}
function ps256_verify(string $base, string $sig, string $spki): bool {
    $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
    $key = openssl_pkey_get_public($pem);
    if ($key === false) return false;
    $det = openssl_pkey_get_details($key);
    if (!isset($det["rsa"])) return false;
    $n = gmp_import($det["rsa"]["n"]); $e = gmp_import($det["rsa"]["e"]);
    $s = gmp_import($sig);
    if (gmp_cmp($s, $n) >= 0) return false;
    $modBits = strlen(gmp_strval($n, 2));
    $emBits = $modBits - 1; $emLen = intdiv($emBits + 7, 8);
    $EM = str_pad(gmp_export(gmp_powm($s, $e, $n)), $emLen, "\x00", STR_PAD_LEFT);
    return emsa_pss_verify_sha256($base, $EM, $emBits, 32);
}

// ================= ES256 verify (ECDSA P-256 SHA-256, low-s gate) =================
const P256_SPKI_PREFIX = "3059301306072a8648ce3d020106082a8648ce3d030107034200";
function der_int(string $b): string {
    $b = ltrim($b, "\x00");
    if ($b === "") $b = "\x00";
    if (ord($b[0]) & 0x80) $b = "\x00" . $b;
    return "\x02" . chr(strlen($b)) . $b;
}
function es256_verify(string $base, string $sig_raw, string $pub, bool $require_low_s, array $policy): bool {
    if (strlen($sig_raw) !== 64) return false;
    $r = gmp_init(bin2hex(substr($sig_raw, 0, 32)), 16);
    $s = gmp_init(bin2hex(substr($sig_raw, 32, 32)), 16);
    if ($require_low_s) {
        $n = gmp_init($policy["p256_n"], 10);
        if (gmp_cmp($s, gmp_div_q($n, 2)) > 0) return false;
    }
    if (strlen($pub) !== 65 || ord($pub[0]) !== 0x04) return false;
    $spki = hex2bin(P256_SPKI_PREFIX) . $pub;
    $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
    $key = openssl_pkey_get_public($pem);
    if ($key === false) return false;
    $der = der_int(substr($sig_raw, 0, 32)) . der_int(substr($sig_raw, 32, 32));
    $der = "\x30" . chr(strlen($der)) . $der;
    return openssl_verify($base, $der, $key, OPENSSL_ALGO_SHA256) === 1;
}

// ================= driver =================
$path = $argv[1] ?? DEFAULT_PATH;
$corpus = json_decode(file_get_contents($path), true);
$policy = $corpus["policy"];
$total = 0; $matched = 0; $fails = [];
$record = function (bool $ok, string $section, array $c) use (&$total, &$matched, &$fails) {
    $total++;
    if ($ok) $matched++; else $fails[] = "[$section] " . ($c["note"] ?? "");
};

foreach ($corpus["fapi_signing_base"] as $c) {
    $want = base64_decode($c["signing_base_b64"]);
    try {
        // build FIRST; `$c["ok"] && build(...)` would short-circuit for negative
        // cases and never verify that the build actually fails.
        $built = fapi_signing_base($c["in"], $c["signature_params_raw"] ?? null);
        $ok = $c["ok"] && $built === $want;
    } catch (\Throwable) { $ok = !$c["ok"]; }
    $record($ok, "fapi_signing_base", $c);
}
foreach ($corpus["fapi_required_coverage"] as $c) {
    $ok = coverage_ok($c["message_type"], $c["covered_components"], $policy) === $c["expect_accept"];
    $record($ok, "fapi_required_coverage", $c);
}
foreach ($corpus["fapi_content_digest"] as $c) {
    $ok = content_digest_ok($c["body_b64"], $c["content_digest"], $c["covered_components"], $policy) === $c["expect_accept"];
    $record($ok, "fapi_content_digest", $c);
}
foreach ($corpus["fapi_alg"] as $c) {
    $ok = (in_array(strtolower($c["alg"]), $policy["allowed_algs"], true)) === $c["expect_accept"];
    $record($ok, "fapi_alg", $c);
}
foreach ($corpus["fapi_ps256_verify"] as $c) {
    $base = base64_decode($c["signing_base_b64"]);
    $valid = ps256_verify($base, hex2bin($c["sig_hex"]), hex2bin($c["pub_spki_hex"]));
    $record($valid === $c["expect_valid"], "fapi_ps256_verify", $c);
}
foreach ($corpus["fapi_es256_verify"] as $c) {
    $base = base64_decode($c["signing_base_b64"]);
    $valid = es256_verify($base, hex2bin($c["sig_raw_hex"]), hex2bin($c["pub_uncompressed_hex"]),
                          ($c["require_low_s"] ?? false) === true, $policy);
    $record($valid === $c["expect_valid"], "fapi_es256_verify", $c);
}

foreach ($fails as $f) echo "FAIL  $f\n";
echo "\nphp (fapi): $matched/$total cases matched\n";
exit($matched === $total ? 0 : 1);
