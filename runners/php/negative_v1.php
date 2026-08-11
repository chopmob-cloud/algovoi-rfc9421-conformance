<?php
// PHP runner for the rfc9421_negative_v1 CORE cross-language battery.
//
// Independent PHP port of the verdict surface (signing_base.py, parse.py,
// keycheck.py, verify.py + the algovoi-rfc9421-ecdsa provider). Self-contained
// (no PHP RFC 9421 verifier exists); must produce byte-identical verdicts to
// every other runner. Ed25519 verify via ext-sodium (libsodium enforces
// canonical S) plus an explicit S < L check and the ported small-order /
// non-canonical key gate (ext-gmp, RFC 8032 arithmetic) applied fail-closed
// first. ECDSA P-256/P-384 via ext-openssl over a hand-assembled SPKI public key,
// with explicit range / width / on-curve / strict-low-s checks (ext-gmp).
//
// Corpus path: argv[1], else $ALGOVOI_NEGATIVE_V1, else the sibling repo default.

const DEFAULT_PATH = "../../corpus/rfc9421_negative_v1/rfc9421_negative_v1.json";

class SigningBaseError extends Exception {}
class ParseErr extends Exception {}
class WeakKeyErr extends Exception {}

// ================= signing base (port of signing_base.py) =================
function build_signing_base(array $in, string $mode, ?string $spr): string {
    if ($mode !== "algovoi-v0" && $mode !== "rfc9421") throw new SigningBaseError("bad mode");
    if ($mode === "rfc9421" && $spr === null) throw new SigningBaseError("rfc9421 needs signature_params_raw");
    $headers = [];
    foreach (($in["headers"] ?? []) as $k => $v) $headers[strtolower($k)] = $v;
    $params = $in["parameters"] ?? [];

    $strOr = function (string $f, string $m) use ($in) {
        if (!isset($in[$f]) || $in[$f] === null) throw new SigningBaseError($m);
        return $in[$f];
    };
    $paramOr = function (string $k, string $m) use ($params) {
        if (!array_key_exists($k, $params)) throw new SigningBaseError($m);
        return (string)$params[$k];
    };

    $lines = [];
    foreach ($in["covered_components"] as $component) {
        $c = strtolower($component);
        switch ($c) {
            case "@method":
                $v = $strOr("method", "@method covered but method not supplied");
                $value = $mode === "rfc9421" ? $v : strtolower($v);
                break;
            case "@authority":
                $value = strtolower($strOr("authority", "@authority covered but authority not supplied"));
                break;
            case "@path":
                $value = $strOr("path", "@path covered but path not supplied");
                break;
            case "@target-uri":
                $value = $strOr("target_uri", "@target-uri covered but target_uri not supplied");
                break;
            case "@scheme":
                $value = strtolower($strOr("scheme", "@scheme covered but scheme not supplied"));
                break;
            case "@status":
                if (!isset($in["status"]) || $in["status"] === null) throw new SigningBaseError("@status covered but status not supplied");
                $value = (string)$in["status"];
                break;
            case "created":
                $value = $paramOr("created", "'created' covered but no 'created' parameter in Signature-Input");
                break;
            case "expires":
                $value = $paramOr("expires", "'expires' covered but no 'expires' parameter in Signature-Input");
                break;
            default:
                if (str_starts_with($c, "@")) throw new SigningBaseError("unsupported derived component: $component");
                if (!array_key_exists($c, $headers)) throw new SigningBaseError("covered header $component not present");
                $value = $headers[$c];
        }
        $lines[] = "\"$c\": $value";
    }
    if ($mode === "rfc9421") $lines[] = "\"@signature-params\": $spr";
    return implode("\n", $lines);
}

// ================= structured-field parse (port of parse.py) =================
function parse_signature_input(?string $header): void {
    if ($header === null) throw new ParseErr("header must be str");
    $hv = trim($header);
    if ($hv === "") throw new ParseErr("empty header value");
    if (preg_match('/^\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*/', $hv, $m)) {
        $rest = substr($hv, strlen($m[0]));
    } elseif (str_starts_with($hv, "(")) {
        $rest = $hv;
    } else {
        throw new ParseErr("no label or covered-components list found at start");
    }
    if (!preg_match('/^\(\s*(?:"[^"]*"\s*)*\)/', $rest)) throw new ParseErr("no covered-components list found");
}

function parse_signature_value(?string $header): void {
    if ($header === null) throw new ParseErr("header must be str");
    $hv = trim($header);
    if ($hv === "") throw new ParseErr("empty Signature header value");
    if (preg_match('/^\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*/', $hv, $m)) {
        $rest = trim(substr($hv, strlen($m[0])));
    } elseif (str_starts_with($hv, ":")) {
        $rest = $hv;
    } else {
        throw new ParseErr("no label or signature-value prefix found at start");
    }
    if (!str_starts_with($rest, ":") || !str_ends_with($rest, ":") || strlen($rest) < 2)
        throw new ParseErr("signature value must be wrapped in colons");
    $sigB64 = substr($rest, 1, -1);
    $decoded = base64_decode($sigB64, true);
    if ($decoded === false) throw new ParseErr("signature value is not valid base64");
    if (base64_encode($decoded) !== $sigB64) throw new ParseErr("non-canonical base64");
}

// ================= gmp helpers + Ed25519 key gate (port of keycheck.py) ==========
function g($v) { return is_string($v) ? gmp_init($v, 0) : gmp_init($v); }
$GLOBALS['P'] = gmp_sub(gmp_pow(2, 255), 19);
function P() { return $GLOBALS['P']; }
function md($a) { $r = gmp_mod($a, P()); return gmp_sign($r) < 0 ? gmp_add($r, P()) : $r; }
function inv($a) { return gmp_powm(md($a), gmp_sub(P(), 2), P()); }
$GLOBALS['D'] = md(gmp_mul(gmp_init(-121665), inv(gmp_init(121666))));
$GLOBALS['SQRT_M1'] = gmp_powm(gmp_init(2), gmp_div_q(gmp_sub(P(), 1), gmp_init(4)), P());
$GLOBALS['L'] = gmp_add(gmp_pow(2, 252), gmp_init("27742317777372353535851937790883648493"));

function recover_x($y, int $sign) {
    if (gmp_cmp($y, P()) >= 0) return null;
    $y2 = md(gmp_mul($y, $y));
    $x2 = md(gmp_mul(md(gmp_sub($y2, 1)), inv(md(gmp_add(gmp_mul($GLOBALS['D'], $y2), 1)))));
    if (gmp_sign($x2) === 0) return $sign === 1 ? null : gmp_init(0);
    $x = gmp_powm($x2, gmp_div_q(gmp_add(P(), 3), gmp_init(8)), P());
    if (gmp_sign(md(gmp_sub(gmp_mul($x, $x), $x2))) !== 0) $x = md(gmp_mul($x, $GLOBALS['SQRT_M1']));
    if (gmp_sign(md(gmp_sub(gmp_mul($x, $x), $x2))) !== 0) return null;
    if (gmp_intval(gmp_and($x, 1)) !== $sign) $x = gmp_sub(P(), $x);
    return $x;
}

function decode_point(string $pk) {
    if (strlen($pk) !== 32) return null;
    $full = gmp_init(bin2hex(strrev($pk)), 16);
    $sign = gmp_testbit($full, 255) ? 1 : 0;
    $y = gmp_and($full, gmp_sub(gmp_pow(2, 255), 1));
    $x = recover_x($y, $sign);
    if ($x === null) return null;
    return [$x, $y, gmp_init(1), md(gmp_mul($x, $y))];
}

function pt_add($p, $q) {
    $a = md(gmp_mul(gmp_sub($p[1], $p[0]), gmp_sub($q[1], $q[0])));
    $b = md(gmp_mul(gmp_add($p[1], $p[0]), gmp_add($q[1], $q[0])));
    $c = md(gmp_mul(gmp_mul(gmp_mul(gmp_init(2), $p[3]), $q[3]), $GLOBALS['D']));
    $dd = md(gmp_mul(gmp_mul(gmp_init(2), $p[2]), $q[2]));
    $e = gmp_sub($b, $a); $f = gmp_sub($dd, $c); $gg = gmp_add($dd, $c); $h = gmp_add($b, $a);
    return [md(gmp_mul($e, $f)), md(gmp_mul($gg, $h)), md(gmp_mul($f, $gg)), md(gmp_mul($e, $h))];
}

function mul8($p) { $p2 = pt_add($p, $p); $p4 = pt_add($p2, $p2); return pt_add($p4, $p4); }
function is_identity($p) { return gmp_sign(md($p[0])) === 0 && gmp_sign(md(gmp_sub($p[1], $p[2]))) === 0; }

function small_order(string $pk): bool {
    $p = decode_point($pk);
    return $p !== null && is_identity(mul8($p));
}

function check_ed25519_public_key(string $pk): void {
    $p = decode_point($pk);
    if ($p === null) throw new WeakKeyErr("non-canonical/off-curve");
    if (is_identity(mul8($p))) throw new WeakKeyErr("small-order");
}

// ================= Ed25519 verify (port of verify.py) =================
function ed25519_verify(string $msg, string $sig, string $pk): bool {
    if (strlen($sig) !== 64 || strlen($pk) !== 32) return false;
    try { check_ed25519_public_key($pk); } catch (WeakKeyErr) { return false; }
    $s = gmp_init(bin2hex(strrev(substr($sig, 32, 32))), 16);
    if (gmp_cmp($s, $GLOBALS['L']) >= 0) return false;   // canonical-S
    try { return sodium_crypto_sign_verify_detached($sig, $msg, $pk); }
    catch (\Throwable) { return false; }
}

// ================= ECDSA verify (port of algovoi-rfc9421-ecdsa) =================
$GLOBALS['CURVES'] = [
    "p256" => [
        "field" => 32, "digest" => OPENSSL_ALGO_SHA256,
        "p" => "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "b" => "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
        "n" => "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "spki_prefix" => "3059301306072a8648ce3d020106082a8648ce3d030107034200",
    ],
    "p384" => [
        "field" => 48, "digest" => OPENSSL_ALGO_SHA384,
        "p" => "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
        "b" => "0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
        "n" => "0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
        "spki_prefix" => "3076301006072a8648ce3d0201060 5 2b81040022036200",
    ],
];

function der_int(string $b): string {
    $b = ltrim($b, "\x00");
    if ($b === "") $b = "\x00";
    if (ord($b[0]) & 0x80) $b = "\x00" . $b;
    return "\x02" . chr(strlen($b)) . $b;
}

function ecdsa_verify(string $curve, string $msg, string $sig, string $pub, bool $strict): bool {
    $cfg = $GLOBALS['CURVES'][$curve];
    $fs = $cfg["field"];
    if (strlen($sig) !== 2 * $fs) return false;
    $r = gmp_init(bin2hex(substr($sig, 0, $fs)), 16);
    $s = gmp_init(bin2hex(substr($sig, $fs, $fs)), 16);
    $n = gmp_init($cfg["n"], 0);
    if (gmp_cmp($r, 1) < 0 || gmp_cmp($r, gmp_sub($n, 1)) > 0) return false;
    if (gmp_cmp($s, 1) < 0 || gmp_cmp($s, gmp_sub($n, 1)) > 0) return false;
    if ($strict && gmp_cmp($s, gmp_div_q($n, 2)) > 0) return false;
    if (strlen($pub) !== 1 + 2 * $fs || ord($pub[0]) !== 0x04) return false;

    // explicit on-curve check: y^2 == x^3 - 3x + b (mod p)
    $p = gmp_init($cfg["p"], 0);
    $b = gmp_init($cfg["b"], 0);
    $x = gmp_init(bin2hex(substr($pub, 1, $fs)), 16);
    $y = gmp_init(bin2hex(substr($pub, 1 + $fs, $fs)), 16);
    $lhs = gmp_mod(gmp_mul($y, $y), $p);
    $rhs = gmp_mod(gmp_add(gmp_sub(gmp_mul(gmp_mul($x, $x), $x), gmp_mul(3, $x)), $b), $p);
    if (gmp_cmp($lhs, $rhs) !== 0) return false;

    $spki = hex2bin(str_replace(" ", "", $cfg["spki_prefix"])) . $pub;
    $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
    $key = openssl_pkey_get_public($pem);
    if ($key === false) return false;
    $der = der_int(substr($sig, 0, $fs)) . der_int(substr($sig, $fs, $fs));
    $der = "\x30" . chr(strlen($der)) . $der;
    return openssl_verify($msg, $der, $key, $cfg["digest"]) === 1;
}

// ================= driver =================
$path = $argv[1] ?? getenv("ALGOVOI_NEGATIVE_V1") ?: DEFAULT_PATH;
$corpus = json_decode(file_get_contents($path), true);
$total = 0; $matched = 0; $fails = [];
$record = function (bool $ok, string $section, array $c) use (&$total, &$matched, &$fails) {
    $total++;
    if ($ok) $matched++; else $fails[] = "[$section] " . ($c["note"] ?? "");
};

foreach ($corpus["signing_base"] as $c) {
    $want = base64_decode($c["signing_base_b64"]);
    try { $ok = $c["ok"] && build_signing_base($c["in"], $c["mode"], $c["signature_params_raw"] ?? null) === $want; }
    catch (\Throwable) { $ok = !$c["ok"]; }
    $record($ok, "signing_base", $c);
}
foreach ($corpus["signature_input_parse"] as $c) {
    try { parse_signature_input($c["header"]); $p = true; } catch (ParseErr) { $p = false; }
    $record($p === $c["ok"], "sig_input_parse", $c);
}
foreach ($corpus["signature_value_parse"] as $c) {
    try { parse_signature_value($c["header"]); $p = true; } catch (ParseErr) { $p = false; }
    $record($p === $c["ok"], "sig_value_parse", $c);
}
foreach ($corpus["keygate"] as $c) {
    $raw = hex2bin($c["pk_hex"]);
    try { check_ed25519_public_key($raw); $rej = null; } catch (WeakKeyErr) { $rej = "WeakKeyError"; }
    $record($rej === $c["rejected"] && small_order($raw) === $c["small_order"], "keygate", $c);
}
foreach ($corpus["ed25519_verify"] as $c) {
    $base = base64_decode($c["signing_base_b64"]);
    $valid = ed25519_verify($base, hex2bin($c["sig_hex"]), hex2bin($c["pk_hex"]));
    $record($valid === $c["expect_valid"], "ed25519_verify", $c);
}
foreach ($corpus["ecdsa_verify"] as $c) {
    $valid = ecdsa_verify($c["curve"], hex2bin($c["msg_hex"]), hex2bin($c["sig_raw_hex"]),
                          hex2bin($c["pub_uncompressed_hex"]), ($c["strict_low_s"] ?? false) === true);
    $record($valid === $c["expect_valid"], "ecdsa_verify", $c);
}

foreach ($fails as $f) echo "FAIL  $f\n";
echo "\nphp: $matched/$total cases matched\n";
exit($matched === $total ? 0 : 1);
