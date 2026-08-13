<?php
// PHP runner for the COSE_Sign1 corpus (cose_v0).
//
// Independent PHP port of the Python reference runner (runners/python/verify_cose.py)
// and its decision surface (tools/oracle_cose.py). Parses each COSE_Sign1 (CBOR array
// of 4, tagged 18 or untagged), applies the COSE security gates in order (protected
// header deterministically encoded per RFC 8949 Section 4.2, alg (label 1) present in
// the protected header, an unknown crit (label 2) label rejected, alg/key-type match),
// builds the Sig_structure ["Signature1", protected, h'', payload] in deterministic
// CBOR and verifies the ES256 / EdDSA / PS256 signature. For the deterministic-CBOR
// section it decides whether the datum is RFC 8949 Section 4.2 canonical. Low-s is NOT
// enforced (a COSE base rule, not a FAPI rule).
//
// The CBOR codec is hand-rolled (a minimal decoder plus an RFC 8949 Section 4.2
// canonical encoder) so the deterministic judgement and the Sig_structure bytes are
// byte-identical to the frozen corpus, independent of any CBOR library's default
// map-key ordering (bytewise-lexicographic, not length-first).
//
// ES256 (ECDSA P-256) via ext-openssl; EdDSA (Ed25519) via ext-sodium; PS256
// (RSA-PSS SHA-256, salt 32) via a self-contained EMSA-PSS-VERIFY (RFC 8017) over the
// RSA public op (ext-gmp), since PHP's openssl_verify has no RSA-PSS mode. Public keys
// are rebuilt from the hex COSE key material. Needs ext-openssl + ext-sodium + ext-gmp.
//
// Corpus path: argv[1], else the sibling repo default.

const DEFAULT_PATH = __DIR__ . "/../../corpus/cose_v0/cose_v0.json";

const SECTIONS = ["cose_sig_structure", "cose_deterministic_cbor", "cose_protected_header",
    "cose_es256_verify", "cose_eddsa_verify", "cose_ps256_verify", "cose_crit"];

const COSE_SIGN1_TAG = 18;
const ALG_KTY = [-7 => "EC2", -8 => "OKP", -37 => "RSA"];
const KNOWN_LABELS = [1, 2, 3, 4, 5];
const P256_SPKI_PREFIX = "3059301306072a8648ce3d020106082a8648ce3d030107034200";

class CborError extends Exception {}

// ---------------------------------------------------------------------------
// Minimal CBOR decode (permissive) + RFC 8949 Section 4.2 canonical encode.
// A value is an array: ["int", n] ["bytes", s] ["text", s] ["array", [..]]
// ["map", [[k,v]..]] ["null"] ["tag", n, v] ["bool", b]
// ---------------------------------------------------------------------------
function cbor_decode(string $buf, int $pos): array {
    if ($pos >= strlen($buf)) throw new CborError("truncated");
    $ib = ord($buf[$pos]); $pos++;
    $major = $ib >> 5; $ai = $ib & 0x1f;
    if ($ai < 24) { $arg = $ai; }
    elseif ($ai === 24) { if ($pos + 1 > strlen($buf)) throw new CborError("t"); $arg = ord($buf[$pos]); $pos++; }
    elseif ($ai === 25) { if ($pos + 2 > strlen($buf)) throw new CborError("t"); $arg = (ord($buf[$pos]) << 8) | ord($buf[$pos+1]); $pos += 2; }
    elseif ($ai === 26) { if ($pos + 4 > strlen($buf)) throw new CborError("t"); $arg = 0; for ($i=0;$i<4;$i++) $arg = ($arg << 8) | ord($buf[$pos+$i]); $pos += 4; }
    elseif ($ai === 27) { if ($pos + 8 > strlen($buf)) throw new CborError("t"); $arg = 0; for ($i=0;$i<8;$i++) $arg = ($arg << 8) | ord($buf[$pos+$i]); $pos += 8; }
    elseif ($ai === 31) { if ($major < 2 || $major > 5) throw new CborError("indef"); return cbor_decode_indefinite($buf, $pos, $major); }
    else { throw new CborError("reserved"); }

    switch ($major) {
        case 0: return [["int", $arg], $pos];
        case 1: return [["int", -1 - $arg], $pos];
        case 2: if ($pos + $arg > strlen($buf)) throw new CborError("t"); return [["bytes", substr($buf, $pos, $arg)], $pos + $arg];
        case 3: if ($pos + $arg > strlen($buf)) throw new CborError("t"); return [["text", substr($buf, $pos, $arg)], $pos + $arg];
        case 4:
            $items = [];
            for ($i = 0; $i < $arg; $i++) { [$v, $pos] = cbor_decode($buf, $pos); $items[] = $v; }
            return [["array", $items], $pos];
        case 5:
            $pairs = [];
            for ($i = 0; $i < $arg; $i++) { [$k, $pos] = cbor_decode($buf, $pos); [$v, $pos] = cbor_decode($buf, $pos); $pairs[] = [$k, $v]; }
            return [["map", $pairs], $pos];
        case 6: [$inner, $pos] = cbor_decode($buf, $pos); return [["tag", $arg, $inner], $pos];
        case 7:
            if ($ai === 22) return [["null"], $pos];
            if ($ai === 20) return [["bool", false], $pos];
            if ($ai === 21) return [["bool", true], $pos];
            throw new CborError("simple/float");
        default: throw new CborError("major");
    }
}

function cbor_decode_indefinite(string $buf, int $pos, int $major): array {
    if ($major === 2 || $major === 3) {
        $acc = "";
        while (true) {
            if ($pos >= strlen($buf)) throw new CborError("t");
            if (ord($buf[$pos]) === 0xff) { $pos++; break; }
            [$chunk, $pos] = cbor_decode($buf, $pos);
            if ($chunk[0] !== ($major === 2 ? "bytes" : "text")) throw new CborError("chunk");
            $acc .= $chunk[1];
        }
        return [[$major === 2 ? "bytes" : "text", $acc], $pos];
    }
    if ($major === 4) {
        $items = [];
        while (true) {
            if ($pos >= strlen($buf)) throw new CborError("t");
            if (ord($buf[$pos]) === 0xff) { $pos++; break; }
            [$v, $pos] = cbor_decode($buf, $pos); $items[] = $v;
        }
        return [["array", $items], $pos];
    }
    $pairs = [];
    while (true) {
        if ($pos >= strlen($buf)) throw new CborError("t");
        if (ord($buf[$pos]) === 0xff) { $pos++; break; }
        [$k, $pos] = cbor_decode($buf, $pos); [$v, $pos] = cbor_decode($buf, $pos);
        $pairs[] = [$k, $v];
    }
    return [["map", $pairs], $pos];
}

function cbor_head(int $major, int $n): string {
    $base = $major << 5;
    if ($n < 24) return chr($base | $n);
    if ($n < 0x100) return chr($base | 24) . chr($n);
    if ($n < 0x10000) return chr($base | 25) . chr(($n >> 8) & 0xff) . chr($n & 0xff);
    if ($n < 0x100000000) return chr($base | 26) . chr(($n >> 24) & 0xff) . chr(($n >> 16) & 0xff) . chr(($n >> 8) & 0xff) . chr($n & 0xff);
    $out = chr($base | 27);
    for ($i = 7; $i >= 0; $i--) $out .= chr(($n >> (8 * $i)) & 0xff);
    return $out;
}

function cbor_encode(array $val): string {
    switch ($val[0]) {
        case "int": return $val[1] >= 0 ? cbor_head(0, $val[1]) : cbor_head(1, -1 - $val[1]);
        case "bytes": return cbor_head(2, strlen($val[1])) . $val[1];
        case "text": return cbor_head(3, strlen($val[1])) . $val[1];
        case "array":
            $out = cbor_head(4, count($val[1]));
            foreach ($val[1] as $x) $out .= cbor_encode($x);
            return $out;
        case "map":
            $enc = [];
            foreach ($val[1] as [$k, $v]) $enc[] = [cbor_encode($k), cbor_encode($v)];
            usort($enc, fn($a, $b) => strcmp($a[0], $b[0]));
            $out = cbor_head(5, count($enc));
            foreach ($enc as [$k, $v]) $out .= $k . $v;
            return $out;
        case "null": return "\xf6";
        default: throw new CborError("encode");
    }
}

function is_deterministic(string $buf): bool {
    try {
        [$value, $np] = cbor_decode($buf, 0);
    } catch (CborError $e) {
        return false;
    }
    if ($np !== strlen($buf)) return false;
    if ($value[0] === "tag") return false;
    try {
        return cbor_encode($value) === $buf;
    } catch (CborError $e) {
        return false;
    }
}

function map_get(array $m, int $key) {
    foreach ($m[1] as [$k, $v]) if ($k[0] === "int" && $k[1] === $key) return $v;
    return null;
}

// ---------------------------------------------------------------------------
// COSE_Sign1 parse + gates
// ---------------------------------------------------------------------------
function parse_sign1(string $buf) {
    try {
        [$top, ] = cbor_decode($buf, 0);
    } catch (CborError $e) {
        return null;
    }
    $arr = $top;
    if ($top[0] === "tag") {
        if ($top[1] !== COSE_SIGN1_TAG) return null;
        $arr = $top[2];
    }
    if ($arr[0] !== "array" || count($arr[1]) !== 4) return null;
    [$protected, $uhdr, $payload, $sig] = $arr[1];
    if ($protected[0] !== "bytes") return null;
    if ($uhdr[0] !== "map") return null;
    if ($payload[0] !== "bytes" && $payload[0] !== "null") return null;
    if ($sig[0] !== "bytes") return null;
    if (strlen($protected[1]) === 0) {
        $phdr = ["map", []];
    } else {
        if (!is_deterministic($protected[1])) return null;
        try {
            [$dec, ] = cbor_decode($protected[1], 0);
        } catch (CborError $e) {
            return null;
        }
        if ($dec[0] !== "map") return null;
        $phdr = $dec;
    }
    $pl = $payload[0] === "bytes" ? $payload[1] : "";
    return ["protected" => $protected[1], "phdr" => $phdr, "payload" => $pl, "sig" => $sig[1]];
}

function sig_structure(string $protected, string $payload): string {
    return cbor_encode(["array", [
        ["text", "Signature1"],
        ["bytes", $protected],
        ["bytes", ""],
        ["bytes", $payload],
    ]]);
}

// ---------------------------------------------------------------------------
// Signature verification per algorithm
// ---------------------------------------------------------------------------
function der_int_raw(string $b): string {
    $b = ltrim($b, "\x00");
    if ($b === "") $b = "\x00";
    if (ord($b[0]) & 0x80) $b = "\x00" . $b;
    return "\x02" . chr(strlen($b)) . $b;
}

function verify_es256(array $key, string $preimage, string $sig): bool {
    if (strlen($sig) !== 64) return false;
    $x = hex2bin($key["x"]); $y = hex2bin($key["y"]);
    if ($x === false || $y === false || strlen($x) !== 32 || strlen($y) !== 32) return false;
    $uncompressed = "\x04" . $x . $y;
    $spki = hex2bin(P256_SPKI_PREFIX) . $uncompressed;
    $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
    $pub = openssl_pkey_get_public($pem); // rejects an off-curve point at load
    if ($pub === false) return false;
    $der = der_int_raw(substr($sig, 0, 32)) . der_int_raw(substr($sig, 32, 32));
    $der = "\x30" . chr(strlen($der)) . $der;
    return openssl_verify($preimage, $der, $pub, OPENSSL_ALGO_SHA256) === 1;
}

function verify_eddsa(array $key, string $preimage, string $sig): bool {
    $pk = hex2bin($key["x"]);
    if ($pk === false || strlen($pk) !== 32 || strlen($sig) !== 64) return false;
    try {
        return sodium_crypto_sign_verify_detached($sig, $preimage, $pk);
    } catch (\Throwable $e) {
        return false;
    }
}

// ---- PS256 = RSA-PSS SHA-256 salt 32, hand-rolled EMSA-PSS-VERIFY (RFC 8017) ----
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
function verify_ps256(array $key, string $preimage, string $sig): bool {
    $nbin = hex2bin($key["n"]); $ebin = hex2bin($key["e"]);
    if ($nbin === false || $ebin === false) return false;
    $n = gmp_import($nbin); $e = gmp_import($ebin); $s = gmp_import($sig);
    if (gmp_cmp($s, $n) >= 0) return false;
    $modBits = strlen(gmp_strval($n, 2));
    $emBits = $modBits - 1; $emLen = intdiv($emBits + 7, 8);
    $EM = str_pad(gmp_export(gmp_powm($s, $e, $n)), $emLen, "\x00", STR_PAD_LEFT);
    return emsa_pss_verify_sha256($preimage, $EM, $emBits, 32);
}

function verdict(string $buf, array $key): bool {
    $parsed = parse_sign1($buf);
    if ($parsed === null) return false;
    $alg = map_get($parsed["phdr"], 1);
    if ($alg === null || $alg[0] !== "int") return false;
    $crit = map_get($parsed["phdr"], 2);
    if ($crit !== null) {
        if ($crit[0] !== "array" || count($crit[1]) === 0) return false;
        foreach ($crit[1] as $l) if ($l[0] !== "int" || !in_array($l[1], KNOWN_LABELS, true)) return false;
    }
    if (!array_key_exists($alg[1], ALG_KTY)) return false;
    if (($key["kty"] ?? null) !== ALG_KTY[$alg[1]]) return false;
    $preimage = sig_structure($parsed["protected"], $parsed["payload"]);
    return match ($alg[1]) {
        -7 => verify_es256($key, $preimage, $parsed["sig"]),
        -8 => verify_eddsa($key, $preimage, $parsed["sig"]),
        -37 => verify_ps256($key, $preimage, $parsed["sig"]),
        default => false,
    };
}

$path = $argv[1] ?? DEFAULT_PATH;
$corpus = json_decode(file_get_contents($path), true);
$material = $corpus["keys"];
$results = [];
foreach (SECTIONS as $sec) {
    foreach (($corpus[$sec] ?? []) as $c) {
        if ($sec === "cose_deterministic_cbor") {
            $accept = is_deterministic(hex2bin($c["cbor_hex"]));
        } else {
            $accept = verdict(hex2bin($c["cose_hex"]), $material[$c["key"]]);
        }
        $results[] = [$sec, $c["note"], $accept === $c["expect_valid"]];
    }
}
$fails = 0;
foreach ($results as [$section, $note, $ok]) {
    if (!$ok) { echo "FAIL  [$section] $note\n"; $fails++; }
}
$total = count($results);
echo "\nphp (cose): " . ($total - $fails) . "/$total cases matched\n";
exit($fails === 0 ? 0 : 1);
