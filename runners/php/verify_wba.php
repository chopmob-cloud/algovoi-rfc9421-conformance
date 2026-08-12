<?php
// PHP runner for the Web Bot Auth profile corpus (webbotauth_v0).
//
// Self-contained PHP port of the Python reference runner
// (runners/python/verify_wba.py) and its independent KAT gate
// (tools/check_kat_wba.py). Every PROFILE rule (signing base, coverage
// completeness, freshness window, directory keyid resolution, Signature-Agent
// SSRF, and the Ed25519 signature verdict) is re-implemented here directly from
// the corpus `policy` block, NOT imported from a shared oracle, so a runner
// passing is genuine agreement rather than an echo. Ed25519 is verified with
// ext-sodium (sodium_crypto_sign_verify_detached) over the raw 32-byte key; the
// IPv4/IPv6 CIDR membership needed by the SSRF guard is hand-rolled with
// inet_pton + bitmask (PHP has no built-in CIDR support).
//
// Mirrors runners/python/verify_wba.py, runners/typescript/verify_wba.mjs and
// runners/go/verify_wba_go.go case for case.
//
//   php -d extension=sodium -d extension=gmp runners/php/verify_wba.php [corpus.json]
//
// Corpus path: argv[1], else ../../corpus/webbotauth_v0/webbotauth_v0.json
// relative to this runner. Exit 0 iff every case matches, else exit 1.

class SigningBaseError extends Exception {}

const DEFAULT_PATH = __DIR__ . "/../../corpus/webbotauth_v0/webbotauth_v0.json";

// ---------------------------------------------------------------------------
// Rule 1: RFC 9421 Section 2.5 signing base, by direct concatenation.
// Throws when a covered component's value is missing (build impossible).
// ---------------------------------------------------------------------------
function build_signing_base(array $in, ?string $params_raw): string {
    $lines = [];
    foreach ($in["covered_components"] as $component) {
        $name = strtolower((string)$component);
        switch ($name) {
            case "@authority":
                $val = $in["authority"] ?? null;
                break;
            case "@method":
                $val = $in["method"] ?? null;
                break;
            case "@path":
                $val = $in["path"] ?? null;
                break;
            default:
                $headers = $in["headers"] ?? [];
                $val = array_key_exists($name, $headers) ? $headers[$name] : null;
        }
        if ($val === null) throw new SigningBaseError("missing covered component: $name");
        $lines[] = "\"$name\": $val";
    }
    $lines[] = "\"@signature-params\": " . (string)$params_raw;
    return implode("\n", $lines);
}

// ---------------------------------------------------------------------------
// Rule 2: coverage completeness (every required component present, lowercased).
// ---------------------------------------------------------------------------
function coverage_ok(array $covered, array $policy): bool {
    $have = [];
    foreach ($covered as $c) $have[strtolower((string)$c)] = true;
    foreach ($policy["required_covered_components"] as $req) {
        if (!isset($have[strtolower((string)$req)])) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Rule 3: freshness window.  All three must be integers, expires > created,
// and (created - skew) <= now < expires.
// ---------------------------------------------------------------------------
function freshness_ok($created, $expires, $now, array $policy): bool {
    $skew = $policy["clock_skew_seconds"] ?? 0;
    if (!is_int($created) || !is_int($expires) || !is_int($now)) return false;
    if ($expires <= $created) return false;
    return ($created - $skew) <= $now && $now < $expires;
}

// ---------------------------------------------------------------------------
// Rule 4: directory keyid resolution to a usable Ed25519 JWK.
// ---------------------------------------------------------------------------
function directory_ok(array $directory, string $keyid): bool {
    foreach ($directory as $jwk) {
        if (($jwk["kid"] ?? null) === $keyid) {
            return ($jwk["kty"] ?? null) === "OKP"
                && ($jwk["crv"] ?? null) === "Ed25519"
                && (string)($jwk["x"] ?? "") !== "";
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// Rule 5: Signature-Agent SSRF guard.  Needs IPv4 AND IPv6 CIDR membership by
// bit masking on the inet_pton-packed bytes (PHP has no built-in CIDR support).
// ---------------------------------------------------------------------------

// Returns [version, packed_bytes] or null for a malformed address.
function parse_ip(string $s) {
    $packed = @inet_pton($s);
    if ($packed === false) return null;
    return [strlen($packed) === 4 ? 4 : 6, $packed];
}

// Returns [version, packed_bytes, prefix] or null for a malformed CIDR.
function parse_cidr(string $cidr) {
    $slash = strrpos($cidr, "/");
    if ($slash === false) return null;
    $ip = parse_ip(substr($cidr, 0, $slash));
    if ($ip === null) return null;
    $prefix_str = substr($cidr, $slash + 1);
    if ($prefix_str === "" || !ctype_digit($prefix_str)) return null;
    $prefix = (int)$prefix_str;
    $bits = $ip[0] === 4 ? 32 : 128;
    if ($prefix < 0 || $prefix > $bits) return null;
    return [$ip[0], $ip[1], $prefix];
}

// Same-version membership by prefix bitmask over the packed bytes.
function ip_in_net(array $addr, array $net): bool {
    if ($addr[0] !== $net[0]) return false;
    $a = $addr[1];
    $n = $net[1];
    $prefix = $net[2];
    $full_bytes = intdiv($prefix, 8);
    $rem = $prefix % 8;
    if ($full_bytes > 0 && substr($a, 0, $full_bytes) !== substr($n, 0, $full_bytes)) return false;
    if ($rem !== 0) {
        $mask = (0xFF << (8 - $rem)) & 0xFF;
        if ((ord($a[$full_bytes]) & $mask) !== (ord($n[$full_bytes]) & $mask)) return false;
    }
    return true;
}

function ssrf_ok(string $url, ?string $resolved_ip, array $policy): bool {
    $ssrf = $policy["ssrf"];
    $u = parse_url($url);
    if ($u === false) return false;
    $scheme = isset($u["scheme"]) ? strtolower($u["scheme"]) : "";
    if (($ssrf["require_https"] ?? true) && $scheme !== "https") return false;
    if (isset($u["user"]) || isset($u["pass"])) return false; // userinfo -> reject
    $host = $u["host"] ?? "";
    if ($host === "") return false;
    $host = trim($host, "[]"); // strip IPv6 literal brackets

    $addr = parse_ip($host);
    if ($addr === null) {
        // hostname is a domain -> rely on the resolved address
        if ($resolved_ip === null || $resolved_ip === "") return false;
        $addr = parse_ip($resolved_ip);
        if ($addr === null) return false;
    }
    foreach ($ssrf["denied_cidrs"] as $cidr) {
        $net = parse_cidr($cidr);
        if ($net !== null && $addr[0] === $net[0] && ip_in_net($addr, $net)) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Rule 6: Ed25519 verify of the raw signing-base bytes under a raw 32-byte key.
// ---------------------------------------------------------------------------
function ed25519_verify(string $msg, string $sig, string $pk): bool {
    if (strlen($sig) !== 64 || strlen($pk) !== 32) return false;
    try {
        return sodium_crypto_sign_verify_detached($sig, $msg, $pk);
    } catch (\Throwable $e) {
        return false;
    }
}

// ---------------------------------------------------------------------------
// Driver.
// ---------------------------------------------------------------------------
$path = $argv[1] ?? DEFAULT_PATH;
$corpus = json_decode(file_get_contents($path), true);
$policy = $corpus["policy"];

$results = [];
$rec = function (string $section, string $note, bool $ok) use (&$results) {
    $results[] = [$section, $note, $ok];
};

// 1. wba_signing_base
foreach ($corpus["wba_signing_base"] as $c) {
    $decoded = base64_decode($c["signing_base_b64"]);
    // Build FIRST; `$c["ok"] && build(...)` would short-circuit negative cases
    // and never exercise the build-failure path.
    try {
        $built = build_signing_base($c["in"], $c["signature_params_raw"] ?? null);
        $ok = ($c["ok"] === true) && $built === $decoded;
    } catch (\Throwable $e) {
        $ok = !$c["ok"];
    }
    $rec("wba_signing_base", $c["note"], $ok);
}

// 2. wba_coverage
foreach ($corpus["wba_coverage"] as $c) {
    $rec("wba_coverage", $c["note"],
        coverage_ok($c["covered_components"], $policy) === $c["expect_accept"]);
}

// 3. wba_freshness
foreach ($corpus["wba_freshness"] as $c) {
    $rec("wba_freshness", $c["note"],
        freshness_ok($c["created"], $c["expires"], $c["now"], $policy) === $c["expect_accept"]);
}

// 4. wba_directory
foreach ($corpus["wba_directory"] as $c) {
    $rec("wba_directory", $c["note"],
        directory_ok($c["directory"], $c["keyid"]) === $c["expect_accept"]);
}

// 5. wba_directory_ssrf
foreach ($corpus["wba_directory_ssrf"] as $c) {
    $rec("wba_directory_ssrf", $c["note"],
        ssrf_ok($c["signature_agent_url"], $c["resolved_ip"] ?? null, $policy) === $c["expect_fetch_allowed"]);
}

// 6. wba_ed25519_verify
foreach ($corpus["wba_ed25519_verify"] as $c) {
    $base = base64_decode($c["signing_base_b64"]);
    $valid = ed25519_verify($base, hex2bin($c["sig_hex"]), hex2bin($c["pk_hex"]));
    $rec("wba_ed25519_verify", $c["note"], $valid === $c["expect_valid"]);
}

$fails = 0;
foreach ($results as [$section, $note, $ok]) {
    if (!$ok) {
        echo "FAIL  [$section] $note\n";
        $fails++;
    }
}
$total = count($results);
echo "\nphp (wba): " . ($total - $fails) . "/$total cases matched\n";
exit($fails === 0 ? 0 : 1);
