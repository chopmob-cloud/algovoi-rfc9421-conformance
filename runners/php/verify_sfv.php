<?php
// PHP runner for the Structured Field Values corpus (sfv_v0).
//
// Independently reproduces every verdict in the frozen corpus: parse `input` as
// its declared field type (item|list|dictionary), and if it parses, serialize it
// canonically (RFC 8941 Section 4.1) and compare to the frozen `canonical`. A case
// matches iff parse_ok == expect_parse_ok and, when ok, the canonical bytes are
// equal.
//
// Parsing and canonical serialization use the third-party RFC 8941 library
// bakame/http-structured-fields, so a pass is genuine agreement with an
// independent implementation, not an echo of the generator's oracle. That library
// silently repairs a non-canonically-padded Byte Sequence (e.g. ":aGVsbG8:"),
// which RFC 8941 and the frozen corpus reject; a small strict pre-check
// (strict_bytes_ok) rejects any input carrying a non-canonical base64 Byte
// Sequence before delegating, so the runner matches the corpus byte-for-byte.
//
//   php runners/php/verify_sfv.php [corpus.json]
//
// The composer autoloader is discovered from ./vendor or $SFV_VENDOR. Corpus
// path: argv[1], else ../../corpus/sfv_v0/sfv_v0.json. Exit 0 iff all match.

foreach ([getenv("SFV_VENDOR"), __DIR__ . "/vendor/autoload.php",
          getcwd() . "/vendor/autoload.php", "/tmp/sfv/vendor/autoload.php"] as $cand) {
    if ($cand && is_file($cand)) { require $cand; break; }
}

use Bakame\Http\StructuredFields\Item;
use Bakame\Http\StructuredFields\OuterList;
use Bakame\Http\StructuredFields\Dictionary;

const DEFAULT_PATH = __DIR__ . "/../../corpus/sfv_v0/sfv_v0.json";
const SECTIONS = ["sfv_item", "sfv_list", "sfv_dictionary",
                  "sfv_parameters", "sfv_canonical", "sfv_reject"];

// A byte sequence's base64 must be canonical: length a multiple of 4 and padding
// only in the final one or two positions (mirrors python base64 validate=True).
function b64_canonical(string $content): bool {
    if (strlen($content) % 4 !== 0) return false;
    $pad = 0;
    $len = strlen($content);
    for ($k = 0; $k < $len; $k++) {
        $c = $content[$k];
        if ($c === "=") {
            $pad++;
            if ($k < $len - 2) return false;
        } else {
            if ($pad > 0) return false;
            if (!ctype_alnum($c) && $c !== "+" && $c !== "/") return false;
        }
    }
    return true;
}

function is_token_tail(string $c): bool {
    return ctype_alnum($c) || strpos("!#$%&'*+-.^_`|~:/", $c) !== false;
}

// Reject the whole input if any Byte Sequence token carries non-canonical base64.
// Strings are skipped and tokens consumed whole (Tokens may contain ':'), so the
// only ':' this sees begins a Byte Sequence at a bare-item position.
function strict_bytes_ok(string $s): bool {
    $i = 0;
    $n = strlen($s);
    while ($i < $n) {
        $c = $s[$i];
        if ($c === '"') {
            $i++;
            while ($i < $n) {
                if ($s[$i] === "\\") { $i += 2; continue; }
                if ($s[$i] === '"') { $i++; break; }
                $i++;
            }
        } elseif (ctype_alpha($c) || $c === "*") {
            $i++;
            while ($i < $n && is_token_tail($s[$i])) $i++;
        } elseif ($c === ":") {
            $start = $i + 1;
            $j = $start;
            while ($j < $n && $s[$j] !== ":") $j++;
            if ($j >= $n) return true; // unterminated: let the library reject
            if (!b64_canonical(substr($s, $start, $j - $start))) return false;
            $i = $j + 1;
        } else {
            $i++;
        }
    }
    return true;
}

function verdict(string $fieldType, string $input): array {
    if (!strict_bytes_ok($input)) return [false, null];
    try {
        switch ($fieldType) {
            case "item":       $canon = Item::fromHttpValue($input)->toHttpValue(); break;
            case "list":       $canon = OuterList::fromHttpValue($input)->toHttpValue(); break;
            case "dictionary": $canon = Dictionary::fromHttpValue($input)->toHttpValue(); break;
            default: return [false, null];
        }
        return [true, $canon];
    } catch (\Throwable $e) {
        return [false, null];
    }
}

$path = $argv[1] ?? DEFAULT_PATH;
$corpus = json_decode(file_get_contents($path), true);

$total = 0;
$matched = 0;
$fails = [];
foreach (SECTIONS as $sec) {
    foreach ($corpus[$sec] ?? [] as $c) {
        [$ok, $canon] = verdict($c["field_type"], $c["input"]);
        $match = ($ok === $c["expect_parse_ok"]) && (!$ok || $canon === ($c["canonical"] ?? null));
        $total++;
        if ($match) $matched++;
        else $fails[] = "[$sec] " . ($c["note"] ?? "");
    }
}
foreach ($fails as $f) echo "FAIL  $f\n";
echo "\nphp (sfv): $matched/$total cases matched\n";
exit($matched === $total ? 0 : 1);
