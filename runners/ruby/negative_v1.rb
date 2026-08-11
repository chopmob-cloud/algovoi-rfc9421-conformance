#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Ruby runner for the rfc9421_negative_v1 CORE cross-language battery.
#
# Independent Ruby port of the verdict surface (signing_base.py, parse.py,
# keycheck.py, verify.py + the algovoi-rfc9421-ecdsa provider). Self-contained
# (no Ruby RFC 9421 verifier exists); must produce byte-identical verdicts to
# every other runner. Ed25519 verify via OpenSSL (key built from a hand-assembled
# SPKI DER, since OpenSSL 3.0 here has no new_raw_public_key), with an explicit
# canonical-S (S < L) malleability check and the ported small-order / non-canonical
# key gate applied fail-closed first. ECDSA P-256/P-384 via OpenSSL with explicit
# range / width / on-curve / strict-low-s checks.
#
# Corpus path: ARGV[0], else $ALGOVOI_NEGATIVE_V1, else the sibling repo default.

require "json"
require "base64"
require "openssl"

DEFAULT_PATH = "../../corpus/rfc9421_negative_v1/rfc9421_negative_v1.json"

class SigningBaseError < StandardError; end
class ParseError < StandardError; end
class WeakKeyError < StandardError; end

# ================= signing base (port of signing_base.py) =================
def build_signing_base(input, mode, sig_params_raw)
  raise SigningBaseError, "bad mode" unless %w[algovoi-v0 rfc9421].include?(mode)
  raise SigningBaseError, "rfc9421 mode requires signature_params_raw" if mode == "rfc9421" && sig_params_raw.nil?

  headers = {}
  (input["headers"] || {}).each { |k, v| headers[k.downcase] = v }
  params = input["parameters"] || {}

  str_or_throw = lambda do |field, msg|
    v = input[field]
    raise SigningBaseError, msg if v.nil?
    v
  end
  param_str_or_throw = lambda do |key, msg|
    raise SigningBaseError, msg unless params.key?(key)
    params[key].to_s
  end

  lines = []
  input["covered_components"].each do |component|
    c = component.downcase
    value =
      case c
      when "@method"
        v = str_or_throw.call("method", "@method covered but method not supplied")
        mode == "rfc9421" ? v : v.downcase
      when "@authority"
        str_or_throw.call("authority", "@authority covered but authority not supplied").downcase
      when "@path"
        str_or_throw.call("path", "@path covered but path not supplied")
      when "@target-uri"
        str_or_throw.call("target_uri", "@target-uri covered but target_uri not supplied")
      when "@scheme"
        str_or_throw.call("scheme", "@scheme covered but scheme not supplied").downcase
      when "@status"
        raise SigningBaseError, "@status covered but status not supplied" if input["status"].nil?
        input["status"].to_s
      when "created"
        param_str_or_throw.call("created", "'created' covered but no 'created' parameter in Signature-Input")
      when "expires"
        param_str_or_throw.call("expires", "'expires' covered but no 'expires' parameter in Signature-Input")
      else
        raise SigningBaseError, "unsupported derived component: #{component}" if c.start_with?("@")
        raise SigningBaseError, "covered header #{component} not present" unless headers.key?(c)
        headers[c]
      end
    lines << "\"#{c}\": #{value}"
  end
  lines << "\"@signature-params\": #{sig_params_raw}" if mode == "rfc9421"
  lines.join("\n")
end

# ================= structured-field parse (port of parse.py) =================
LABEL_RE = /\A\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*/
COVERED_RE = /\A\(\s*(?:"[^"]*"\s*)*\)/

def parse_signature_input(header)
  raise ParseError, "header must be str" if header.nil?
  hv = header.strip
  raise ParseError, "empty header value" if hv.empty?
  if (m = LABEL_RE.match(hv))
    rest = hv[m.end(0)..]
  elsif hv.start_with?("(")
    rest = hv
  else
    raise ParseError, "no label or covered-components list found at start"
  end
  raise ParseError, "no covered-components list found" unless COVERED_RE.match?(rest)
end

def parse_signature_value(header)
  raise ParseError, "header must be str" if header.nil?
  hv = header.strip
  raise ParseError, "empty Signature header value" if hv.empty?
  if (m = LABEL_RE.match(hv))
    rest = hv[m.end(0)..].strip
  elsif hv.start_with?(":")
    rest = hv
  else
    raise ParseError, "no label or signature-value prefix found at start"
  end
  raise ParseError, "signature value must be wrapped in colons" unless rest.start_with?(":") && rest.end_with?(":") && rest.length >= 2
  sig_b64 = rest[1..-2]
  begin
    decoded = Base64.strict_decode64(sig_b64)
  rescue ArgumentError
    raise ParseError, "signature value is not valid base64"
  end
  raise ParseError, "non-canonical base64" unless Base64.strict_encode64(decoded) == sig_b64
end

# ================= Ed25519 key gate (port of keycheck.py) =================
P = 2**255 - 19
D = (-121665 * 121666.pow(P - 2, P)) % P
SQRT_M1 = 2.pow((P - 1) / 4, P)
L_ORDER = 2**252 + 27_742_317_777_372_353_535_851_937_790_883_648_493

def recover_x(y, sign)
  return nil if y >= P
  y2 = (y * y) % P
  x2 = ((y2 - 1) * (D * y2 + 1).pow(P - 2, P)) % P
  return (sign == 1 ? nil : 0) if x2.zero?
  x = x2.pow((P + 3) / 8, P)
  x = (x * SQRT_M1) % P unless ((x * x - x2) % P).zero?
  return nil unless ((x * x - x2) % P).zero?
  x = P - x if (x & 1) != sign
  x
end

def decode_point(pk)
  return nil unless pk.bytesize == 32
  full = pk.reverse.unpack1("H*").to_i(16)
  sign = (full >> 255) & 1
  y = full & ((1 << 255) - 1)
  x = recover_x(y, sign)
  return nil if x.nil?
  [x, y, 1, (x * y) % P]
end

def point_add(p, q)
  a = ((p[1] - p[0]) * (q[1] - q[0])) % P
  b = ((p[1] + p[0]) * (q[1] + q[0])) % P
  c = (2 * p[3] * q[3] * D) % P
  dd = (2 * p[2] * q[2]) % P
  e = b - a; f = dd - c; g = dd + c; h = b + a
  [(e * f) % P, (g * h) % P, (f * g) % P, (e * h) % P]
end

def mul8(p)
  p2 = point_add(p, p); p4 = point_add(p2, p2); point_add(p4, p4)
end

def identity?(p)
  (p[0] % P).zero? && ((p[1] - p[2]) % P).zero?
end

def small_order?(pk)
  p = decode_point(pk)
  return false if p.nil?
  identity?(mul8(p))
end

def check_ed25519_public_key(pk)
  p = decode_point(pk)
  raise WeakKeyError, "non-canonical/off-curve" if p.nil?
  raise WeakKeyError, "small-order" if identity?(mul8(p))
end

# ================= Ed25519 verify (port of verify.py) =================
def ed25519_verify(msg, sig, pk)
  return false unless sig.bytesize == 64
  return false unless pk.bytesize == 32
  begin
    check_ed25519_public_key(pk)
  rescue WeakKeyError
    return false
  end
  # canonical-S: reject S >= L (Ed25519 signature malleability)
  s = sig[32, 32].reverse.unpack1("H*").to_i(16)
  return false if s >= L_ORDER
  begin
    der = ["302a300506032b6570032100"].pack("H*") + pk
    key = OpenSSL::PKey.read(der)
    key.verify(nil, sig, msg)
  rescue StandardError
    false
  end
end

# ================= ECDSA verify (port of algovoi-rfc9421-ecdsa) =================
def ecdsa_verify(curve, msg, sig_raw, pub, strict_low_s)
  field_size = curve == "p256" ? 32 : 48
  group_name = curve == "p256" ? "prime256v1" : "secp384r1"
  digest = curve == "p256" ? "SHA256" : "SHA384"
  return false unless sig_raw.bytesize == 2 * field_size

  r = sig_raw[0, field_size].unpack1("H*").to_i(16)
  s = sig_raw[field_size, field_size].unpack1("H*").to_i(16)
  group = OpenSSL::PKey::EC::Group.new(group_name)
  n = group.order.to_i
  return false unless r.between?(1, n - 1) && s.between?(1, n - 1)
  return false if strict_low_s && s > n / 2
  return false unless pub.bytesize == 1 + 2 * field_size && pub.bytes[0] == 0x04

  begin
    # Point.new validates the point is on the curve (raises otherwise)
    OpenSSL::PKey::EC::Point.new(group, OpenSSL::BN.new(pub.unpack1("H*"), 16))
    spki = OpenSSL::ASN1::Sequence([
      OpenSSL::ASN1::Sequence([
        OpenSSL::ASN1::ObjectId("id-ecPublicKey"),
        OpenSSL::ASN1::ObjectId(group_name)
      ]),
      OpenSSL::ASN1::BitString(pub)
    ])
    key = OpenSSL::PKey.read(spki.to_der)
    der = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(r), OpenSSL::ASN1::Integer(s)]).to_der
    key.verify(OpenSSL::Digest.new(digest), der, msg)
  rescue StandardError
    false
  end
end

# ================= driver =================
def hexb(s) = [s].pack("H*")

path = ARGV[0] || ENV["ALGOVOI_NEGATIVE_V1"] || DEFAULT_PATH
corpus = JSON.parse(File.read(path))
total = 0
matched = 0
fails = []

record = lambda do |ok, section, c|
  total += 1
  if ok
    matched += 1
  else
    fails << "[#{section}] #{c['note']}"
  end
end

corpus["signing_base"].each do |c|
  want = Base64.decode64(c["signing_base_b64"]).force_encoding("UTF-8")
  ok =
    begin
      c["ok"] && build_signing_base(c["in"], c["mode"], c["signature_params_raw"]) == want
    rescue StandardError
      !c["ok"]
    end
  record.call(ok, "signing_base", c)
end
corpus["signature_input_parse"].each do |c|
  parsed_ok = begin; parse_signature_input(c["header"]); true; rescue ParseError; false; end
  record.call(parsed_ok == c["ok"], "sig_input_parse", c)
end
corpus["signature_value_parse"].each do |c|
  parsed_ok = begin; parse_signature_value(c["header"]); true; rescue ParseError; false; end
  record.call(parsed_ok == c["ok"], "sig_value_parse", c)
end
corpus["keygate"].each do |c|
  raw = hexb(c["pk_hex"])
  rejected = begin; check_ed25519_public_key(raw); nil; rescue WeakKeyError; "WeakKeyError"; end
  record.call(rejected == c["rejected"] && small_order?(raw) == c["small_order"], "keygate", c)
end
corpus["ed25519_verify"].each do |c|
  base = Base64.decode64(c["signing_base_b64"])
  valid = ed25519_verify(base, hexb(c["sig_hex"]), hexb(c["pk_hex"]))
  record.call(valid == c["expect_valid"], "ed25519_verify", c)
end
corpus["ecdsa_verify"].each do |c|
  valid = ecdsa_verify(c["curve"], hexb(c["msg_hex"]), hexb(c["sig_raw_hex"]),
                       hexb(c["pub_uncompressed_hex"]), c["strict_low_s"] == true)
  record.call(valid == c["expect_valid"], "ecdsa_verify", c)
end

fails.each { |f| puts "FAIL  #{f}" }
puts "\nruby: #{matched}/#{total} cases matched"
exit(matched == total ? 0 : 1)
