#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Ruby reference runner for the FAPI 2.0 Message Signing corpus (fapi_messagesigning_v0).
#
# Independently reproduces every verdict in the frozen corpus. The RFC 9421
# Section 2.5 signing base is hand-assembled here; the PROFILE rules (mandated
# covered-component completeness, Content-Digest (RFC 9530) body binding,
# PS256/ES256 algorithm restriction) and the PS256/ES256 crypto are re-derived
# from the corpus `policy` block read at RUNTIME, NOT imported from the
# generator's oracle, so a runner passing is genuine agreement rather than an
# echo. Mirrors the Python reference runner (runners/python/verify_fapi.py)
# case for case.
#
# Self-contained: Ruby standard library only (json, base64, openssl, digest).
# RSA-PSS-SHA256 (PS256) and ECDSA P-256 (ES256, strict low-s) via OpenSSL; the
# EC public key is rebuilt from the uncompressed point and the raw r||s signature
# is re-encoded to DER for verification.
#
# Exit 0 iff every case matches. Corpus path: ARGV[0], else the repo corpus
# relative to this source file's directory (runners/ruby).
#
# Run:  ruby runners/ruby/verify_fapi.rb [corpus.json]

require "json"
require "base64"
require "openssl"
require "digest"

DEFAULT_PATH = "../../corpus/fapi_messagesigning_v0/fapi_messagesigning_v0.json"

class BuildError < StandardError; end

# ---- Section 1: RFC 9421 Section 2.5 signing base, by direct concatenation ----
# Raises BuildError when a covered component's value is missing (build impossible).
def fapi_signing_base(src, signature_params_raw)
  headers = {}
  (src["headers"] || {}).each { |k, v| headers[k.downcase] = v }

  lines = []
  (src["covered_components"] || []).each do |comp|
    name = comp.downcase
    val =
      case name
      when "@method"     then src["method"]
      when "@target-uri" then src["target_uri"]
      when "@status"     then src["status"].nil? ? nil : src["status"].to_s
      when "@authority"  then src["authority"]
      when "@path"       then src["path"]
      else headers[name]
      end
    raise BuildError, "missing covered component: #{name}" if val.nil?
    lines << "\"#{name}\": #{val}"
  end
  lines << "\"@signature-params\": #{signature_params_raw}"
  lines.join("\n")
end

# ---- Section 2: required covered-component completeness ----
def required_coverage_ok(message_type, covered, policy)
  key = message_type == "request" ? "required_covered_request" : "required_covered_response"
  have = (covered || []).map(&:downcase)
  policy[key].all? { |r| have.include?(r.downcase) }
end

# ---- Section 3: Content-Digest (RFC 9530) body binding ----
def content_digest_ok(body_b64, header_value, covered, policy)
  return false unless (covered || []).map(&:downcase).include?("content-digest")
  algorithm, rest = header_value.split("=", 2)
  return false if rest.nil?
  algorithm = algorithm.strip.downcase
  return false unless policy["content_digest_algorithms"].include?(algorithm)
  body = Base64.decode64(body_b64)
  digest = algorithm == "sha-256" ? Digest::SHA256.digest(body) : Digest::SHA512.digest(body)
  expect = "#{algorithm}=:#{Base64.strict_encode64(digest)}:"
  header_value.strip == expect
end

# ---- Section 5: PS256 (RSA-PSS SHA-256, salt 32) over the signing base ----
def ps256_ok(base, sig, spki_der)
  key = OpenSSL::PKey.read(spki_der)
  key.verify_pss("SHA256", sig, base, salt_length: 32, mgf1_hash: "SHA256")
rescue StandardError
  false
end

# ---- Section 6: ES256 (ECDSA P-256 SHA-256, strict low-s) over the signing base ----
def es256_ok(base, sig_raw, pub_uncompressed, require_low_s, policy)
  return false unless sig_raw.bytesize == 64
  r = sig_raw[0, 32].unpack1("H*").to_i(16)
  s = sig_raw[32, 32].unpack1("H*").to_i(16)
  return false if require_low_s && s > policy["p256_n"].to_i / 2

  group = OpenSSL::PKey::EC::Group.new("prime256v1")
  # Point.new validates the point is on the curve (raises otherwise)
  OpenSSL::PKey::EC::Point.new(group, OpenSSL::BN.new(pub_uncompressed.unpack1("H*"), 16))
  spki = OpenSSL::ASN1::Sequence([
    OpenSSL::ASN1::Sequence([
      OpenSSL::ASN1::ObjectId("id-ecPublicKey"),
      OpenSSL::ASN1::ObjectId("prime256v1")
    ]),
    OpenSSL::ASN1::BitString(pub_uncompressed)
  ])
  key = OpenSSL::PKey.read(spki.to_der)
  der = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(r), OpenSSL::ASN1::Integer(s)]).to_der
  key.verify(OpenSSL::Digest.new("SHA256"), der, base)
rescue StandardError
  false
end

# ---- driver ----
def hexb(s) = [s].pack("H*")

path = ARGV[0] || DEFAULT_PATH
corpus = JSON.parse(File.read(path))
policy = corpus["policy"]
results = []

record = lambda { |section, note, ok| results << [section, note, ok] }

# 1. fapi_signing_base
corpus["fapi_signing_base"].each do |c|
  want = Base64.decode64(c["signing_base_b64"]).force_encoding("UTF-8")
  ok =
    begin
      # build FIRST; `c["ok"] && build(...)` would short-circuit negative cases
      # and never exercise the build-failure path.
      built = fapi_signing_base(c["in"], c["signature_params_raw"])
      c["ok"] && built == want
    rescue BuildError
      !c["ok"]
    end
  record.call("fapi_signing_base", c["note"], ok)
end

# 2. fapi_required_coverage
corpus["fapi_required_coverage"].each do |c|
  record.call("fapi_required_coverage", c["note"],
              required_coverage_ok(c["message_type"], c["covered_components"], policy) == c["expect_accept"])
end

# 3. fapi_content_digest
corpus["fapi_content_digest"].each do |c|
  record.call("fapi_content_digest", c["note"],
              content_digest_ok(c["body_b64"], c["content_digest"], c["covered_components"], policy) == c["expect_accept"])
end

# 4. fapi_alg
corpus["fapi_alg"].each do |c|
  record.call("fapi_alg", c["note"],
              policy["allowed_algs"].include?(c["alg"].downcase) == c["expect_accept"])
end

# 5. fapi_ps256_verify
corpus["fapi_ps256_verify"].each do |c|
  base = Base64.decode64(c["signing_base_b64"])
  valid = ps256_ok(base, hexb(c["sig_hex"]), hexb(c["pub_spki_hex"]))
  record.call("fapi_ps256_verify", c["note"], valid == c["expect_valid"])
end

# 6. fapi_es256_verify
corpus["fapi_es256_verify"].each do |c|
  base = Base64.decode64(c["signing_base_b64"])
  valid = es256_ok(base, hexb(c["sig_raw_hex"]), hexb(c["pub_uncompressed_hex"]),
                   c["require_low_s"] == true, policy)
  record.call("fapi_es256_verify", c["note"], valid == c["expect_valid"])
end

fails = results.reject { |_, _, ok| ok }
fails.each { |section, note, _| puts "FAIL  [#{section}] #{note}" }
total = results.length
puts "\nruby (fapi): #{total - fails.length}/#{total} cases matched"
exit(fails.empty? ? 0 : 1)
