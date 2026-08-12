#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Ruby runner for the JSON Web Signature corpus (jws_v0).
#
# Independently reproduces every verdict in the frozen corpus, mirroring the
# Python reference runner (runners/python/verify_jws.py) and its decision surface
# (tools/oracle_jws.py) case for case. Parses each compact JWS, applies the JOSE
# security gates in order (reject alg:none, reject any crit, reject alg/key-type
# mismatch such as HS256 keyed with an RSA public key, select the key by kid when
# required), then verifies the RS256 / ES256 / EdDSA signature over
# ASCII(protected)+"."+ASCII(payload). Low-s is NOT enforced (plain JOSE permits a
# high-s ECDSA signature; low-s is a FAPI rule, not a jws_v0 rule).
#
# Self-contained: Ruby standard library only (json, base64, openssl). RS256
# (RSASSA-PKCS1v15 SHA-256), ES256 (ECDSA P-256, raw r||s re-encoded to DER, with
# the on-curve check that Point.new enforces) and EdDSA (Ed25519) via OpenSSL, the
# public keys rebuilt from the JWK material.
#
# Exit 0 iff every case matches. Corpus path: ARGV[0], else the repo corpus.
#
# Run:  ruby runners/ruby/verify_jws.rb [corpus.json]

require "json"
require "base64"
require "openssl"

DEFAULT_PATH = File.expand_path("../../corpus/jws_v0/jws_v0.json", __dir__)

SECTIONS = %w[jws_compact_parse jws_alg_none jws_alg_confusion jws_rs256_verify
              jws_es256_verify jws_eddsa_verify jws_crit jws_kid].freeze

# RFC 7518 Section 3.1 alg -> the JWK kty a verifier must hold for it.
ALG_KTY = { "RS256" => "RSA", "ES256" => "EC", "EdDSA" => "OKP", "HS256" => "oct" }.freeze

# Strict base64url decode of one compact segment (unpadded, URL-safe alphabet).
def b64url(seg)
  return nil unless seg =~ /\A[A-Za-z0-9_-]*\z/
  return nil if seg.length % 4 == 1
  pad = "=" * ((4 - (seg.length % 4)) % 4)
  Base64.urlsafe_decode64(seg + pad)
rescue ArgumentError
  nil
end

def b64url_int(seg)
  bytes = b64url(seg)
  return nil if bytes.nil?
  bytes.empty? ? 0 : bytes.unpack1("H*").to_i(16)
end

def parse_compact(token)
  parts = token.split(".", -1)
  return nil unless parts.length == 3
  header_bytes = b64url(parts[0])
  return nil if header_bytes.nil?
  begin
    header = JSON.parse(header_bytes)
  rescue JSON::ParserError
    return nil
  end
  return nil unless header.is_a?(Hash)
  return nil unless header.key?("alg")
  return nil if b64url(parts[1]).nil?
  sig = b64url(parts[2])
  return nil if sig.nil?
  [header, sig, (parts[0] + "." + parts[1]).b]
end

def select_key(header, keys, select_by_kid)
  if select_by_kid
    kid = header["kid"]
    return nil if kid.nil?
    keys.each { |k| return k[:jwk] if k[:kid] == kid }
    return nil
  end
  keys[0][:jwk]
end

def verify_rs256(jwk, signing_input, sig)
  n = b64url_int(jwk["n"])
  e = b64url_int(jwk["e"])
  return false if n.nil? || e.nil?
  pkcs1 = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(n), OpenSSL::ASN1::Integer(e)]).to_der
  spki = OpenSSL::ASN1::Sequence([
    OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId("rsaEncryption"), OpenSSL::ASN1::Null(nil)]),
    OpenSSL::ASN1::BitString(pkcs1)
  ]).to_der
  key = OpenSSL::PKey.read(spki)
  key.verify(OpenSSL::Digest.new("SHA256"), sig, signing_input)
rescue StandardError
  false
end

def verify_es256(jwk, signing_input, sig)
  return false unless sig.bytesize == 64
  x = b64url(jwk["x"])
  y = b64url(jwk["y"])
  return false if x.nil? || y.nil? || x.bytesize != 32 || y.bytesize != 32
  uncompressed = ("\x04".b + x + y)
  group = OpenSSL::PKey::EC::Group.new("prime256v1")
  # Point.new validates the point is on the curve (raises otherwise).
  OpenSSL::PKey::EC::Point.new(group, OpenSSL::BN.new(uncompressed.unpack1("H*"), 16))
  spki = OpenSSL::ASN1::Sequence([
    OpenSSL::ASN1::Sequence([
      OpenSSL::ASN1::ObjectId("id-ecPublicKey"),
      OpenSSL::ASN1::ObjectId("prime256v1")
    ]),
    OpenSSL::ASN1::BitString(uncompressed)
  ]).to_der
  key = OpenSSL::PKey.read(spki)
  r = sig[0, 32].unpack1("H*").to_i(16)
  s = sig[32, 32].unpack1("H*").to_i(16)
  der = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(r), OpenSSL::ASN1::Integer(s)]).to_der
  key.verify(OpenSSL::Digest.new("SHA256"), der, signing_input)
rescue StandardError
  false
end

def verify_eddsa(jwk, signing_input, sig)
  pk = b64url(jwk["x"])
  return false if pk.nil? || pk.bytesize != 32
  der = ["302a300506032b6570032100"].pack("H*") + pk
  key = OpenSSL::PKey.read(der)
  key.verify(nil, sig, signing_input)
rescue StandardError
  false
end

def verdict(token, keys, select_by_kid)
  parsed = parse_compact(token)
  return false if parsed.nil?
  header, sig, signing_input = parsed
  alg = header["alg"]
  return false if alg == "none"
  return false if header.key?("crit")
  return false unless ALG_KTY.key?(alg)
  jwk = select_key(header, keys, select_by_kid)
  return false if jwk.nil?
  return false unless jwk["kty"] == ALG_KTY[alg]
  case alg
  when "RS256" then verify_rs256(jwk, signing_input, sig)
  when "ES256" then verify_es256(jwk, signing_input, sig)
  when "EdDSA" then verify_eddsa(jwk, signing_input, sig)
  else false
  end
end

path = ARGV[0] || DEFAULT_PATH
corpus = JSON.parse(File.read(path))
material = corpus["keys"]
results = []

SECTIONS.each do |sec|
  (corpus[sec] || []).each do |c|
    keys = c["verify"]["key_names"].map { |n| { kid: material[n]["kid"], jwk: material[n] } }
    accept = verdict(c["jws"], keys, c["verify"]["select_by_kid"])
    results << [sec, c["note"], accept == c["expect_valid"]]
  end
end

fails = results.reject { |_, _, ok| ok }
fails.each { |section, note, _| puts "FAIL  [#{section}] #{note}" }
total = results.length
puts "\nruby (jws): #{total - fails.length}/#{total} cases matched"
exit(fails.empty? ? 0 : 1)
