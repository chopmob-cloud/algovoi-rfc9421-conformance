#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Ruby runner for the COSE_Sign1 corpus (cose_v0).
#
# Independently reproduces every verdict in the frozen corpus, mirroring the Python
# reference runner (runners/python/verify_cose.py) and its decision surface
# (tools/oracle_cose.py) case for case. Parses each COSE_Sign1 (CBOR array of 4,
# tagged 18 or untagged), applies the COSE security gates in order (protected header
# deterministically encoded per RFC 8949 Section 4.2, alg (label 1) present in the
# protected header, an unknown crit (label 2) label rejected, alg/key-type match),
# builds the Sig_structure ["Signature1", protected, h'', payload] in deterministic
# CBOR and verifies the ES256 / EdDSA / PS256 signature. For the deterministic-CBOR
# section it decides whether the datum is RFC 8949 Section 4.2 canonical. Low-s is
# NOT enforced (a COSE base rule, not a FAPI rule).
#
# The CBOR codec is hand-rolled (a minimal decoder plus an RFC 8949 Section 4.2
# canonical encoder) so the deterministic judgement and the Sig_structure bytes are
# byte-identical to the frozen corpus, independent of any CBOR library's default
# map-key ordering (bytewise-lexicographic, not length-first).
#
# Self-contained: Ruby standard library only (json, openssl). ES256 (ECDSA P-256),
# EdDSA (Ed25519) and PS256 (RSA-PSS SHA-256, salt 32) via OpenSSL, public keys
# rebuilt from the hex COSE key material.
#
# Exit 0 iff every case matches. Corpus path: ARGV[0], else the repo corpus.

require "json"
require "openssl"

DEFAULT_PATH = File.expand_path("../../corpus/cose_v0/cose_v0.json", __dir__)

SECTIONS = %w[cose_sig_structure cose_deterministic_cbor cose_protected_header
              cose_es256_verify cose_eddsa_verify cose_ps256_verify cose_crit].freeze

COSE_SIGN1_TAG = 18
ALG_KTY = { -7 => "EC2", -8 => "OKP", -37 => "RSA" }.freeze
KNOWN_LABELS = [1, 2, 3, 4, 5].freeze

class CborError < StandardError; end

# ---------------------------------------------------------------------------
# Minimal CBOR decode (permissive) + RFC 8949 Section 4.2 canonical encode.
# A value is a tagged array: [:int, n] [:bytes, s] [:text, s] [:array, [..]]
# [:map, [[k,v]..]] [:null] [:tag, n, v] [:bool, b]
# ---------------------------------------------------------------------------
def decode(buf, pos)
  raise CborError, "truncated" if pos >= buf.bytesize
  ib = buf.getbyte(pos)
  pos += 1
  major = ib >> 5
  ai = ib & 0x1f
  if ai < 24
    arg = ai
  elsif ai == 24
    raise CborError, "trunc" if pos + 1 > buf.bytesize
    arg = buf.getbyte(pos); pos += 1
  elsif ai == 25
    raise CborError, "trunc" if pos + 2 > buf.bytesize
    arg = (buf.getbyte(pos) << 8) | buf.getbyte(pos + 1); pos += 2
  elsif ai == 26
    raise CborError, "trunc" if pos + 4 > buf.bytesize
    arg = 0; 4.times { |i| arg = (arg << 8) | buf.getbyte(pos + i) }; pos += 4
  elsif ai == 27
    raise CborError, "trunc" if pos + 8 > buf.bytesize
    arg = 0; 8.times { |i| arg = (arg << 8) | buf.getbyte(pos + i) }; pos += 8
  elsif ai == 31
    raise CborError, "indefinite" if major < 2 || major > 5
    return decode_indefinite(buf, pos, major)
  else
    raise CborError, "reserved"
  end

  case major
  when 0 then [[:int, arg], pos]
  when 1 then [[:int, -1 - arg], pos]
  when 2
    raise CborError, "trunc" if pos + arg > buf.bytesize
    [[:bytes, buf.byteslice(pos, arg)], pos + arg]
  when 3
    raise CborError, "trunc" if pos + arg > buf.bytesize
    [[:text, buf.byteslice(pos, arg)], pos + arg]
  when 4
    items = []
    arg.times { v, pos = decode(buf, pos); items << v }
    [[:array, items], pos]
  when 5
    pairs = []
    arg.times do
      k, pos = decode(buf, pos)
      v, pos = decode(buf, pos)
      pairs << [k, v]
    end
    [[:map, pairs], pos]
  when 6
    inner, pos = decode(buf, pos)
    [[:tag, arg, inner], pos]
  when 7
    return [[:null], pos] if ai == 22
    return [[:bool, false], pos] if ai == 20
    return [[:bool, true], pos] if ai == 21
    raise CborError, "unsupported simple/float"
  else
    raise CborError, "bad major"
  end
end

def decode_indefinite(buf, pos, major)
  if major == 2 || major == 3
    acc = +"".b
    loop do
      raise CborError, "trunc" if pos >= buf.bytesize
      if buf.getbyte(pos) == 0xff then pos += 1; break end
      chunk, pos = decode(buf, pos)
      raise CborError, "bad chunk" unless chunk[0] == (major == 2 ? :bytes : :text)
      acc << chunk[1]
    end
    return [[major == 2 ? :bytes : :text, acc], pos]
  end
  if major == 4
    items = []
    loop do
      raise CborError, "trunc" if pos >= buf.bytesize
      if buf.getbyte(pos) == 0xff then pos += 1; break end
      v, pos = decode(buf, pos); items << v
    end
    return [[:array, items], pos]
  end
  pairs = []
  loop do
    raise CborError, "trunc" if pos >= buf.bytesize
    if buf.getbyte(pos) == 0xff then pos += 1; break end
    k, pos = decode(buf, pos)
    v, pos = decode(buf, pos)
    pairs << [k, v]
  end
  [[:map, pairs], pos]
end

def head(major, n)
  base = major << 5
  if n < 24 then [base | n].pack("C")
  elsif n < 0x100 then [base | 24, n].pack("C2")
  elsif n < 0x10000 then [base | 25, (n >> 8) & 0xff, n & 0xff].pack("C3")
  elsif n < 0x100000000 then ([base | 26] + [24, 16, 8, 0].map { |s| (n >> s) & 0xff }).pack("C5")
  else ([base | 27] + (0..7).map { |i| (n >> (8 * (7 - i))) & 0xff }).pack("C9")
  end
end

def encode(val)
  case val[0]
  when :int
    val[1] >= 0 ? head(0, val[1]) : head(1, -1 - val[1])
  when :bytes then head(2, val[1].bytesize) + val[1]
  when :text then head(3, val[1].bytesize) + val[1].b
  when :array then head(4, val[1].size) + val[1].map { |x| encode(x) }.join
  when :map
    enc = val[1].map { |k, v| [encode(k), encode(v)] }
    enc.sort_by! { |k, _| k.b }
    head(5, enc.size) + enc.map { |k, v| k + v }.join
  when :null then "\xf6".b
  else raise CborError, "cannot encode"
  end
end

def deterministic?(buf)
  value, np = decode(buf, 0)
  return false unless np == buf.bytesize
  return false if value[0] == :tag
  encode(value) == buf
rescue CborError
  false
end

def map_get(m, key)
  m[1].each { |k, v| return v if k[0] == :int && k[1] == key }
  nil
end

# ---------------------------------------------------------------------------
# COSE_Sign1 parse + gates
# ---------------------------------------------------------------------------
def parse_sign1(buf)
  top, = decode(buf, 0)
  arr = top
  if top[0] == :tag
    return nil unless top[1] == COSE_SIGN1_TAG
    arr = top[2]
  end
  return nil unless arr[0] == :array && arr[1].size == 4
  protected_, uhdr, payload, sig = arr[1]
  return nil unless protected_[0] == :bytes
  return nil unless uhdr[0] == :map
  return nil unless payload[0] == :bytes || payload[0] == :null
  return nil unless sig[0] == :bytes
  if protected_[1].bytesize.zero?
    phdr = [:map, []]
  else
    return nil unless deterministic?(protected_[1])
    dec, = decode(protected_[1], 0)
    return nil unless dec[0] == :map
    phdr = dec
  end
  pl = payload[0] == :bytes ? payload[1] : "".b
  { protected: protected_[1], phdr: phdr, payload: pl, sig: sig[1] }
rescue CborError
  nil
end

def sig_structure(protected_bytes, payload_bytes)
  encode([:array, [
    [:text, "Signature1"],
    [:bytes, protected_bytes],
    [:bytes, "".b],
    [:bytes, payload_bytes]
  ]])
end

# ---------------------------------------------------------------------------
# Signature verification per algorithm
# ---------------------------------------------------------------------------
def verify_es256(key, preimage, sig)
  return false unless sig.bytesize == 64
  x = [key["x"]].pack("H*")
  y = [key["y"]].pack("H*")
  return false unless x.bytesize == 32 && y.bytesize == 32
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
  key_obj = OpenSSL::PKey.read(spki)
  r = sig[0, 32].unpack1("H*").to_i(16)
  s = sig[32, 32].unpack1("H*").to_i(16)
  der = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(r), OpenSSL::ASN1::Integer(s)]).to_der
  key_obj.verify(OpenSSL::Digest.new("SHA256"), der, preimage)
rescue StandardError
  false
end

def verify_eddsa(key, preimage, sig)
  pk = [key["x"]].pack("H*")
  return false unless pk.bytesize == 32 && sig.bytesize == 64
  der = ["302a300506032b6570032100"].pack("H*") + pk
  key_obj = OpenSSL::PKey.read(der)
  key_obj.verify(nil, sig, preimage)
rescue StandardError
  false
end

def verify_ps256(key, preimage, sig)
  n = key["n"].to_i(16)
  e = key["e"].to_i(16)
  pkcs1 = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(n), OpenSSL::ASN1::Integer(e)]).to_der
  spki = OpenSSL::ASN1::Sequence([
    OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId("rsaEncryption"), OpenSSL::ASN1::Null(nil)]),
    OpenSSL::ASN1::BitString(pkcs1)
  ]).to_der
  key_obj = OpenSSL::PKey.read(spki)
  key_obj.verify_pss("SHA256", sig, preimage, salt_length: 32, mgf1_hash: "SHA256")
rescue StandardError
  false
end

VERIFIERS = { -7 => method(:verify_es256), -8 => method(:verify_eddsa), -37 => method(:verify_ps256) }.freeze

def verdict(buf, key)
  parsed = parse_sign1(buf)
  return false if parsed.nil?
  alg = map_get(parsed[:phdr], 1)
  return false if alg.nil? || alg[0] != :int
  crit = map_get(parsed[:phdr], 2)
  unless crit.nil?
    return false unless crit[0] == :array && !crit[1].empty?
    crit[1].each { |l| return false unless l[0] == :int && KNOWN_LABELS.include?(l[1]) }
  end
  return false unless ALG_KTY.key?(alg[1])
  return false unless key["kty"] == ALG_KTY[alg[1]]
  preimage = sig_structure(parsed[:protected], parsed[:payload])
  VERIFIERS[alg[1]].call(key, preimage, parsed[:sig])
end

path = ARGV[0] || DEFAULT_PATH
corpus = JSON.parse(File.read(path))
material = corpus["keys"]
results = []

SECTIONS.each do |sec|
  (corpus[sec] || []).each do |c|
    accept =
      if sec == "cose_deterministic_cbor"
        deterministic?([c["cbor_hex"]].pack("H*"))
      else
        verdict([c["cose_hex"]].pack("H*"), material[c["key"]])
      end
    results << [sec, c["note"], accept == c["expect_valid"]]
  end
end

fails = results.reject { |_, _, ok| ok }
fails.each { |section, note, _| puts "FAIL  [#{section}] #{note}" }
total = results.length
puts "\nruby (cose): #{total - fails.length}/#{total} cases matched"
exit(fails.empty? ? 0 : 1)
