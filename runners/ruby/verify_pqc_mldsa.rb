#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Ruby runner for the post-quantum ML-DSA-65 corpus (pqc_mldsa_v0).
#
# Independent Ruby port of the Python reference runner
# (runners/python/verify_pqc_mldsa.py) and its decision surface
# (tools/oracle_pqc_mldsa.py): decode the hex public key, message and signature,
# reject a wrong-length public key (must be 1952) or signature (must be 3309)
# before any verify, then verify the FIPS-204 ML-DSA-65 signature over the exact
# message bytes with the EMPTY context string (the pure ML-DSA variant).
#
# Ruby's bundled OpenSSL predates ML-DSA (FIPS 204 landed in OpenSSL 3.5), and
# there is no mature pure-Ruby FIPS-204 library, so this runner binds liboqs (the
# C reference the C runner already uses) through the `ffi` gem. It calls exactly
# the liboqs C API the C runner does: OQS_SIG_new("ML-DSA-65") + OQS_SIG_verify.
# OQS_SIG_new returns NULL if the installed liboqs is an old build that exposes
# only round-3 "Dilithium3" and not "ML-DSA-65"; that is the built-in tripwire.
#
# Requires the `ffi` gem and a system liboqs shared library (0.14.0 minimal, the
# same build the C cell makes) exposing the ML-DSA-65 mechanism.
#
# Exit 0 iff every case matches. Corpus path: ARGV[0], else $ALGOVOI_PQC_MLDSA,
# else the repo corpus.
#
# Run:  ruby runners/ruby/verify_pqc_mldsa.rb [corpus.json]

require "json"
require "ffi"

PK_LEN = 1952
SIG_LEN = 3309
MECHANISM = "ML-DSA-65"

# Thin FFI binding to the liboqs C API. Only the three symbols the verify path
# needs are declared; the OQS_SIG struct is treated as an opaque pointer because
# the fixed FIPS-204 lengths are hard-coded, so no struct fields are read.
module Oqs
  extend FFI::Library
  ffi_lib ["liboqs.so", "liboqs.so.0", "liboqs"]

  # OQS_SIG *OQS_SIG_new(const char *method_name)
  attach_function :OQS_SIG_new, [:string], :pointer
  # void OQS_SIG_free(OQS_SIG *sig)
  attach_function :OQS_SIG_free, [:pointer], :void
  # OQS_STATUS OQS_SIG_verify(const OQS_SIG *sig, const uint8_t *message,
  #   size_t message_len, const uint8_t *signature, size_t signature_len,
  #   const uint8_t *public_key)  -- returns 0 (OQS_SUCCESS) on a valid signature.
  attach_function :OQS_SIG_verify,
                  [:pointer, :pointer, :size_t, :pointer, :size_t, :pointer], :int
end

OQS_SUCCESS = 0

# hex -> binary String; nil on odd length or a bad digit. An empty string decodes
# to a real 0-byte value (not a decode failure), so the empty-message case works.
def hexdec(s)
  return nil if s.nil?
  return nil if s.length.odd?
  return "".b if s.empty?
  return nil unless s =~ /\A[0-9a-fA-F]*\z/
  [s].pack("H*")
end

# Copy a binary String into a native FFI memory buffer (or a 1-byte buffer for an
# empty message, whose pointer is passed with length 0).
def to_buf(bytes)
  buf = FFI::MemoryPointer.new(:uint8, bytes.empty? ? 1 : bytes.bytesize)
  buf.put_bytes(0, bytes) unless bytes.empty?
  buf
end

def verdict(sig, pk_hex, msg_hex, sig_hex)
  pk = hexdec(pk_hex)
  msg = hexdec(msg_hex)
  s = hexdec(sig_hex)
  return false if pk.nil? || msg.nil? || s.nil?
  return false if pk.bytesize != PK_LEN || s.bytesize != SIG_LEN
  pk_buf = to_buf(pk)
  msg_buf = to_buf(msg)
  sig_buf = to_buf(s)
  rc = Oqs.OQS_SIG_verify(sig, msg_buf, msg.bytesize, sig_buf, s.bytesize, pk_buf)
  rc == OQS_SUCCESS
end

DEFAULT_PATH = File.expand_path("../../corpus/pqc_mldsa_v0/pqc_mldsa_v0.json", __dir__)
SECTIONS = %w[mldsa65_verify mldsa65_malformed mldsa65_acvp_kat].freeze

path = ARGV[0] || ENV["ALGOVOI_PQC_MLDSA"] || DEFAULT_PATH
corpus = JSON.parse(File.read(path))

sig = Oqs.OQS_SIG_new(MECHANISM)
if sig.null?
  warn "liboqs has no ML-DSA-65 (old/Dilithium build)"
  exit 2
end

results = []
SECTIONS.each do |sec|
  (corpus[sec] || []).each do |c|
    accept = verdict(sig, c["public_key"], c["message"], c["signature"])
    results << [sec, c["note"], accept == c["expect_valid"]]
  end
end
Oqs.OQS_SIG_free(sig)

fails = results.reject { |_, _, ok| ok }
fails.each { |section, note, _| puts "FAIL  [#{section}] #{note}" }
total = results.length
puts "\nruby (pqc_mldsa): #{total - fails.length}/#{total} cases matched"
exit(fails.empty? ? 0 : 1)
