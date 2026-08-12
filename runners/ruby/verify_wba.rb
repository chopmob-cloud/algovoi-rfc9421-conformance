#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Ruby reference runner for the Web Bot Auth profile corpus (webbotauth_v0).
#
# Independently reproduces every verdict in the frozen corpus. Crypto and the
# RFC 9421 Section 2.5 signing base are re-derived here directly; the PROFILE
# rules (coverage completeness, freshness window, directory keyid resolution,
# Signature-Agent SSRF) are re-implemented from the corpus `policy` block read at
# RUNTIME, NOT imported from the generator's oracle, so a runner passing is
# genuine agreement rather than an echo. Mirrors the Python reference runner
# (runners/python/verify_wba.py) and the go/typescript WBA runners case for case.
#
# Self-contained: Ruby standard library only (json, base64, openssl, uri, ipaddr).
# Ed25519 verify via OpenSSL (key built from a hand-assembled SPKI DER, since the
# OpenSSL 3.0 here has no new_raw_public_key); IPv4+IPv6 CIDR membership via
# IPAddr, matched same-version only.
#
# Exit 0 iff every case matches. Corpus path: ARGV[0], else the repo corpus
# relative to this source file's directory (runners/ruby).
#
# Run:  ruby runners/ruby/verify_wba.rb [corpus.json]

require "json"
require "base64"
require "openssl"
require "uri"
require "ipaddr"

# Default assumes the corpus lives at repo/corpus, two directories up from here.
DEFAULT_PATH = File.expand_path("../../corpus/webbotauth_v0/webbotauth_v0.json", __dir__)

class BuildError < StandardError; end

# ---- Rule 1: RFC 9421 Section 2.5 signing base, by direct concatenation ----
# Raises BuildError when a covered component's value is missing (build impossible).
def build_signing_base(src, params_raw)
  lines = []
  (src["covered_components"] || []).each do |comp|
    name = comp.downcase
    val =
      case name
      when "@authority" then src["authority"]
      when "@method"    then src["method"]
      when "@path"      then src["path"]
      else (src["headers"] || {})[name]
      end
    raise BuildError, "missing covered component: #{name}" if val.nil?
    lines << "\"#{name}\": #{val}"
  end
  lines << "\"@signature-params\": #{params_raw}"
  lines.join("\n")
end

# ---- Rule 2: coverage completeness (every required component present) ----
def coverage_ok(covered, policy)
  have = (covered || []).map(&:downcase)
  policy["required_covered_components"].all? { |r| have.include?(r.downcase) }
end

# ---- Rule 3: freshness window ----
# All three must be integers, expires > created, and (created - skew) <= now < expires.
def freshness_ok(created, expires, now, policy)
  skew = policy["clock_skew_seconds"] || 0
  return false unless [created, expires, now].all? { |x| x.is_a?(Integer) }
  return false if expires <= created
  (created - skew) <= now && now < expires
end

# ---- Rule 4: directory keyid resolution to a usable Ed25519 JWK ----
def directory_ok(directory, keyid)
  (directory || []).each do |jwk|
    if jwk["kid"] == keyid
      x = jwk["x"]
      return jwk["kty"] == "OKP" && jwk["crv"] == "Ed25519" && !(x.nil? || x.empty?)
    end
  end
  false
end

# ---- Rule 5: Signature-Agent SSRF guard ----
def ssrf_ok(url, resolved_ip, policy)
  ssrf = policy["ssrf"]
  begin
    u = URI.parse(url)
  rescue URI::InvalidURIError
    return false
  end
  return false if ssrf.fetch("require_https", true) && u.scheme != "https"
  return false unless u.userinfo.nil? # userinfo present -> reject
  host = u.hostname # strips [] from IPv6 literals
  return false if host.nil? || host.empty?

  addr =
    begin
      IPAddr.new(host) # host is an IP literal (v4 or v6)
    rescue IPAddr::Error
      return false if resolved_ip.nil?
      begin
        IPAddr.new(resolved_ip)
      rescue IPAddr::Error
        return false
      end
    end

  ssrf["denied_cidrs"].each do |cidr|
    net = IPAddr.new(cidr)
    # Same IP version only, mirroring the Python reference.
    return false if net.ipv4? == addr.ipv4? && net.include?(addr)
  end
  true
end

# ---- Rule 6: Ed25519 verify of the raw signing-base bytes under a raw 32-byte key ----
def ed25519_verify(msg, sig, pk)
  return false unless pk.bytesize == 32
  der = ["302a300506032b6570032100"].pack("H*") + pk
  key = OpenSSL::PKey.read(der)
  key.verify(nil, sig, msg)
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

# 1. wba_signing_base
corpus["wba_signing_base"].each do |c|
  want = Base64.decode64(c["signing_base_b64"]).force_encoding("UTF-8")
  ok =
    begin
      # build FIRST; `c["ok"] && build(...)` would short-circuit negative cases
      # and never exercise the build-failure path.
      built = build_signing_base(c["in"], c["signature_params_raw"])
      c["ok"] && built == want
    rescue BuildError
      !c["ok"]
    end
  record.call("wba_signing_base", c["note"], ok)
end

# 2. wba_coverage
corpus["wba_coverage"].each do |c|
  record.call("wba_coverage", c["note"],
              coverage_ok(c["covered_components"], policy) == c["expect_accept"])
end

# 3. wba_freshness
corpus["wba_freshness"].each do |c|
  record.call("wba_freshness", c["note"],
              freshness_ok(c["created"], c["expires"], c["now"], policy) == c["expect_accept"])
end

# 4. wba_directory
corpus["wba_directory"].each do |c|
  record.call("wba_directory", c["note"],
              directory_ok(c["directory"], c["keyid"]) == c["expect_accept"])
end

# 5. wba_directory_ssrf
corpus["wba_directory_ssrf"].each do |c|
  record.call("wba_directory_ssrf", c["note"],
              ssrf_ok(c["signature_agent_url"], c["resolved_ip"], policy) == c["expect_fetch_allowed"])
end

# 6. wba_ed25519_verify
corpus["wba_ed25519_verify"].each do |c|
  base = Base64.decode64(c["signing_base_b64"])
  valid = ed25519_verify(base, hexb(c["sig_hex"]), hexb(c["pk_hex"]))
  record.call("wba_ed25519_verify", c["note"], valid == c["expect_valid"])
end

fails = results.reject { |_, _, ok| ok }
fails.each { |section, note, _| puts "FAIL  [#{section}] #{note}" }
total = results.length
puts "\nruby (wba): #{total - fails.length}/#{total} cases matched"
exit(fails.empty? ? 0 : 1)
