#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Ruby runner for the Structured Field Values corpus (sfv_v0).
#
# Independently reproduces every verdict in the frozen corpus: parse `input` as
# its declared field type (item|list|dictionary), and if it parses, serialize it
# canonically (RFC 8941 Section 4.1) and compare to the frozen `canonical`. A case
# matches iff parse_ok == expect_parse_ok and, when ok, the canonical bytes are
# equal.
#
# Parsing and canonical serialization use the third-party RFC 8941 gem `starry`,
# so a pass is genuine agreement with an independent implementation, not an echo
# of the generator's oracle. starry silently repairs a non-canonically-padded
# Byte Sequence (e.g. ":aGVsbG8:"), which RFC 8941 and the frozen corpus reject; a
# small strict pre-check (strict_bytes_ok?) rejects any input carrying a
# non-canonical base64 Byte Sequence before delegating, so the runner matches the
# corpus byte-for-byte.
#
# Run:  ruby runners/ruby/verify_sfv.rb [corpus.json]
# Corpus path: ARGV[0], else ../../corpus/sfv_v0/sfv_v0.json. Exit 0 iff all match.

require "json"
require "starry"

DEFAULT_PATH = File.expand_path("../../corpus/sfv_v0/sfv_v0.json", __dir__)
SECTIONS = %w[sfv_item sfv_list sfv_dictionary sfv_parameters sfv_canonical sfv_reject].freeze

TOKEN_TAIL = /[A-Za-z0-9!#$%&'*+\-.^_`|~:\/]/.freeze
B64_CHAR = /[A-Za-z0-9+\/]/.freeze

# A byte sequence's base64 must be canonical: length a multiple of 4 and padding
# only in the final one or two positions (mirrors python base64 validate=True).
def b64_canonical?(content)
  return false unless (content.length % 4).zero?

  pad = 0
  content.each_char.with_index do |c, k|
    if c == "="
      pad += 1
      return false if k < content.length - 2
    else
      return false if pad.positive?
      return false unless c.match?(B64_CHAR)
    end
  end
  true
end

# Reject the whole input if any Byte Sequence token carries non-canonical base64.
# Strings are skipped and tokens consumed whole (Tokens may contain ':'), so the
# only ':' this sees begins a Byte Sequence at a bare-item position.
def strict_bytes_ok?(s)
  i = 0
  while i < s.length
    c = s[i]
    if c == '"'
      i += 1
      while i < s.length
        if s[i] == "\\"
          i += 2
          next
        end
        if s[i] == '"'
          i += 1
          break
        end
        i += 1
      end
    elsif c.match?(/[A-Za-z*]/)
      i += 1
      i += 1 while i < s.length && s[i].match?(TOKEN_TAIL)
    elsif c == ":"
      start = i + 1
      j = start
      j += 1 while j < s.length && s[j] != ":"
      return true if j >= s.length # unterminated: let the gem reject

      return false unless b64_canonical?(s[start...j])

      i = j + 1
    else
      i += 1
    end
  end
  true
end

def verdict(field_type, input)
  return [false, nil] unless strict_bytes_ok?(input)

  begin
    obj =
      case field_type
      when "item" then Starry.parse_item(input)
      when "list" then Starry.parse_list(input)
      when "dictionary" then Starry.parse_dictionary(input)
      else return [false, nil]
      end
    [true, Starry.serialize(obj)]
  rescue StandardError
    [false, nil]
  end
end

path = ARGV[0] || DEFAULT_PATH
corpus = JSON.parse(File.read(path))

total = 0
matched = 0
fails = []
SECTIONS.each do |sec|
  (corpus[sec] || []).each do |c|
    ok, canon = verdict(c["field_type"], c["input"])
    match = (ok == c["expect_parse_ok"]) && (!ok || canon == c["canonical"])
    total += 1
    if match
      matched += 1
    else
      fails << "[#{sec}] #{c['note']}"
    end
  end
end

fails.each { |f| puts "FAIL  #{f}" }
puts "\nruby (sfv): #{matched}/#{total} cases matched"
exit(matched == total ? 0 : 1)
