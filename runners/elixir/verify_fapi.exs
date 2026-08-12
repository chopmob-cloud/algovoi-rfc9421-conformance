# Elixir runner for the FAPI 2.0 Message Signing corpus (fapi_messagesigning_v0).
#
# Independent Elixir port of the Python reference runner
# (runners/python/verify_fapi.py). Every PROFILE rule (RFC 9421 Section 2.5
# signing base, mandated covered-component completeness, Content-Digest
# (RFC 9530) body binding, PS256/ES256 algorithm restriction) and the
# PS256/ES256 signature verdicts are re-implemented here directly from the
# corpus `policy` block, read at RUNTIME, NOT imported from a shared oracle, so
# a runner passing is genuine agreement rather than an echo. This mirrors the
# Python reference runner case for case.
#
# Self-contained, matching the sibling negative_v1.exs / verify_wba.exs: JSON via
# jason, RSA-PSS-SHA256 and ECDSA-P256-SHA256 via Erlang :public_key / :crypto.
#
# Corpus path: argv[0], else the repo corpus relative to this source directory.
#
# Run:  cd runners/elixir && elixir verify_fapi.exs [corpus.json]

Mix.install([{:jason, "~> 1.4"}])

import Bitwise

defmodule SigningBaseError, do: (defexception message: "")

defmodule VerifyFapi do
  @default_path "../../corpus/fapi_messagesigning_v0/fapi_messagesigning_v0.json"

  # ------------------------------------------------------------------
  # Rule 1: RFC 9421 Section 2.5 signing base, hand-built by direct
  # concatenation (mode "rfc9421": derived components from the `in` fields,
  # every other covered name from headers, then the @signature-params line).
  # Raises SigningBaseError when a covered component's value is missing
  # (build impossible); the driver maps that to "unbuildable".
  # ------------------------------------------------------------------
  def build_signing_base(input, params_raw) do
    headers = for {k, v} <- input["headers"] || %{}, into: %{}, do: {String.downcase(k), v}

    lines =
      Enum.map(input["covered_components"], fn comp ->
        c = String.downcase(comp)

        value =
          case c do
            "@method" -> fetch!(input, "method", "@method covered but method not supplied")
            "@target-uri" -> fetch!(input, "target_uri", "@target-uri covered but target_uri not supplied")
            "@authority" -> String.downcase(fetch!(input, "authority", "@authority covered but authority not supplied"))
            "@path" -> fetch!(input, "path", "@path covered but path not supplied")
            "@scheme" -> String.downcase(fetch!(input, "scheme", "@scheme covered but scheme not supplied"))
            "@status" ->
              case input["status"] do
                nil -> raise(SigningBaseError, message: "@status covered but status not supplied")
                s -> to_string(s)
              end

            _ ->
              if String.starts_with?(c, "@"),
                do: raise(SigningBaseError, message: "unsupported derived component: #{comp}")

              case Map.fetch(headers, c) do
                {:ok, hv} when not is_nil(hv) -> hv
                _ -> raise(SigningBaseError, message: "covered header #{comp} not present")
              end
          end

        "\"#{c}\": #{value}"
      end)

    Enum.join(lines ++ ["\"@signature-params\": #{params_raw}"], "\n")
  end

  defp fetch!(map, key, msg) do
    case Map.fetch(map, key) do
      {:ok, v} when not is_nil(v) -> v
      _ -> raise(SigningBaseError, message: msg)
    end
  end

  # ------------------------------------------------------------------
  # Rule 2: mandated covered-component completeness. The required set is keyed
  # by message_type; the required names (lowercased) must be a subset of the
  # covered names (lowercased).
  # ------------------------------------------------------------------
  def coverage_ok(message_type, covered, policy) do
    key = if message_type == "request", do: "required_covered_request", else: "required_covered_response"
    have = MapSet.new(covered || [], &String.downcase/1)
    Enum.all?(policy[key], fn r -> MapSet.member?(have, String.downcase(r)) end)
  end

  # ------------------------------------------------------------------
  # Rule 3: Content-Digest (RFC 9530) body binding. content-digest must be
  # covered; the header's algorithm token (lowercased) must be an allowed one;
  # and the header must equal "<alg>=:<base64(hash(body))>:" exactly.
  # ------------------------------------------------------------------
  def content_digest_ok(body_b64, header_value, covered, policy) do
    covered_lc = MapSet.new(covered || [], &String.downcase/1)

    cond do
      not MapSet.member?(covered_lc, "content-digest") -> false
      true ->
        case String.split(header_value, "=", parts: 2) do
          [alg_raw, _] ->
            algorithm = alg_raw |> String.trim() |> String.downcase()

            cond do
              algorithm not in policy["content_digest_algorithms"] -> false
              true ->
                body = Base.decode64!(body_b64)
                hash_alg = if algorithm == "sha-256", do: :sha256, else: :sha512
                digest = :crypto.hash(hash_alg, body)
                expect = "#{algorithm}=:#{Base.encode64(digest)}:"
                String.trim(header_value) == expect
            end

          _ -> false
        end
    end
  end

  # ------------------------------------------------------------------
  # Rule 5: PS256 (RSA-PSS SHA-256, salt length 32) over the raw signing-base
  # bytes, with the RSA public key extracted from its SubjectPublicKeyInfo DER.
  # Mirrors the sibling negative_v1.exs RSA key parse.
  # ------------------------------------------------------------------
  def ps256_ok(base, sig, spki_der) do
    try do
      spki_info = :public_key.der_decode(:SubjectPublicKeyInfo, spki_der)
      {:RSAPublicKey, n, e} = :public_key.der_decode(:RSAPublicKey, elem(spki_info, 2))

      :crypto.verify(:rsa, :sha256, base, sig, [e, n],
        [{:rsa_padding, :rsa_pkcs1_pss_padding}, {:rsa_pss_saltlen, 32}, {:rsa_mgf1_md, :sha256}])
    rescue
      _ -> false
    end
  end

  # ------------------------------------------------------------------
  # Rule 6: ES256 (ECDSA P-256 SHA-256). The signature is raw 64-byte r||s.
  # Reject high-s (s > n/2) when low-s is required, else convert r||s to a DER
  # ECDSA signature (SEQUENCE of two INTEGERs) and verify against the
  # uncompressed public point.
  # ------------------------------------------------------------------
  def es256_ok(base, sig_raw, pub_uncompressed, require_low_s, policy) do
    if byte_size(sig_raw) != 64 do
      false
    else
      r = :binary.decode_unsigned(binary_part(sig_raw, 0, 32))
      s = :binary.decode_unsigned(binary_part(sig_raw, 32, 32))
      n = String.to_integer(policy["p256_n"])

      cond do
        require_low_s and s > div(n, 2) -> false
        true ->
          der = <<0x30, byte_size(der_int(r) <> der_int(s))>> <> der_int(r) <> der_int(s)

          try do
            :crypto.verify(:ecdsa, :sha256, base, der, [pub_uncompressed, :secp256r1])
          rescue
            _ -> false
          end
      end
    end
  end

  defp der_int(i) do
    bytes = :binary.encode_unsigned(i)
    bytes = if (:binary.first(bytes) &&& 0x80) != 0, do: <<0>> <> bytes, else: bytes
    <<0x02, byte_size(bytes)>> <> bytes
  end

  # ------------------------------------------------------------------
  # Driver.
  # ------------------------------------------------------------------
  defp hexb(s), do: Base.decode16!(s, case: :lower)

  def main(argv) do
    path = List.first(argv) || @default_path
    corpus = Jason.decode!(File.read!(path))
    policy = corpus["policy"]
    results = []

    results =
      results ++
        Enum.map(corpus["fapi_signing_base"], fn c ->
          want = Base.decode64!(c["signing_base_b64"])
          # Build FIRST; `c["ok"] and build(...)` would short-circuit negative
          # cases and never exercise the build-failure path.
          ok =
            try do
              built = build_signing_base(c["in"], c["signature_params_raw"])
              c["ok"] and built == want
            rescue
              _ -> not c["ok"]
            end

          {ok, "fapi_signing_base", c["note"]}
        end)

    results =
      results ++
        Enum.map(corpus["fapi_required_coverage"], fn c ->
          {coverage_ok(c["message_type"], c["covered_components"], policy) == c["expect_accept"],
           "fapi_required_coverage", c["note"]}
        end)

    results =
      results ++
        Enum.map(corpus["fapi_content_digest"], fn c ->
          {content_digest_ok(c["body_b64"], c["content_digest"], c["covered_components"], policy) ==
             c["expect_accept"], "fapi_content_digest", c["note"]}
        end)

    results =
      results ++
        Enum.map(corpus["fapi_alg"], fn c ->
          {(String.downcase(c["alg"]) in policy["allowed_algs"]) == c["expect_accept"], "fapi_alg",
           c["note"]}
        end)

    results =
      results ++
        Enum.map(corpus["fapi_ps256_verify"], fn c ->
          base = Base.decode64!(c["signing_base_b64"])
          ok = ps256_ok(base, hexb(c["sig_hex"]), hexb(c["pub_spki_hex"]))
          {ok == c["expect_valid"], "fapi_ps256_verify", c["note"]}
        end)

    results =
      results ++
        Enum.map(corpus["fapi_es256_verify"], fn c ->
          base = Base.decode64!(c["signing_base_b64"])
          ok =
            es256_ok(base, hexb(c["sig_raw_hex"]), hexb(c["pub_uncompressed_hex"]),
              c["require_low_s"] == true, policy)

          {ok == c["expect_valid"], "fapi_es256_verify", c["note"]}
        end)

    fails = Enum.filter(results, fn {ok, _, _} -> not ok end)
    Enum.each(fails, fn {_, s, n} -> IO.puts("FAIL  [#{s}] #{n}") end)
    matched = Enum.count(results, fn {ok, _, _} -> ok end)
    total = length(results)
    IO.puts("\nelixir (fapi): #{matched}/#{total} cases matched")
    System.halt(if length(fails) == 0, do: 0, else: 1)
  end
end

VerifyFapi.main(System.argv())
