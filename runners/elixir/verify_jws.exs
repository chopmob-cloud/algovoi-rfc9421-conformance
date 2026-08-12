# Elixir runner for the JSON Web Signature corpus (jws_v0).
#
# Independent Elixir port of the Python reference runner (runners/python/verify_jws.py)
# and its decision surface (tools/oracle_jws.py). Parses each compact JWS, applies
# the JOSE security gates in order (reject alg:none, reject any crit, reject
# alg/key-type mismatch such as HS256 keyed with an RSA public key, select the key
# by kid when required), then verifies the RS256 / ES256 / EdDSA signature over
# ASCII(protected)+"."+ASCII(payload). Low-s is NOT enforced (plain JOSE permits a
# high-s ECDSA signature; low-s is a FAPI rule, not a jws_v0 rule).
#
# Self-contained, matching the sibling verify_fapi.exs / verify_wba.exs: JSON via
# jason; RS256 (RSASSA-PKCS1v15 SHA-256), ES256 (ECDSA P-256, raw r||s re-encoded
# to DER) and EdDSA (Ed25519) via Erlang :crypto.
#
# Corpus path: argv[0], else the repo corpus relative to this source directory.
#
# Run:  cd runners/elixir && elixir verify_jws.exs [corpus.json]

Mix.install([{:jason, "~> 1.4"}])

defmodule VerifyJws do
  @default_path "../../corpus/jws_v0/jws_v0.json"

  @sections ~w(jws_compact_parse jws_alg_none jws_alg_confusion jws_rs256_verify
               jws_es256_verify jws_eddsa_verify jws_crit jws_kid)

  # RFC 7518 Section 3.1 alg -> the JWK kty a verifier must hold for it.
  @alg_kty %{"RS256" => "RSA", "ES256" => "EC", "EdDSA" => "OKP", "HS256" => "oct"}

  # Strict base64url decode of one compact segment (unpadded, URL-safe alphabet).
  defp b64url(seg) do
    case Base.url_decode64(seg, padding: false) do
      {:ok, b} -> b
      :error -> nil
    end
  end

  defp b64url_int(seg) do
    case b64url(seg) do
      nil -> nil
      "" -> 0
      b -> :binary.decode_unsigned(b)
    end
  end

  defp parse_compact(token) do
    case String.split(token, ".") do
      [p, pl, s] ->
        with hb when is_binary(hb) <- b64url(p),
             {:ok, header} when is_map(header) <- Jason.decode(hb),
             true <- Map.has_key?(header, "alg"),
             plb when is_binary(plb) <- b64url(pl),
             sig when is_binary(sig) <- b64url(s) do
          {header, sig, p <> "." <> pl}
        else
          _ -> nil
        end

      _ -> nil
    end
  end

  defp select_key(header, keys, true) do
    case Map.get(header, "kid") do
      nil -> nil
      kid -> Enum.find_value(keys, fn k -> if k.kid == kid, do: k.jwk end)
    end
  end

  defp select_key(_header, keys, false), do: hd(keys).jwk

  defp verify_rs256(jwk, signing_input, sig) do
    with n when not is_nil(n) <- b64url_int(jwk["n"]),
         e when not is_nil(e) <- b64url_int(jwk["e"]) do
      try do
        :crypto.verify(:rsa, :sha256, signing_input, sig, [e, n])
      rescue
        _ -> false
      end
    else
      _ -> false
    end
  end

  defp verify_es256(jwk, signing_input, sig) do
    x = b64url(jwk["x"])
    y = b64url(jwk["y"])

    cond do
      byte_size(sig) != 64 -> false
      is_nil(x) or is_nil(y) or byte_size(x) != 32 or byte_size(y) != 32 -> false
      true ->
        pub = <<4>> <> x <> y
        r = :binary.decode_unsigned(binary_part(sig, 0, 32))
        s = :binary.decode_unsigned(binary_part(sig, 32, 32))
        der = <<0x30, byte_size(der_int(r) <> der_int(s))>> <> der_int(r) <> der_int(s)

        try do
          :crypto.verify(:ecdsa, :sha256, signing_input, der, [pub, :secp256r1])
        rescue
          _ -> false
        catch
          _, _ -> false
        end
    end
  end

  defp verify_eddsa(jwk, signing_input, sig) do
    pk = b64url(jwk["x"])

    cond do
      is_nil(pk) or byte_size(pk) != 32 or byte_size(sig) != 64 -> false
      true ->
        try do
          :crypto.verify(:eddsa, :none, signing_input, sig, [pk, :ed25519])
        rescue
          _ -> false
        catch
          _, _ -> false
        end
    end
  end

  defp der_int(i) do
    bytes = :binary.encode_unsigned(i)
    bytes = if :binary.first(bytes) >= 0x80, do: <<0>> <> bytes, else: bytes
    <<0x02, byte_size(bytes)>> <> bytes
  end

  defp verdict(token, keys, select_by_kid) do
    case parse_compact(token) do
      nil -> false
      {header, sig, signing_input} ->
        alg = header["alg"]

        cond do
          alg == "none" -> false
          Map.has_key?(header, "crit") -> false
          not Map.has_key?(@alg_kty, alg) -> false
          true ->
            case select_key(header, keys, select_by_kid) do
              nil -> false
              jwk ->
                if Map.get(jwk, "kty") != @alg_kty[alg] do
                  false
                else
                  case alg do
                    "RS256" -> verify_rs256(jwk, signing_input, sig)
                    "ES256" -> verify_es256(jwk, signing_input, sig)
                    "EdDSA" -> verify_eddsa(jwk, signing_input, sig)
                    _ -> false
                  end
                end
            end
        end
    end
  end

  def main(argv) do
    path = List.first(argv) || @default_path
    corpus = Jason.decode!(File.read!(path))
    material = corpus["keys"]

    results =
      Enum.flat_map(@sections, fn sec ->
        Enum.map(corpus[sec] || [], fn c ->
          keys =
            Enum.map(c["verify"]["key_names"], fn n ->
              %{kid: material[n]["kid"], jwk: material[n]}
            end)

          accept = verdict(c["jws"], keys, c["verify"]["select_by_kid"])
          {accept == c["expect_valid"], sec, c["note"]}
        end)
      end)

    fails = Enum.filter(results, fn {ok, _, _} -> not ok end)
    Enum.each(fails, fn {_, s, n} -> IO.puts("FAIL  [#{s}] #{n}") end)
    matched = Enum.count(results, fn {ok, _, _} -> ok end)
    total = length(results)
    IO.puts("\nelixir (jws): #{matched}/#{total} cases matched")
    System.halt(if length(fails) == 0, do: 0, else: 1)
  end
end

VerifyJws.main(System.argv())
