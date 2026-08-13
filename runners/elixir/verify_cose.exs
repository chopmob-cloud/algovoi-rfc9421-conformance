# Elixir runner for the COSE_Sign1 corpus (cose_v0).
#
# Independent Elixir port of the Python reference runner (runners/python/verify_cose.py)
# and its decision surface (tools/oracle_cose.py). Parses each COSE_Sign1 (CBOR array
# of 4, tagged 18 or untagged), applies the COSE security gates in order (protected
# header deterministically encoded per RFC 8949 Section 4.2, alg (label 1) present in
# the protected header, an unknown crit (label 2) label rejected, alg/key-type match),
# builds the Sig_structure ["Signature1", protected, h'', payload] in deterministic
# CBOR and verifies the ES256 / EdDSA / PS256 signature. For the deterministic-CBOR
# section it decides whether the datum is RFC 8949 Section 4.2 canonical. Low-s is NOT
# enforced (a COSE base rule, not a FAPI rule).
#
# The CBOR codec is hand-rolled (a minimal decoder plus an RFC 8949 Section 4.2
# canonical encoder) so the deterministic judgement and the Sig_structure bytes are
# byte-identical to the frozen corpus, independent of any CBOR library's default
# map-key ordering (bytewise-lexicographic, not length-first).
#
# JSON via jason; ES256 (ECDSA P-256, explicit on-curve check), EdDSA (Ed25519) and
# PS256 (RSA-PSS SHA-256, salt 32) via Erlang :crypto. Keys from the hex COSE material.
#
# Run:  cd runners/elixir && elixir verify_cose.exs [corpus.json]

Mix.install([{:jason, "~> 1.4"}])

defmodule VerifyCose do
  @default_path "../../corpus/cose_v0/cose_v0.json"

  @sections ~w(cose_sig_structure cose_deterministic_cbor cose_protected_header
               cose_es256_verify cose_eddsa_verify cose_ps256_verify cose_crit)

  @cose_sign1_tag 18
  @alg_kty %{-7 => "EC2", -8 => "OKP", -37 => "RSA"}

  @p256_p 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
  @p256_a 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
  @p256_b 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

  # ------------------------------------------------------------------
  # Minimal CBOR decode (permissive). A value is a tagged tuple:
  # {:int, n} {:bytes, bin} {:text, bin} {:array, list} {:map, [{k,v}]}
  # {:null} {:tag, n, v} {:bool, b}. decode/1 returns {value, rest} or :error.
  # ------------------------------------------------------------------
  def decode(<<ib, rest::binary>>) do
    major = Bitwise.bsr(ib, 5)
    ai = Bitwise.band(ib, 0x1F)

    cond do
      ai == 31 and major >= 2 and major <= 5 -> decode_indefinite(major, rest)
      true ->
        case read_arg(ai, rest) do
          :error -> :error
          {arg, rest2} -> decode_value(major, ai, arg, rest2)
        end
    end
  end

  def decode(_), do: :error

  defp read_arg(ai, bin) when ai < 24, do: {ai, bin}
  defp read_arg(24, <<a, rest::binary>>), do: {a, rest}
  defp read_arg(25, <<a::16, rest::binary>>), do: {a, rest}
  defp read_arg(26, <<a::32, rest::binary>>), do: {a, rest}
  defp read_arg(27, <<a::64, rest::binary>>), do: {a, rest}
  defp read_arg(_, _), do: :error

  defp decode_value(0, _ai, arg, rest), do: {{:int, arg}, rest}
  defp decode_value(1, _ai, arg, rest), do: {{:int, -1 - arg}, rest}

  defp decode_value(2, _ai, arg, rest) do
    if byte_size(rest) >= arg do
      <<b::binary-size(arg), r::binary>> = rest
      {{:bytes, b}, r}
    else
      :error
    end
  end

  defp decode_value(3, _ai, arg, rest) do
    if byte_size(rest) >= arg do
      <<b::binary-size(arg), r::binary>> = rest
      {{:text, b}, r}
    else
      :error
    end
  end

  defp decode_value(4, _ai, arg, rest), do: decode_array(arg, rest, [])
  defp decode_value(5, _ai, arg, rest), do: decode_map(arg, rest, [])

  defp decode_value(6, _ai, arg, rest) do
    case decode(rest) do
      :error -> :error
      {inner, r} -> {{:tag, arg, inner}, r}
    end
  end

  defp decode_value(7, 22, _arg, rest), do: {{:null}, rest}
  defp decode_value(7, 20, _arg, rest), do: {{:bool, false}, rest}
  defp decode_value(7, 21, _arg, rest), do: {{:bool, true}, rest}
  defp decode_value(_, _, _, _), do: :error

  defp decode_array(0, rest, acc), do: {{:array, Enum.reverse(acc)}, rest}

  defp decode_array(n, rest, acc) do
    case decode(rest) do
      :error -> :error
      {v, r} -> decode_array(n - 1, r, [v | acc])
    end
  end

  defp decode_map(0, rest, acc), do: {{:map, Enum.reverse(acc)}, rest}

  defp decode_map(n, rest, acc) do
    with {k, r1} when k != :error <- decode(rest),
         {v, r2} when v != :error <- decode(r1) do
      decode_map(n - 1, r2, [{k, v} | acc])
    else
      _ -> :error
    end
  end

  defp decode_indefinite(major, rest) when major in [2, 3] do
    want = if major == 2, do: :bytes, else: :text
    collect_chunks(rest, want, <<>>)
  end

  defp decode_indefinite(4, rest), do: collect_items(rest, [])
  defp decode_indefinite(5, rest), do: collect_pairs(rest, [])

  defp collect_chunks(<<0xFF, rest::binary>>, want, acc), do: {{want, acc}, rest}
  defp collect_chunks(<<>>, _, _), do: :error

  defp collect_chunks(bin, want, acc) do
    case decode(bin) do
      {{^want, b}, r} -> collect_chunks(r, want, acc <> b)
      _ -> :error
    end
  end

  defp collect_items(<<0xFF, rest::binary>>, acc), do: {{:array, Enum.reverse(acc)}, rest}
  defp collect_items(<<>>, _), do: :error

  defp collect_items(bin, acc) do
    case decode(bin) do
      :error -> :error
      {v, r} -> collect_items(r, [v | acc])
    end
  end

  defp collect_pairs(<<0xFF, rest::binary>>, acc), do: {{:map, Enum.reverse(acc)}, rest}
  defp collect_pairs(<<>>, _), do: :error

  defp collect_pairs(bin, acc) do
    with {k, r1} when k != :error <- decode(bin),
         {v, r2} when v != :error <- decode(r1) do
      collect_pairs(r2, [{k, v} | acc])
    else
      _ -> :error
    end
  end

  # ------------------------------------------------------------------
  # RFC 8949 Section 4.2 canonical encode
  # ------------------------------------------------------------------
  defp head(major, n) do
    base = Bitwise.bsl(major, 5)

    cond do
      n < 24 -> <<Bitwise.bor(base, n)>>
      n < 0x100 -> <<Bitwise.bor(base, 24), n>>
      n < 0x10000 -> <<Bitwise.bor(base, 25), n::16>>
      n < 0x100000000 -> <<Bitwise.bor(base, 26), n::32>>
      true -> <<Bitwise.bor(base, 27), n::64>>
    end
  end

  def encode({:int, n}) when n >= 0, do: head(0, n)
  def encode({:int, n}), do: head(1, -1 - n)
  def encode({:bytes, b}), do: head(2, byte_size(b)) <> b
  def encode({:text, b}), do: head(3, byte_size(b)) <> b
  def encode({:array, list}), do: head(4, length(list)) <> Enum.map_join(list, "", &encode/1)

  def encode({:map, pairs}) do
    enc =
      pairs
      |> Enum.map(fn {k, v} -> {encode(k), encode(v)} end)
      |> Enum.sort_by(fn {k, _} -> k end)

    head(5, length(enc)) <> Enum.map_join(enc, "", fn {k, v} -> k <> v end)
  end

  def encode({:null}), do: <<0xF6>>

  def deterministic?(bin) do
    case decode(bin) do
      {value, <<>>} ->
        case value do
          {:tag, _, _} -> false
          _ -> encode(value) == bin
        end

      _ ->
        false
    end
  end

  defp map_get({:map, pairs}, key) do
    Enum.find_value(pairs, fn {k, v} -> if k == {:int, key}, do: {:ok, v} end)
  end

  # ------------------------------------------------------------------
  # COSE_Sign1 parse + gates
  # ------------------------------------------------------------------
  defp parse_sign1(bin) do
    with {top, _rest} when top != :error <- decode(bin),
         {:ok, arr} <- untag(top),
         {:array, [prot, uhdr, payload, sig]} <- arr,
         {:bytes, pbytes} <- prot,
         {:map, _} <- uhdr,
         true <- match?({:bytes, _}, payload) or match?({:null}, payload),
         {:bytes, sbytes} <- sig,
         {:ok, phdr} <- protected_header(pbytes) do
      pl = case payload do
        {:bytes, b} -> b
        {:null} -> <<>>
      end

      {:ok, %{protected: pbytes, phdr: phdr, payload: pl, sig: sbytes}}
    else
      _ -> :error
    end
  end

  defp untag({:tag, @cose_sign1_tag, inner}), do: {:ok, inner}
  defp untag({:tag, _, _}), do: :error
  defp untag(v), do: {:ok, v}

  defp protected_header(<<>>), do: {:ok, {:map, []}}

  defp protected_header(pbytes) do
    if deterministic?(pbytes) do
      case decode(pbytes) do
        {{:map, _} = m, _} -> {:ok, m}
        _ -> :error
      end
    else
      :error
    end
  end

  defp sig_structure(prot, payload) do
    encode({:array, [{:text, "Signature1"}, {:bytes, prot}, {:bytes, <<>>}, {:bytes, payload}]})
  end

  # ------------------------------------------------------------------
  # Signature verification per algorithm
  # ------------------------------------------------------------------
  defp hexb(s), do: Base.decode16!(s, case: :lower)
  defp hexi(s), do: :binary.decode_unsigned(hexb(s))

  defp on_curve?(x, y) do
    y2 = rem(y * y, @p256_p)
    rhs = rem(x * x * x + @p256_a * x + @p256_b, @p256_p)
    y2 == rhs
  end

  defp verify_es256(key, preimage, sig) do
    x = hexb(key["x"])
    y = hexb(key["y"])

    cond do
      byte_size(sig) != 64 -> false
      byte_size(x) != 32 or byte_size(y) != 32 -> false
      not on_curve?(:binary.decode_unsigned(x), :binary.decode_unsigned(y)) -> false
      true ->
        pub = <<4>> <> x <> y
        r = :binary.decode_unsigned(binary_part(sig, 0, 32))
        s = :binary.decode_unsigned(binary_part(sig, 32, 32))
        der = <<0x30, byte_size(der_int(r) <> der_int(s))>> <> der_int(r) <> der_int(s)

        try do
          :crypto.verify(:ecdsa, :sha256, preimage, der, [pub, :secp256r1])
        rescue
          _ -> false
        catch
          _, _ -> false
        end
    end
  end

  defp verify_eddsa(key, preimage, sig) do
    pk = hexb(key["x"])

    cond do
      byte_size(pk) != 32 or byte_size(sig) != 64 -> false
      true ->
        try do
          :crypto.verify(:eddsa, :none, preimage, sig, [pk, :ed25519])
        rescue
          _ -> false
        catch
          _, _ -> false
        end
    end
  end

  defp verify_ps256(key, preimage, sig) do
    n = hexi(key["n"])
    e = hexi(key["e"])

    try do
      :crypto.verify(:rsa, :sha256, preimage, sig, [e, n],
        [{:rsa_padding, :rsa_pkcs1_pss_padding}, {:rsa_pss_saltlen, 32}, {:rsa_mgf1_md, :sha256}])
    rescue
      _ -> false
    catch
      _, _ -> false
    end
  end

  defp der_int(i) do
    bytes = :binary.encode_unsigned(i)
    bytes = if :binary.first(bytes) >= 0x80, do: <<0>> <> bytes, else: bytes
    <<0x02, byte_size(bytes)>> <> bytes
  end

  defp verdict(bin, key) do
    with {:ok, p} <- parse_sign1(bin),
         {:ok, {:int, alg}} <- map_get(p.phdr, 1),
         true <- crit_ok?(map_get(p.phdr, 2)),
         want when not is_nil(want) <- @alg_kty[alg],
         true <- key["kty"] == want do
      preimage = sig_structure(p.protected, p.payload)

      case alg do
        -7 -> verify_es256(key, preimage, sig_of(p))
        -8 -> verify_eddsa(key, preimage, sig_of(p))
        -37 -> verify_ps256(key, preimage, sig_of(p))
        _ -> false
      end
    else
      _ -> false
    end
  end

  defp sig_of(p), do: p.sig

  defp crit_ok?(nil), do: true
  defp crit_ok?({:ok, {:array, []}}), do: false

  defp crit_ok?({:ok, {:array, labels}}) do
    Enum.all?(labels, fn
      {:int, l} -> l >= 1 and l <= 5
      _ -> false
    end)
  end

  defp crit_ok?(_), do: false

  def main(argv) do
    path = List.first(argv) || @default_path
    corpus = Jason.decode!(File.read!(path))
    material = corpus["keys"]

    results =
      Enum.flat_map(@sections, fn sec ->
        Enum.map(corpus[sec] || [], fn c ->
          accept =
            if sec == "cose_deterministic_cbor" do
              deterministic?(hexb(c["cbor_hex"]))
            else
              verdict(hexb(c["cose_hex"]), material[c["key"]])
            end

          {accept == c["expect_valid"], sec, c["note"]}
        end)
      end)

    fails = Enum.filter(results, fn {ok, _, _} -> not ok end)
    Enum.each(fails, fn {_, s, n} -> IO.puts("FAIL  [#{s}] #{n}") end)
    matched = Enum.count(results, fn {ok, _, _} -> ok end)
    total = length(results)
    IO.puts("\nelixir (cose): #{matched}/#{total} cases matched")
    System.halt(if length(fails) == 0, do: 0, else: 1)
  end
end

VerifyCose.main(System.argv())
