# Elixir runner for the rfc9421_negative_v1 CORE cross-language battery.
#
# Independent Elixir port of the verdict surface (signing_base.py, parse.py,
# keycheck.py, verify.py + the algovoi-rfc9421-ecdsa provider). Self-contained
# (no Elixir RFC 9421 verifier exists); must produce byte-identical verdicts to
# every other runner. Ed25519 verify via Erlang :crypto (:eddsa) plus an explicit
# canonical-S (S < L) check and the ported small-order / non-canonical key gate
# (native bignums, RFC 8032 arithmetic) applied fail-closed first. ECDSA
# P-256/P-384 via :crypto with explicit range / width / on-curve / strict-low-s
# checks.
#
# Corpus path: argv[0], else $ALGOVOI_NEGATIVE_V1, else the sibling repo default.

Mix.install([{:jason, "~> 1.4"}])

import Bitwise

defmodule SigningBaseError, do: (defexception message: "")
defmodule ParseError, do: (defexception message: "")
defmodule WeakKeyError, do: (defexception message: "")

defmodule NegativeV1 do
  @default_path "../../corpus/rfc9421_negative_v1/rfc9421_negative_v1.json"

  @p Integer.pow(2, 255) - 19
  @l Integer.pow(2, 252) + 27_742_317_777_372_353_535_851_937_790_883_648_493
  @curves %{
    "p256" => %{
      field: 32, digest: :sha256, atom: :secp256r1,
      p: 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
      b: 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
      n: 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    },
    "p384" => %{
      field: 48, digest: :sha384, atom: :secp384r1,
      p: Integer.pow(2, 384) - Integer.pow(2, 128) - Integer.pow(2, 96) + Integer.pow(2, 32) - 1,
      b: 0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
      n: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
    }
  }

  # ================= signing base (port of signing_base.py) =================
  def build_signing_base(input, mode, spr) do
    unless mode in ["algovoi-v0", "rfc9421"], do: raise(SigningBaseError, message: "bad mode")
    if mode == "rfc9421" and spr == nil, do: raise(SigningBaseError, message: "rfc9421 needs spr")

    headers = for {k, v} <- input["headers"] || %{}, into: %{}, do: {String.downcase(k), v}
    params = input["parameters"] || %{}

    lines =
      Enum.map(input["covered_components"], fn component ->
        c = String.downcase(component)
        value =
          case c do
            "@method" ->
              v = str_or(input, "method", "@method covered but method not supplied")
              if mode == "rfc9421", do: v, else: String.downcase(v)
            "@authority" -> String.downcase(str_or(input, "authority", "@authority covered but authority not supplied"))
            "@path" -> str_or(input, "path", "@path covered but path not supplied")
            "@target-uri" -> str_or(input, "target_uri", "@target-uri covered but target_uri not supplied")
            "@scheme" -> String.downcase(str_or(input, "scheme", "@scheme covered but scheme not supplied"))
            "@status" ->
              if input["status"] == nil, do: raise(SigningBaseError, message: "@status covered but status not supplied")
              to_string(input["status"])
            "created" -> param_or(params, "created", "'created' covered but no 'created' parameter in Signature-Input")
            "expires" -> param_or(params, "expires", "'expires' covered but no 'expires' parameter in Signature-Input")
            _ ->
              if String.starts_with?(c, "@"), do: raise(SigningBaseError, message: "unsupported derived component: #{component}")
              case Map.fetch(headers, c) do
                {:ok, hv} -> hv
                :error -> raise(SigningBaseError, message: "covered header #{component} not present")
              end
          end
        "\"#{c}\": #{value}"
      end)

    lines = if mode == "rfc9421", do: lines ++ ["\"@signature-params\": #{spr}"], else: lines
    Enum.join(lines, "\n")
  end

  defp str_or(input, field, msg) do
    case input[field] do
      nil -> raise(SigningBaseError, message: msg)
      v -> v
    end
  end

  defp param_or(params, key, msg) do
    case Map.fetch(params, key) do
      {:ok, v} -> to_string(v)
      :error -> raise(SigningBaseError, message: msg)
    end
  end

  # ================= structured-field parse (port of parse.py) =================
  def parse_signature_input(nil), do: raise(ParseError, message: "header must be str")
  def parse_signature_input(header) do
    hv = String.trim(header)
    if hv == "", do: raise(ParseError, message: "empty header value")
    rest =
      case Regex.run(~r/^\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*/, hv) do
        [m | _] -> String.slice(hv, String.length(m)..-1//1)
        nil -> if String.starts_with?(hv, "("), do: hv, else: raise(ParseError, message: "no label")
      end
    unless Regex.match?(~r/^\(\s*(?:"[^"]*"\s*)*\)/, rest), do: raise(ParseError, message: "no covered list")
    :ok
  end

  def parse_signature_value(nil), do: raise(ParseError, message: "header must be str")
  def parse_signature_value(header) do
    hv = String.trim(header)
    if hv == "", do: raise(ParseError, message: "empty")
    rest =
      case Regex.run(~r/^\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*/, hv) do
        [m | _] -> String.trim(String.slice(hv, String.length(m)..-1//1))
        nil -> if String.starts_with?(hv, ":"), do: hv, else: raise(ParseError, message: "no prefix")
      end
    unless String.starts_with?(rest, ":") and String.ends_with?(rest, ":") and String.length(rest) >= 2,
      do: raise(ParseError, message: "not colon-wrapped")
    sig_b64 = String.slice(rest, 1..-2//1)
    case Base.decode64(sig_b64) do
      {:ok, decoded} -> if Base.encode64(decoded) != sig_b64, do: raise(ParseError, message: "non-canonical"), else: :ok
      :error -> raise(ParseError, message: "bad base64")
    end
  end

  # ================= Ed25519 key gate (port of keycheck.py) =================
  defp modp(a), do: rem(rem(a, @p) + @p, @p)
  defp pow_mod(b, e, m), do: :binary.decode_unsigned(:crypto.mod_pow(b, e, m))
  defp inv(a), do: pow_mod(modp(a), @p - 2, @p)
  defp d, do: modp(-121665 * inv(121666))
  defp sqrt_m1, do: pow_mod(2, div(@p - 1, 4), @p)

  defp recover_x(y, _sign) when y >= @p, do: nil
  defp recover_x(y, sign) do
    y2 = modp(y * y)
    x2 = modp(modp(y2 - 1) * inv(modp(d() * y2 + 1)))
    cond do
      x2 == 0 -> if sign == 1, do: nil, else: 0
      true ->
        x = pow_mod(x2, div(@p + 3, 8), @p)
        x = if modp(x * x - x2) != 0, do: modp(x * sqrt_m1()), else: x
        cond do
          modp(x * x - x2) != 0 -> nil
          (x &&& 1) != sign -> @p - x
          true -> x
        end
    end
  end

  defp decode_point(pk) when byte_size(pk) != 32, do: nil
  defp decode_point(pk) do
    full = :binary.decode_unsigned(pk, :little)
    sign = full >>> 255 &&& 1
    y = full &&& (1 <<< 255) - 1
    case recover_x(y, sign) do
      nil -> nil
      x -> {x, y, 1, modp(x * y)}
    end
  end

  defp padd({px, py, pz, pt}, {qx, qy, qz, qt}) do
    a = modp((py - px) * (qy - qx))
    b = modp((py + px) * (qy + qx))
    c = modp(2 * pt * qt * d())
    dd = modp(2 * pz * qz)
    e = b - a; f = dd - c; g = dd + c; h = b + a
    {modp(e * f), modp(g * h), modp(f * g), modp(e * h)}
  end

  defp mul8(p) do
    p2 = padd(p, p); p4 = padd(p2, p2); padd(p4, p4)
  end

  defp identity?({x, y, z, _t}), do: modp(x) == 0 and modp(y - z) == 0

  def small_order(pk) do
    case decode_point(pk) do
      nil -> false
      p -> identity?(mul8(p))
    end
  end

  def check_ed25519_public_key(pk) do
    case decode_point(pk) do
      nil -> raise(WeakKeyError, message: "non-canonical/off-curve")
      p -> if identity?(mul8(p)), do: raise(WeakKeyError, message: "small-order"), else: :ok
    end
  end

  # ================= Ed25519 verify (port of verify.py) =================
  def ed25519_verify(_msg, sig, _pk) when byte_size(sig) != 64, do: false
  def ed25519_verify(_msg, _sig, pk) when byte_size(pk) != 32, do: false
  def ed25519_verify(msg, sig, pk) do
    try do
      check_ed25519_public_key(pk)
      s = :binary.decode_unsigned(binary_part(sig, 32, 32), :little)
      if s >= @l do
        false
      else
        :crypto.verify(:eddsa, :none, msg, sig, [pk, :ed25519])
      end
    rescue
      _ -> false
    end
  end

  # ================= ECDSA verify (port of algovoi-rfc9421-ecdsa) =================
  defp der_int(i) do
    bytes = :binary.encode_unsigned(i)
    bytes = if (:binary.first(bytes) &&& 0x80) != 0, do: <<0>> <> bytes, else: bytes
    <<0x02, byte_size(bytes)>> <> bytes
  end

  def ecdsa_verify(curve, msg, sig, pub, strict) do
    cfg = @curves[curve]
    fs = cfg.field
    cond do
      byte_size(sig) != 2 * fs -> false
      byte_size(pub) != 1 + 2 * fs or :binary.first(pub) != 0x04 -> false
      true ->
        r = :binary.decode_unsigned(binary_part(sig, 0, fs))
        s = :binary.decode_unsigned(binary_part(sig, fs, fs))
        n = cfg.n
        cond do
          r < 1 or r > n - 1 or s < 1 or s > n - 1 -> false
          strict and s > div(n, 2) -> false
          true ->
            x = :binary.decode_unsigned(binary_part(pub, 1, fs))
            y = :binary.decode_unsigned(binary_part(pub, 1 + fs, fs))
            lhs = Integer.mod(y * y, cfg.p)
            rhs = Integer.mod(x * x * x - 3 * x + cfg.b, cfg.p)
            if lhs != rhs do
              false
            else
              der = (fn c -> <<0x30, byte_size(c)>> <> c end).(der_int(r) <> der_int(s))
              try do
                :crypto.verify(:ecdsa, cfg.digest, msg, der, [pub, cfg.atom])
              rescue
                _ -> false
              end
            end
        end
    end
  end

  # ================= driver =================
  defp hexb(s), do: Base.decode16!(s, case: :lower)

  def main(argv) do
    path = List.first(argv) || System.get_env("ALGOVOI_NEGATIVE_V1") || @default_path
    corpus = Jason.decode!(File.read!(path))
    results = []

    results = results ++ Enum.map(corpus["signing_base"], fn c ->
      want = Base.decode64!(c["signing_base_b64"])
      ok = try do
        c["ok"] and build_signing_base(c["in"], c["mode"], c["signature_params_raw"]) == want
      rescue _ -> not c["ok"] end
      {ok, "signing_base", c["note"]}
    end)

    results = results ++ Enum.map(corpus["signature_input_parse"], fn c ->
      p = try do parse_signature_input(c["header"]); true rescue ParseError -> false end
      {p == c["ok"], "sig_input_parse", c["note"]}
    end)

    results = results ++ Enum.map(corpus["signature_value_parse"], fn c ->
      p = try do parse_signature_value(c["header"]); true rescue ParseError -> false end
      {p == c["ok"], "sig_value_parse", c["note"]}
    end)

    results = results ++ Enum.map(corpus["keygate"], fn c ->
      raw = hexb(c["pk_hex"])
      rejected = try do check_ed25519_public_key(raw); nil rescue WeakKeyError -> "WeakKeyError" end
      {rejected == c["rejected"] and small_order(raw) == c["small_order"], "keygate", c["note"]}
    end)

    results = results ++ Enum.map(corpus["ed25519_verify"], fn c ->
      base = Base.decode64!(c["signing_base_b64"])
      valid = ed25519_verify(base, hexb(c["sig_hex"]), hexb(c["pk_hex"]))
      {valid == c["expect_valid"], "ed25519_verify", c["note"]}
    end)

    results = results ++ Enum.map(corpus["ecdsa_verify"], fn c ->
      valid = ecdsa_verify(c["curve"], hexb(c["msg_hex"]), hexb(c["sig_raw_hex"]),
                           hexb(c["pub_uncompressed_hex"]), c["strict_low_s"] == true)
      {valid == c["expect_valid"], "ecdsa_verify", c["note"]}
    end)

    fails = Enum.filter(results, fn {ok, _, _} -> not ok end)
    Enum.each(fails, fn {_, s, n} -> IO.puts("FAIL  [#{s}] #{n}") end)
    matched = Enum.count(results, fn {ok, _, _} -> ok end)
    IO.puts("\nelixir: #{matched}/#{length(results)} cases matched")
    System.halt(if length(fails) == 0, do: 0, else: 1)
  end
end

NegativeV1.main(System.argv())
