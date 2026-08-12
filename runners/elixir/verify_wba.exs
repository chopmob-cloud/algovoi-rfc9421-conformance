# Elixir runner for the Web Bot Auth profile corpus (webbotauth_v0).
#
# Independent Elixir port of the Python reference runner
# (runners/python/verify_wba.py) and its independent KAT gate
# (tools/check_kat_wba.py). Every PROFILE rule (signing base, coverage
# completeness, freshness window, directory keyid resolution, Signature-Agent
# SSRF, and the Ed25519 signature verdict over the profile signing base) is
# re-implemented here directly from the corpus `policy` block, NOT imported from
# a shared oracle, so a runner passing is genuine agreement rather than an echo.
# This mirrors the Python/Go/TypeScript reference runners case for case.
#
# Self-contained: JSON via jason (matching the sibling negative_v1.exs), CIDR
# membership via :inet.parse_address + bignum bitmask on the address tuple, and
# Ed25519 verification via Erlang :crypto (:eddsa), exactly like the sibling.
#
# Corpus path: argv[0], else the repo corpus relative to this source directory.
#
# Run:  cd runners/elixir && elixir verify_wba.exs [corpus.json]

Mix.install([{:jason, "~> 1.4"}])

import Bitwise

defmodule SigningBaseError, do: (defexception message: "")

defmodule VerifyWba do
  @default_path "../../corpus/webbotauth_v0/webbotauth_v0.json"

  # ------------------------------------------------------------------
  # Rule 1: RFC 9421 Section 2.5 signing base, by direct concatenation.
  # Raises SigningBaseError when a covered component's value is missing
  # (build impossible); the driver maps that to "unbuildable".
  # ------------------------------------------------------------------
  def build_signing_base(src, params_raw) do
    headers = src["headers"] || %{}

    lines =
      Enum.map(src["covered_components"], fn comp ->
        name = String.downcase(comp)

        val =
          case name do
            "@authority" -> fetch!(src, "authority")
            "@method" -> fetch!(src, "method")
            "@path" -> fetch!(src, "path")
            _ ->
              case Map.fetch(headers, name) do
                {:ok, v} when not is_nil(v) -> v
                _ -> raise(SigningBaseError, message: "missing covered component: #{name}")
              end
          end

        "\"#{name}\": #{val}"
      end)

    Enum.join(lines ++ ["\"@signature-params\": #{params_raw}"], "\n")
  end

  defp fetch!(map, key) do
    case Map.fetch(map, key) do
      {:ok, v} when not is_nil(v) -> v
      _ -> raise(SigningBaseError, message: "missing #{key}")
    end
  end

  # ------------------------------------------------------------------
  # Rule 2: coverage completeness (every required component present,
  # compared case-insensitively).
  # ------------------------------------------------------------------
  def coverage_ok(covered, policy) do
    have = MapSet.new(covered || [], &String.downcase/1)
    Enum.all?(policy["required_covered_components"], fn r -> MapSet.member?(have, String.downcase(r)) end)
  end

  # ------------------------------------------------------------------
  # Rule 3: freshness window. All three must be integers, expires > created,
  # and (created - skew) <= now < expires.
  # ------------------------------------------------------------------
  def freshness_ok(created, expires, now, policy) do
    skew = Map.get(policy, "clock_skew_seconds", 0)

    cond do
      not (is_integer(created) and is_integer(expires) and is_integer(now)) -> false
      expires <= created -> false
      true -> created - skew <= now and now < expires
    end
  end

  # ------------------------------------------------------------------
  # Rule 4: directory keyid resolution to a usable Ed25519 JWK.
  # First JWK whose kid matches decides; if none match, reject.
  # ------------------------------------------------------------------
  def directory_ok(directory, keyid) do
    case Enum.find(directory || [], fn j -> Map.get(j, "kid") == keyid end) do
      nil -> false
      j -> Map.get(j, "kty") == "OKP" and Map.get(j, "crv") == "Ed25519" and Map.get(j, "x") not in [nil, ""]
    end
  end

  # ------------------------------------------------------------------
  # Rule 5: Signature-Agent SSRF guard. https required, userinfo rejected,
  # host IP-literal (v4 or [v6]) else resolved_ip; reject if the address is
  # in ANY denied CIDR of the same IP version.
  # ------------------------------------------------------------------
  def ssrf_ok(url, resolved_ip, policy) do
    ssrf = policy["ssrf"] || %{}
    uri = URI.parse(url)
    scheme = String.downcase(uri.scheme || "")

    cond do
      Map.get(ssrf, "require_https", true) and scheme != "https" -> false
      not is_nil(uri.userinfo) -> false
      is_nil(uri.host) or uri.host == "" -> false
      true ->
        host = strip_brackets(uri.host)

        addr =
          case :inet.parse_address(String.to_charlist(host)) do
            {:ok, t} -> t
            {:error, _} ->
              if resolved_ip in [nil, ""] do
                :none
              else
                case :inet.parse_address(String.to_charlist(resolved_ip)) do
                  {:ok, t} -> t
                  {:error, _} -> :none
                end
              end
          end

        cond do
          addr == :none -> false
          denied?(addr, Map.get(ssrf, "denied_cidrs", [])) -> false
          true -> true
        end
    end
  end

  defp strip_brackets(host) do
    if String.starts_with?(host, "[") and String.ends_with?(host, "]") do
      String.slice(host, 1..-2//1)
    else
      host
    end
  end

  defp denied?(addr, cidrs) do
    Enum.any?(cidrs, fn cidr ->
      case parse_cidr(cidr) do
        {net_addr, prefix} -> version(net_addr) == version(addr) and in_cidr?(addr, net_addr, prefix)
        :error -> false
      end
    end)
  end

  defp parse_cidr(cidr) do
    case String.split(cidr, "/") do
      [a, p] ->
        with {:ok, tuple} <- :inet.parse_address(String.to_charlist(a)),
             {n, ""} <- Integer.parse(p) do
          {tuple, n}
        else
          _ -> :error
        end

      _ -> :error
    end
  end

  # Same-version CIDR membership by bignum bitmask on the address tuple.
  defp in_cidr?(addr, net_addr, prefix) do
    total = bits(version(addr))
    full = (1 <<< total) - 1
    host_bits = total - prefix
    mask = bxor(full, (1 <<< host_bits) - 1)
    (addr_to_int(addr) &&& mask) == (addr_to_int(net_addr) &&& mask)
  end

  defp version(t) when tuple_size(t) == 4, do: 4
  defp version(t) when tuple_size(t) == 8, do: 6
  defp bits(4), do: 32
  defp bits(6), do: 128

  defp addr_to_int(t) do
    shift = if tuple_size(t) == 4, do: 8, else: 16
    t |> Tuple.to_list() |> Enum.reduce(0, fn g, acc -> (acc <<< shift) ||| g end)
  end

  # ------------------------------------------------------------------
  # Rule 6: Ed25519 verify of the raw signing-base bytes under a raw
  # 32-byte key, via Erlang :crypto.
  # ------------------------------------------------------------------
  def ed25519_ok(base, sig_hex, pk_hex) do
    with {:ok, pk} <- Base.decode16(sig_or_key(pk_hex), case: :lower),
         true <- byte_size(pk) == 32,
         {:ok, sig} <- Base.decode16(sig_or_key(sig_hex), case: :lower) do
      try do
        :crypto.verify(:eddsa, :none, base, sig, [pk, :ed25519])
      rescue
        _ -> false
      end
    else
      _ -> false
    end
  end

  defp sig_or_key(nil), do: ""
  defp sig_or_key(s), do: s

  # base64 decode that tolerates padded and unpadded input.
  defp b64decode(s) do
    case Base.decode64(s) do
      {:ok, b} -> {:ok, b}
      :error -> Base.decode64(s, padding: false)
    end
  end

  # ------------------------------------------------------------------
  # Driver.
  # ------------------------------------------------------------------
  def main(argv) do
    path = List.first(argv) || @default_path
    corpus = Jason.decode!(File.read!(path))
    policy = corpus["policy"]
    results = []

    results =
      results ++
        Enum.map(corpus["wba_signing_base"], fn c ->
          # Build FIRST; `c["ok"] and build(...)` would short-circuit negative
          # cases and never exercise the build-failure path.
          {built, buildable} =
            try do
              {build_signing_base(c["in"], c["signature_params_raw"]), true}
            rescue
              _ -> {nil, false}
            end

          matched =
            if not buildable do
              not c["ok"]
            else
              case b64decode(c["signing_base_b64"]) do
                {:ok, decoded} -> c["ok"] and built == decoded
                :error -> false
              end
            end

          {matched, "wba_signing_base", c["note"]}
        end)

    results =
      results ++
        Enum.map(corpus["wba_coverage"], fn c ->
          {coverage_ok(c["covered_components"], policy) == c["expect_accept"], "wba_coverage", c["note"]}
        end)

    results =
      results ++
        Enum.map(corpus["wba_freshness"], fn c ->
          {freshness_ok(c["created"], c["expires"], c["now"], policy) == c["expect_accept"], "wba_freshness",
           c["note"]}
        end)

    results =
      results ++
        Enum.map(corpus["wba_directory"], fn c ->
          {directory_ok(c["directory"], c["keyid"]) == c["expect_accept"], "wba_directory", c["note"]}
        end)

    results =
      results ++
        Enum.map(corpus["wba_directory_ssrf"], fn c ->
          {ssrf_ok(c["signature_agent_url"], c["resolved_ip"], policy) == c["expect_fetch_allowed"],
           "wba_directory_ssrf", c["note"]}
        end)

    results =
      results ++
        Enum.map(corpus["wba_ed25519_verify"], fn c ->
          valid =
            case b64decode(c["signing_base_b64"]) do
              {:ok, base} -> ed25519_ok(base, c["sig_hex"], c["pk_hex"])
              :error -> false
            end

          {valid == c["expect_valid"], "wba_ed25519_verify", c["note"]}
        end)

    fails = Enum.filter(results, fn {ok, _, _} -> not ok end)
    Enum.each(fails, fn {_, s, n} -> IO.puts("FAIL  [#{s}] #{n}") end)
    matched = Enum.count(results, fn {ok, _, _} -> ok end)
    total = length(results)
    IO.puts("\nelixir (wba): #{matched}/#{total} cases matched")
    System.halt(if length(fails) == 0, do: 0, else: 1)
  end
end

VerifyWba.main(System.argv())
