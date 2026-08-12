# Elixir runner for the Structured Field Values corpus (sfv_v0).
#
# Independently reproduces every verdict in the frozen corpus: parse `input` as
# its declared field type (item|list|dictionary), and if it parses, serialize it
# canonically (RFC 8941 Section 4.1) and compare to the frozen `canonical`. A
# case matches iff parse_ok == expect_parse_ok and, when ok, the canonical bytes
# are equal.
#
# No canonical RFC 8941 library ships for Elixir, so this is a compact hand-rolled
# RFC 8941 parser + canonical serializer, ported from the reference
# tools/oracle_sfv.py. JSON via jason (same dep as the sibling elixir runner).
# Independence for the profile comes from the five native-library runners
# (typescript/go/rust/ruby/php) and the http_sfv KAT gate.
#
# Corpus path: argv[0], else ../../corpus/sfv_v0/sfv_v0.json. Exit 0 iff all match.

Mix.install([{:jason, "~> 1.4"}])

defmodule SFVError, do: (defexception message: "")

defmodule Sfv do
  @default_path "../../corpus/sfv_v0/sfv_v0.json"
  @sections ~w(sfv_item sfv_list sfv_dictionary sfv_parameters sfv_canonical sfv_reject)

  @int_min -999_999_999_999_999
  @int_max 999_999_999_999_999

  @digits ~c"0123456789"
  @lcalpha ~c"abcdefghijklmnopqrstuvwxyz"
  @ucalpha ~c"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  @token_tail @lcalpha ++ @ucalpha ++ @digits ++ ~c"!#$%&'*+-.^_`|~:/"
  @key_tail @lcalpha ++ @digits ++ ~c"_-.*"
  @b64_alphabet ~c"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

  defp raise_sfv(m), do: raise(SFVError, message: m)

  defp at(s, i) when i < byte_size(s), do: :binary.at(s, i)
  defp at(_s, _i), do: nil

  defp digit?(c), do: c != nil and c in @digits
  defp lcalpha?(c), do: c != nil and c in @lcalpha
  defp alpha?(c), do: c != nil and (c in @lcalpha or c in @ucalpha)

  defp discard_sp(s, i) do
    if at(s, i) == ?\s, do: discard_sp(s, i + 1), else: i
  end

  defp discard_ows(s, i) do
    c = at(s, i)
    if c == ?\s or c == ?\t, do: discard_ows(s, i + 1), else: i
  end

  # ---- bare item ----
  defp bare_item(s, i) do
    c = at(s, i)

    cond do
      c == nil -> raise_sfv("empty bare item")
      c == ?- or digit?(c) -> number(s, i)
      c == ?" -> {val, i2} = parse_string(s, i); {{:string, val}, i2}
      c == ?: -> {val, i2} = byteseq(s, i); {{:bytes, val}, i2}
      c == ?? -> {val, i2} = boolean(s, i); {{:boolean, val}, i2}
      c == ?* or alpha?(c) -> {val, i2} = token(s, i); {{:token, val}, i2}
      true -> raise_sfv("unexpected char starting a bare item")
    end
  end

  defp number(s, i) do
    {sign, i} = if at(s, i) == ?-, do: {-1, i + 1}, else: {1, i}
    if not digit?(at(s, i)), do: raise_sfv("number with no digits")
    {num, is_decimal, i} = number_loop(s, i, "", false)

    if not is_decimal do
      v = sign * String.to_integer(num)
      if v < @int_min or v > @int_max, do: raise_sfv("integer out of range")
      {{:integer, v}, i}
    else
      if String.ends_with?(num, "."), do: raise_sfv("decimal ends with a dot")
      dot = :binary.match(num, ".") |> elem(0)
      if byte_size(num) - dot - 1 > 3, do: raise_sfv("too many fractional digits")
      dec = ser_decimal(sign, binary_part(num, 0, dot), binary_part(num, dot + 1, byte_size(num) - dot - 1))
      {{:decimal, dec}, i}
    end
  end

  defp number_loop(s, i, num, is_decimal) do
    c = at(s, i)

    cond do
      digit?(c) ->
        num = num <> <<c>>
        check_num_len(num, is_decimal)
        number_loop(s, i + 1, num, is_decimal)

      not is_decimal and c == ?. ->
        if byte_size(num) > 12, do: raise_sfv("too many integer digits before decimal")
        num = num <> "."
        check_num_len(num, true)
        number_loop(s, i + 1, num, true)

      true ->
        {num, is_decimal, i}
    end
  end

  defp check_num_len(num, false) do
    if byte_size(num) > 15, do: raise_sfv("integer too long")
  end

  defp check_num_len(num, true) do
    if byte_size(num) > 16, do: raise_sfv("decimal too long")
  end

  defp parse_string(s, i) do
    parse_string_loop(s, i + 1, [])
  end

  defp parse_string_loop(s, i, acc) do
    c = at(s, i)

    cond do
      c == nil ->
        raise_sfv("unterminated string")

      c == ?\\ ->
        nxt = at(s, i + 1)
        if nxt == nil, do: raise_sfv("trailing backslash in string")
        if nxt != ?" and nxt != ?\\, do: raise_sfv("bad string escape")
        parse_string_loop(s, i + 2, [nxt | acc])

      c == ?" ->
        {acc |> Enum.reverse() |> List.to_string(), i + 1}

      c < 0x20 or c > 0x7E ->
        raise_sfv("control char in string")

      true ->
        parse_string_loop(s, i + 1, [c | acc])
    end
  end

  defp token(s, i) do
    start = i
    i = token_loop(s, i + 1)
    {binary_part(s, start, i - start), i}
  end

  defp token_loop(s, i) do
    c = at(s, i)
    if c != nil and c in @token_tail, do: token_loop(s, i + 1), else: i
  end

  defp byteseq(s, i) do
    start = i + 1
    i = byteseq_loop(s, start)
    if at(s, i) == nil, do: raise_sfv("unterminated byte sequence")
    content = binary_part(s, start, i - start)
    {strict_b64_decode(content), i + 1}
  end

  defp byteseq_loop(s, i) do
    c = at(s, i)

    cond do
      c == nil -> i
      c == ?: -> i
      c in @b64_alphabet -> byteseq_loop(s, i + 1)
      true -> raise_sfv("non-base64 char")
    end
  end

  defp boolean(s, i) do
    case at(s, i + 1) do
      ?1 -> {true, i + 2}
      ?0 -> {false, i + 2}
      _ -> raise_sfv("boolean must be ?0 or ?1")
    end
  end

  defp key(s, i) do
    c = at(s, i)
    if not (lcalpha?(c) or c == ?*), do: raise_sfv("key must start with lcalpha or *")
    start = i
    i = key_loop(s, i + 1)
    {binary_part(s, start, i - start), i}
  end

  defp key_loop(s, i) do
    c = at(s, i)
    if c != nil and c in @key_tail, do: key_loop(s, i + 1), else: i
  end

  defp parameters(s, i), do: parameters_loop(s, i, [])

  defp parameters_loop(s, i, acc) do
    if at(s, i) == ?; do
      i = discard_sp(s, i + 1)
      {k, i} = key(s, i)

      {value, i} =
        if at(s, i) == ?= do
          bare_item(s, i + 1)
        else
          {{:boolean, true}, i}
        end

      acc = List.keydelete(acc, k, 0) ++ [{k, value}]
      parameters_loop(s, i, acc)
    else
      {acc, i}
    end
  end

  defp item(s, i) do
    {bare, i} = bare_item(s, i)
    {params, i} = parameters(s, i)
    {{:item, bare, params}, i}
  end

  defp inner_list(s, i), do: inner_list_loop(s, i + 1, [])

  defp inner_list_loop(s, i, members) do
    i = discard_sp(s, i)
    c = at(s, i)

    cond do
      c == ?) ->
        {params, i} = parameters(s, i + 1)
        {{:inner_list, Enum.reverse(members), params}, i}

      c == nil ->
        raise_sfv("unterminated inner list")

      true ->
        {bare, i} = bare_item(s, i)
        {params, i} = parameters(s, i)
        nxt = at(s, i)
        if nxt != ?\s and nxt != ?), do: raise_sfv("inner-list items must be space separated")
        inner_list_loop(s, i, [{bare, params} | members])
    end
  end

  defp item_or_inner_list(s, i) do
    if at(s, i) == ?(, do: inner_list(s, i), else: item(s, i)
  end

  defp parse_list(s, i) do
    i = discard_sp(s, i)
    if at(s, i) == nil, do: {[], i}, else: parse_list_loop(s, i, [])
  end

  defp parse_list_loop(s, i, members) do
    {node, i} = item_or_inner_list(s, i)
    members = [node | members]
    i = discard_ows(s, i)

    cond do
      at(s, i) == nil ->
        {Enum.reverse(members), i}

      at(s, i) != ?, ->
        raise_sfv("list members must be comma separated")

      true ->
        i = discard_ows(s, i + 1)
        if at(s, i) == nil, do: raise_sfv("trailing comma in list")
        parse_list_loop(s, i, members)
    end
  end

  defp parse_dictionary(s, i) do
    i = discard_sp(s, i)
    if at(s, i) == nil, do: {[], i}, else: parse_dict_loop(s, i, [])
  end

  defp parse_dict_loop(s, i, members) do
    {k, i} = key(s, i)

    {value, i} =
      if at(s, i) == ?= do
        item_or_inner_list(s, i + 1)
      else
        {params, i} = parameters(s, i)
        {{:item, {:boolean, true}, params}, i}
      end

    members = List.keydelete(members, k, 0) ++ [{k, value}]
    i = discard_ows(s, i)

    cond do
      at(s, i) == nil ->
        {members, i}

      at(s, i) != ?, ->
        raise_sfv("dictionary members must be comma separated")

      true ->
        i = discard_ows(s, i + 1)
        if at(s, i) == nil, do: raise_sfv("trailing comma in dictionary")
        parse_dict_loop(s, i, members)
    end
  end

  defp strict_b64_decode(content) do
    if rem(byte_size(content), 4) != 0, do: raise_sfv("bad base64 length")

    case Base.decode64(content) do
      {:ok, bin} -> bin
      :error -> raise_sfv("invalid base64")
    end
  end

  # ---- serialization ----
  defp ser_decimal(sign, intpart, frac) do
    frac3 = binary_part(frac <> "000", 0, 3)
    stripped0 = String.trim_trailing(frac3, "0")
    stripped = if stripped0 == "", do: "0", else: stripped0
    intpart = if intpart == "", do: "0", else: intpart
    whole = String.to_integer(intpart)
    if whole >= 1_000_000_000_000, do: raise_sfv("decimal integer part too large")
    is_zero = whole == 0 and stripped == "0"
    neg = if sign < 0 and not is_zero, do: "-", else: ""
    neg <> Integer.to_string(whole) <> "." <> stripped
  end

  defp ser_bare({:integer, v}) do
    if v < @int_min or v > @int_max, do: raise_sfv("integer out of range")
    Integer.to_string(v)
  end

  defp ser_bare({:decimal, d}), do: d

  defp ser_bare({:string, v}) do
    inner =
      v
      |> String.to_charlist()
      |> Enum.map(fn c ->
        if c < 0x20 or c > 0x7E, do: raise_sfv("control char in string")
        if c == ?" or c == ?\\, do: <<?\\, c>>, else: <<c>>
      end)
      |> IO.iodata_to_binary()

    "\"" <> inner <> "\""
  end

  defp ser_bare({:token, v}), do: v
  defp ser_bare({:bytes, v}), do: ":" <> Base.encode64(v) <> ":"
  defp ser_bare({:boolean, true}), do: "?1"
  defp ser_bare({:boolean, false}), do: "?0"

  defp bool_true?({:boolean, true}), do: true
  defp bool_true?(_), do: false

  defp ser_params(params) do
    Enum.map_join(params, "", fn {k, v} ->
      if bool_true?(v), do: ";" <> k, else: ";" <> k <> "=" <> ser_bare(v)
    end)
  end

  defp ser_member({:inner_list, members, params}) do
    inner = Enum.map_join(members, " ", fn {bare, ps} -> ser_bare(bare) <> ser_params(ps) end)
    "(" <> inner <> ")" <> ser_params(params)
  end

  defp ser_member({:item, bare, params}), do: ser_bare(bare) <> ser_params(params)

  defp serialize("item", node), do: ser_member(node)
  defp serialize("list", members), do: Enum.map_join(members, ", ", &ser_member/1)

  defp serialize("dictionary", members) do
    Enum.map_join(members, ", ", fn {k, node} ->
      case node do
        {:item, {:boolean, true}, params} -> k <> ser_params(params)
        _ -> k <> "=" <> ser_member(node)
      end
    end)
  end

  defp non_ascii?(s), do: :binary.bin_to_list(s) |> Enum.any?(&(&1 > 127))

  def verdict(field_type, text) do
    try do
      if non_ascii?(text), do: raise_sfv("non-ASCII in field value")

      {value, i} =
        case field_type do
          "item" -> item(text, discard_sp(text, 0))
          "list" -> parse_list(text, 0)
          "dictionary" -> parse_dictionary(text, 0)
          _ -> raise_sfv("unknown field type")
        end

      i = discard_sp(text, i)
      if at(text, i) != nil, do: raise_sfv("trailing characters after value")

      canon = serialize(field_type, value)
      {true, canon}
    rescue
      SFVError -> {false, nil}
    end
  end

  def main(argv) do
    path = List.first(argv) || @default_path
    corpus = Jason.decode!(File.read!(path))

    results =
      Enum.flat_map(@sections, fn sec ->
        Enum.map(corpus[sec] || [], fn c ->
          {ok, canon} = verdict(c["field_type"], c["input"])
          match = ok == c["expect_parse_ok"] and (not ok or canon == c["canonical"])
          {match, sec, c["note"]}
        end)
      end)

    fails = Enum.filter(results, fn {m, _, _} -> not m end)
    Enum.each(fails, fn {_, s, n} -> IO.puts("FAIL  [#{s}] #{n}") end)
    matched = Enum.count(results, fn {m, _, _} -> m end)
    total = length(results)
    IO.puts("\nelixir (sfv): #{matched}/#{total} cases matched")
    System.halt(if length(fails) == 0, do: 0, else: 1)
  end
end

Sfv.main(System.argv())
