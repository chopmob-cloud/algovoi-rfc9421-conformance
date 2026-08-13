# Elixir runner for the post-quantum ML-DSA-65 corpus (pqc_mldsa_v0).
#
# Independent Elixir port of the Python reference runner
# (runners/python/verify_pqc_mldsa.py) and its decision surface
# (tools/oracle_pqc_mldsa.py): decode the hex public key, message and signature,
# reject a wrong-length public key (must be 1952) or signature (must be 3309)
# before any verify, then verify the FIPS-204 ML-DSA-65 signature over the exact
# message bytes with the EMPTY context string (the pure ML-DSA variant).
#
# Erlang/OTP's :crypto is built against an OpenSSL that predates ML-DSA (FIPS 204
# landed in OpenSSL 3.5; the OTP-26 image ships OpenSSL 3.0.20, whose public-key
# set has no ML-DSA), OTP has no built-in FFI, and there is no mature FIPS-204
# NIF on hex. So this runner keeps the ENTIRE decision surface in the BEAM (hex
# decode, wrong-length rejection) and shells out through an Erlang port
# (System.cmd) to a tiny C helper (mldsa_verify_helper.c) for the ONE primitive
# it cannot do in-VM: the raw ML-DSA-65 verify. The helper links liboqs, the same
# C reference the C runner uses; OQS_SIG_new returns NULL on an old Dilithium-only
# build, which the helper surfaces as exit 2 (the built-in tripwire).
#
# The helper is compiled on first run (cc ... -loqs) next to this script, so a
# single `elixir verify_pqc_mldsa.exs corpus.json` works given liboqs + a C
# compiler. Requires jason for JSON.
#
# Corpus path: argv[0], else the repo corpus relative to this source directory.
#
# Run:  cd runners/elixir && elixir verify_pqc_mldsa.exs [corpus.json]

Mix.install([{:jason, "~> 1.4"}])

defmodule VerifyPqcMldsa do
  @default_path "../../corpus/pqc_mldsa_v0/pqc_mldsa_v0.json"
  @sections ~w(mldsa65_verify mldsa65_malformed mldsa65_acvp_kat)

  @pk_len 1952
  @sig_len 3309

  # hex -> binary; :error on odd length or a bad digit. An empty string decodes
  # to a real 0-byte value, so the empty-message case is a real 0-byte message.
  defp hexdec(s) when is_binary(s) do
    if rem(byte_size(s), 2) == 0 and String.match?(s, ~r/\A[0-9a-fA-F]*\z/) do
      {:ok, Base.decode16!(s, case: :mixed)}
    else
      :error
    end
  end

  defp hexdec(_), do: :error

  # The BEAM-side decision surface: reject a malformed public key / signature
  # (wrong byte length, empty included) before any verify, exactly as the Python
  # oracle does. Only a well-formed, correctly sized triple reaches the helper.
  defp verdict(helper, pk_hex, msg_hex, sig_hex) do
    with {:ok, pk} <- hexdec(pk_hex),
         {:ok, _msg} <- hexdec(msg_hex),
         {:ok, sig} <- hexdec(sig_hex),
         true <- byte_size(pk) == @pk_len,
         true <- byte_size(sig) == @sig_len do
      # Empty message stays an empty argv element (a real 0-byte message).
      {_out, status} =
        System.cmd(helper, [pk_hex, msg_hex, sig_hex], stderr_to_stdout: true)

      case status do
        0 -> true
        1 -> false
        _ -> raise "mldsa_verify_helper failed (exit #{status}); is liboqs ML-DSA-65 present?"
      end
    else
      _ -> false
    end
  end

  # Compile the liboqs C helper next to this script on first run; reuse it after.
  defp ensure_helper(dir) do
    bin = Path.join(dir, "mldsa_verify_helper")
    src = Path.join(dir, "mldsa_verify_helper.c")

    unless File.exists?(bin) do
      {out, status} =
        System.cmd("cc", ["-O2", "-w", "-o", bin, src, "-loqs"], stderr_to_stdout: true)

      if status != 0 do
        IO.puts(:stderr, "failed to build mldsa_verify_helper:\n#{out}")
        System.halt(2)
      end
    end

    bin
  end

  def main(argv) do
    dir = __DIR__
    path = List.first(argv) || Path.join(dir, @default_path)
    helper = ensure_helper(dir)
    corpus = Jason.decode!(File.read!(path))

    results =
      Enum.flat_map(@sections, fn sec ->
        Enum.map(corpus[sec] || [], fn c ->
          accept = verdict(helper, c["public_key"], c["message"], c["signature"])
          {accept == c["expect_valid"], sec, c["note"]}
        end)
      end)

    fails = Enum.filter(results, fn {ok, _, _} -> not ok end)
    Enum.each(fails, fn {_, s, n} -> IO.puts("FAIL  [#{s}] #{n}") end)
    matched = Enum.count(results, fn {ok, _, _} -> ok end)
    total = length(results)
    IO.puts("\nelixir (pqc_mldsa): #{matched}/#{total} cases matched")
    System.halt(if length(fails) == 0, do: 0, else: 1)
  end
end

VerifyPqcMldsa.main(System.argv())
