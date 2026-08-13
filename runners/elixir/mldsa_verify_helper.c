/* Tiny liboqs verify helper for the Elixir ML-DSA-65 runner (pqc_mldsa_v0).
 *
 * Erlang/OTP has no built-in FFI, so the Elixir runner (verify_pqc_mldsa.exs)
 * shells out to this helper for the ONE thing it cannot do in-VM: the FIPS-204
 * ML-DSA-65 cryptographic verify. The runner keeps the whole decision surface
 * (hex decode, wrong-length public-key/signature rejection) and only invokes
 * this helper for the raw verify, exactly mirroring the C runner
 * (runners/c/verify_pqc_mldsa.c) and the Python decision surface
 * (tools/oracle_pqc_mldsa.py).
 *
 * Contract: argv[1]=public_key_hex, argv[2]=message_hex, argv[3]=signature_hex.
 * Exit 0 iff the FIPS-204 ML-DSA-65 signature verifies over the exact message
 * bytes with the EMPTY context string (the pure ML-DSA variant); exit 1 on a
 * valid-shaped but non-verifying input; exit 2 on any usage/decode error or if
 * the installed liboqs is an old build that exposes only round-3 "Dilithium3"
 * and not "ML-DSA-65" (the built-in tripwire).
 *
 * The runner has already length-gated the inputs, but this helper re-checks the
 * fixed FIPS-204 lengths as a defensive measure and passes the message through
 * verbatim (empty message included).
 *
 * Build:  cc -O2 -w -o mldsa_verify_helper mldsa_verify_helper.c -loqs
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

#define PK_LEN 1952
#define SIG_LEN 3309

static int nib(char c){
    if(c>='0'&&c<='9') return c-'0';
    if(c>='a'&&c<='f') return c-'a'+10;
    if(c>='A'&&c<='F') return c-'A'+10;
    return -1;
}

/* hex decode into a malloc'd buffer; NULL on odd length or a bad digit. An empty
 * string decodes to a zero-length buffer (non-NULL), so an empty message is a
 * real 0-byte message, not a decode failure. */
static unsigned char *hexdec(const char *s, size_t *outlen){
    if(!s) return NULL;
    size_t n = strlen(s);
    if(n % 2) return NULL;
    size_t bl = n / 2;
    unsigned char *b = malloc(bl ? bl : 1);
    if(!b) return NULL;
    for(size_t i=0;i<bl;i++){
        int hi = nib(s[2*i]), lo = nib(s[2*i+1]);
        if(hi<0 || lo<0){ free(b); return NULL; }
        b[i] = (unsigned char)((hi<<4)|lo);
    }
    *outlen = bl;
    return b;
}

int main(int argc, char **argv){
    if(argc != 4) return 2;
    size_t pl=0, ml=0, sl=0;
    unsigned char *pk = hexdec(argv[1], &pl);
    unsigned char *msg = hexdec(argv[2], &ml);
    unsigned char *sig = hexdec(argv[3], &sl);
    if(!pk || !msg || !sig || pl != PK_LEN || sl != SIG_LEN){
        free(pk); free(msg); free(sig);
        return 2;
    }
    OQS_SIG *v = OQS_SIG_new("ML-DSA-65");
    if(!v){
        fprintf(stderr, "liboqs has no ML-DSA-65 (old/Dilithium build)\n");
        free(pk); free(msg); free(sig);
        return 2;
    }
    int ok = (OQS_SIG_verify(v, msg, ml, sig, sl, pk) == OQS_SUCCESS);
    OQS_SIG_free(v);
    free(pk); free(msg); free(sig);
    return ok ? 0 : 1;
}
