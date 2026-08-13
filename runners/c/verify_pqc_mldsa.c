/* C runner for the post-quantum ML-DSA-65 corpus (pqc_mldsa_v0).
 *
 * Independent C port of the Python reference runner (runners/python/verify_pqc_mldsa.py)
 * and its decision surface (tools/oracle_pqc_mldsa.py): decode the hex public key,
 * message and signature, reject a wrong-length public key (must be 1952) or
 * signature (must be 3309) before any verify, then verify the FIPS-204 ML-DSA-65
 * signature over the exact message bytes with the EMPTY context string.
 *
 * The ML-DSA implementation is liboqs via its C API (OQS_SIG_new("ML-DSA-65") /
 * OQS_SIG_verify). OQS_SIG_verify verifies the pure ML-DSA variant (empty context).
 * OQS_SIG_new returns NULL if the installed liboqs is an old build that exposes
 * only round-3 "Dilithium3" and not "ML-DSA-65"; that is the built-in tripwire.
 * JSON via jansson.
 *
 * Build (matches kaf/run_cells_pqc_mldsa.sh, which first builds liboqs 0.14.0):
 *   cc -O2 -w -o verify_pqc_mldsa verify_pqc_mldsa.c $(pkg-config --cflags --libs jansson) -loqs -lcrypto
 * Corpus path: argv[1], else $ALGOVOI_PQC_MLDSA, else ../../corpus/pqc_mldsa_v0/pqc_mldsa_v0.json
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <jansson.h>
#include <oqs/oqs.h>

#define PK_LEN 1952
#define SIG_LEN 3309

static const char *jstr(json_t *o, const char *k){
    json_t *v = json_object_get(o, k);
    return (v && json_is_string(v)) ? json_string_value(v) : NULL;
}

static int nib(char c){
    if(c>='0'&&c<='9') return c-'0';
    if(c>='a'&&c<='f') return c-'a'+10;
    if(c>='A'&&c<='F') return c-'A'+10;
    return -1;
}

/* hex decode into a malloc'd buffer; NULL on odd length or a bad digit. An empty
 * string decodes to a zero-length buffer (non-NULL), so the empty-message case is
 * a real 0-byte message, not a decode failure. */
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

static int verdict(OQS_SIG *sig, const char *pkHex, const char *msgHex, const char *sigHex){
    size_t pl=0, ml=0, sl=0;
    int rc = 0;
    unsigned char *pk = hexdec(pkHex, &pl);
    unsigned char *msg = hexdec(msgHex, &ml);
    unsigned char *s = hexdec(sigHex, &sl);
    if(pk && msg && s && pl == PK_LEN && sl == SIG_LEN){
        rc = (OQS_SIG_verify(sig, msg, ml, s, sl, pk) == OQS_SUCCESS) ? 1 : 0;
    }
    free(pk); free(msg); free(s);
    return rc;
}

int main(int argc, char **argv){
    const char *env = getenv("ALGOVOI_PQC_MLDSA");
    const char *path = argc > 1 ? argv[1]
                     : (env ? env : "../../corpus/pqc_mldsa_v0/pqc_mldsa_v0.json");
    json_error_t err;
    json_t *corpus = json_load_file(path, 0, &err);
    if(!corpus){ fprintf(stderr, "cannot load corpus %s: %s\n", path, err.text); return 2; }

    OQS_SIG *sig = OQS_SIG_new("ML-DSA-65");
    if(!sig){ fprintf(stderr, "liboqs has no ML-DSA-65 (old/Dilithium build)\n"); json_decref(corpus); return 2; }

    const char *sections[] = {"mldsa65_verify", "mldsa65_malformed", "mldsa65_acvp_kat"};
    int total = 0, matched = 0;
    for(size_t si = 0; si < sizeof(sections)/sizeof(sections[0]); si++){
        json_t *sec = json_object_get(corpus, sections[si]);
        size_t i; json_t *c;
        json_array_foreach(sec, i, c){
            const char *pk = jstr(c, "public_key");
            const char *msg = jstr(c, "message");
            const char *s = jstr(c, "signature");
            const char *note = jstr(c, "note");
            int expect = json_is_true(json_object_get(c, "expect_valid"));
            int accept = verdict(sig, pk, msg, s);
            total++;
            if(accept == expect) matched++;
            else printf("FAIL  [%s] %s\n", sections[si], note ? note : "");
        }
    }
    printf("\nc (pqc_mldsa): %d/%d cases matched\n", matched, total);
    OQS_SIG_free(sig);
    json_decref(corpus);
    return matched == total ? 0 : 1;
}
