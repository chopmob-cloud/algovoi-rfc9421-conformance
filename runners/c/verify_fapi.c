/* C runner for the FAPI 2.0 Message Signing profile corpus (fapi_messagesigning_v0).
 *
 * Independent C port of the Python reference runner (runners/python/verify_fapi.py).
 * Every PROFILE rule (RFC 9421 s2.5 signing base, mandated coverage, Content-Digest
 * body binding, algorithm restriction) and the PS256 / ES256 crypto is re-implemented
 * here directly from the corpus `policy` block, NOT imported from a shared oracle, so a
 * runner passing is genuine agreement rather than an echo. This mirrors the Python
 * authority and the sibling verify_wba.c / negative_v1.c runners case for case. JSON
 * via jansson; RSA-PSS / ECDSA via OpenSSL EVP.
 *
 * Build (matches tools/run_consensus_fapi.sh and the sibling verify_wba.c):
 *   cc -O2 -w -o verify_fapi verify_fapi.c $(pkg-config --cflags --libs jansson) -lcrypto
 * Corpus path: argv[1], else ../../corpus/fapi_messagesigning_v0/fapi_messagesigning_v0.json
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <jansson.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

/* ---------- small helpers (mirrors of the sibling verify_wba.c) ---------- */
static const char *jstr(json_t *o, const char *k){
    json_t *v = json_object_get(o, k);
    return (v && json_is_string(v)) ? json_string_value(v) : NULL;
}
static int jbool(json_t *o, const char *k){
    json_t *v = json_object_get(o, k);
    return v && json_is_true(v);
}
static void lower(char *s){ for(; *s; s++) if(*s >= 'A' && *s <= 'Z') *s += 32; }
static char *trimdup(const char *s){
    while(*s==' '||*s=='\t'||*s=='\n'||*s=='\r') s++;
    size_t n = strlen(s);
    while(n && (s[n-1]==' '||s[n-1]=='\t'||s[n-1]=='\n'||s[n-1]=='\r')) n--;
    char *o = malloc(n+1); memcpy(o,s,n); o[n]=0; return o;
}

/* ---------- hex decode ---------- */
static int hexnib(char c){
    if(c>='0'&&c<='9') return c-'0';
    if(c>='a'&&c<='f') return c-'a'+10;
    if(c>='A'&&c<='F') return c-'A'+10;
    return -1;
}
static unsigned char *hexdec(const char *s, size_t *out){
    if(!s) return NULL;
    size_t n = strlen(s);
    if(n % 2) return NULL;
    unsigned char *b = malloc(n/2 ? n/2 : 1);
    if(!b) return NULL;
    for(size_t i=0;i<n;i+=2){
        int h=hexnib(s[i]), l=hexnib(s[i+1]);
        if(h<0||l<0){ free(b); return NULL; }
        b[i/2] = (unsigned char)((h<<4)|l);
    }
    *out = n/2;
    return b;
}

/* ---------- base64 (standard, padded; as emitted by base64.b64encode) ---------- */
static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static int b64i(char c){ const char *p = strchr(B64, c); return (p && c) ? (int)(p-B64) : -1; }
/* decode into a caller-owned buffer of at least (strlen(s)/4*3) bytes */
static int b64_decode(const char *s, unsigned char *out, size_t *outlen){
    size_t n = strlen(s);
    if(n % 4) return -1;
    size_t o = 0; int pad = 0;
    for(size_t i=0;i<n;i+=4){
        int v[4];
        for(int k=0;k<4;k++){
            char c = s[i+k];
            if(c=='='){ if(i+4<n){ return -1; } v[k]=0; pad++; }
            else { v[k]=b64i(c); if(v[k]<0) return -1; }
        }
        out[o++] = (unsigned char)((v[0]<<2)|(v[1]>>4));
        if(pad<2) out[o++] = (unsigned char)(((v[1]&0xf)<<4)|(v[2]>>2));
        if(pad<1) out[o++] = (unsigned char)(((v[2]&0x3)<<6)|v[3]);
    }
    *outlen = o;
    return 0;
}
/* decode into a fresh malloc'd buffer; returns buffer (caller frees) or NULL */
static unsigned char *b64_decode_alloc(const char *s, size_t *outlen){
    if(!s) return NULL;
    size_t n = strlen(s);
    unsigned char *buf = malloc(n/4*3 + 4);
    if(!buf) return NULL;
    if(b64_decode(s, buf, outlen) != 0){ free(buf); return NULL; }
    return buf;
}
static void b64_encode(const unsigned char *in, size_t len, char *out){
    size_t o = 0;
    for(size_t i=0;i<len;i+=3){
        int n = (int)(len - i);
        uint32_t x = (uint32_t)in[i] << 16;
        if(n>1) x |= (uint32_t)in[i+1] << 8;
        if(n>2) x |= (uint32_t)in[i+2];
        out[o++] = B64[(x>>18)&63];
        out[o++] = B64[(x>>12)&63];
        out[o++] = (n>1) ? B64[(x>>6)&63] : '=';
        out[o++] = (n>2) ? B64[x&63] : '=';
    }
    out[o] = 0;
}

/* =====================================================================
 * Section 1: fapi_signing_base
 *   RFC 9421 s2.5 base, hand-built. The covered-component NAME is
 *   lowercased; the VALUE is emitted verbatim per the mapping:
 *     @method     -> in.method
 *     @target-uri -> in.target_uri
 *     @status     -> the integer, rendered as its decimal string
 *     @authority  -> in.authority
 *     @path       -> in.path
 *     else        -> in.headers[name]  (case-insensitive header lookup)
 *   then a trailing  "@signature-params": <signature_params_raw>  line,
 *   joined with "\n". Returns a malloc'd string, or NULL when the base is
 *   unbuildable (missing covered value / missing signature-params).
 * ===================================================================== */
static char *build_signing_base(json_t *in, const char *spr){
    if(!spr) return NULL;
    json_t *cc = json_object_get(in, "covered_components");
    if(!json_is_array(cc)) return NULL;
    size_t cap = 16384;
    char *buf = malloc(cap);
    if(!buf) return NULL;
    size_t bl = 0; buf[0] = 0;
    size_t i; json_t *comp;
    json_array_foreach(cc, i, comp){
        if(!json_is_string(comp)){ free(buf); return NULL; }
        char name[128];
        strncpy(name, json_string_value(comp), sizeof(name)-1);
        name[sizeof(name)-1] = 0;
        lower(name);
        char val[4096]; val[0] = 0;
        if(strcmp(name, "@method")==0){
            const char *m = jstr(in, "method");
            if(!m){ free(buf); return NULL; }
            strncpy(val, m, sizeof(val)-1); val[sizeof(val)-1]=0;
        } else if(strcmp(name, "@target-uri")==0){
            const char *t = jstr(in, "target_uri");
            if(!t){ free(buf); return NULL; }
            strncpy(val, t, sizeof(val)-1); val[sizeof(val)-1]=0;
        } else if(strcmp(name, "@authority")==0){
            const char *a = jstr(in, "authority");
            if(!a){ free(buf); return NULL; }
            strncpy(val, a, sizeof(val)-1); val[sizeof(val)-1]=0;
        } else if(strcmp(name, "@path")==0){
            const char *p = jstr(in, "path");
            if(!p){ free(buf); return NULL; }
            strncpy(val, p, sizeof(val)-1); val[sizeof(val)-1]=0;
        } else if(strcmp(name, "@status")==0){
            json_t *st = json_object_get(in, "status");
            if(!json_is_integer(st)){ free(buf); return NULL; }
            snprintf(val, sizeof(val), "%lld", (long long)json_integer_value(st));
        } else {
            /* ordinary header: case-insensitive match on the lowercased name */
            json_t *hs = json_object_get(in, "headers");
            const char *hv = NULL;
            if(hs){
                const char *hk; json_t *hvv;
                json_object_foreach(hs, hk, hvv){
                    char lk[128];
                    strncpy(lk, hk, sizeof(lk)-1); lk[sizeof(lk)-1]=0; lower(lk);
                    if(strcmp(lk, name)==0 && json_is_string(hvv)){ hv = json_string_value(hvv); break; }
                }
            }
            if(!hv){ free(buf); return NULL; }
            strncpy(val, hv, sizeof(val)-1); val[sizeof(val)-1]=0;
        }
        int need = snprintf(buf+bl, cap-bl, "%s\"%s\": %s", bl ? "\n" : "", name, val);
        if(need < 0 || (size_t)need >= cap-bl){ free(buf); return NULL; }
        bl += (size_t)need;
    }
    int need = snprintf(buf+bl, cap-bl, "%s\"@signature-params\": %s", bl ? "\n" : "", spr);
    if(need < 0 || (size_t)need >= cap-bl){ free(buf); return NULL; }
    return buf;
}

/* =====================================================================
 * Section 2: fapi_required_coverage
 *   required_covered_request (message_type=="request") / _response else;
 *   every required component (lowercased) present in covered (lowercased).
 * ===================================================================== */
static int coverage_ok(const char *message_type, json_t *covered, json_t *policy){
    const char *key = (message_type && strcmp(message_type, "request")==0)
                      ? "required_covered_request" : "required_covered_response";
    json_t *required = json_object_get(policy, key);
    if(!json_is_array(required) || !json_is_array(covered)) return 0;
    size_t i, j; json_t *r, *c;
    json_array_foreach(required, i, r){
        const char *rs = json_string_value(r);
        if(!rs) continue;
        char rl[128]; strncpy(rl, rs, sizeof(rl)-1); rl[sizeof(rl)-1]=0; lower(rl);
        int found = 0;
        json_array_foreach(covered, j, c){
            const char *cs = json_string_value(c);
            if(!cs) continue;
            char cl[128]; strncpy(cl, cs, sizeof(cl)-1); cl[sizeof(cl)-1]=0; lower(cl);
            if(strcmp(cl, rl)==0){ found = 1; break; }
        }
        if(!found) return 0;
    }
    return 1;
}

/* =====================================================================
 * Section 3: fapi_content_digest
 *   content-digest must be covered; split the header at the first '=' into
 *   the algorithm (trimmed, lowercased); algorithm must be listed in
 *   policy.content_digest_algorithms; recompute SHA-256 / SHA-512 over the
 *   base64-decoded body; accept iff  header.strip() == "<alg>=:<b64(digest)>:".
 * ===================================================================== */
static int content_digest_ok(const char *body_b64, const char *header_value,
                             json_t *covered, json_t *policy){
    /* content-digest must be among the covered components (lowercased) */
    int cd_covered = 0;
    size_t i; json_t *c;
    if(json_is_array(covered)){
        json_array_foreach(covered, i, c){
            const char *cs = json_string_value(c);
            if(!cs) continue;
            char cl[128]; strncpy(cl, cs, sizeof(cl)-1); cl[sizeof(cl)-1]=0; lower(cl);
            if(strcmp(cl, "content-digest")==0){ cd_covered = 1; break; }
        }
    }
    if(!cd_covered) return 0;
    if(!header_value || !body_b64) return 0;

    /* split at the first '=' */
    const char *eq = strchr(header_value, '=');
    if(!eq) return 0;
    size_t alen = (size_t)(eq - header_value);
    char alg[64];
    if(alen >= sizeof(alg)) return 0;
    memcpy(alg, header_value, alen); alg[alen] = 0;
    /* strip + lowercase the algorithm token */
    char *algt = trimdup(alg);
    lower(algt);

    /* algorithm must be allowed by policy */
    json_t *algs = json_object_get(policy, "content_digest_algorithms");
    int allowed = 0;
    if(json_is_array(algs)){
        json_array_foreach(algs, i, c){
            const char *as = json_string_value(c);
            if(as && strcmp(as, algt)==0){ allowed = 1; break; }
        }
    }
    if(!allowed){ free(algt); return 0; }

    /* recompute the digest of the decoded body */
    size_t blen = 0;
    unsigned char *body = b64_decode_alloc(body_b64, &blen);
    if(!body){ free(algt); return 0; }
    const EVP_MD *md = (strcmp(algt, "sha-256")==0) ? EVP_sha256() : EVP_sha512();
    unsigned char digest[EVP_MAX_MD_SIZE]; unsigned int dlen = 0;
    int dg = EVP_Digest(body, blen, digest, &dlen, md, NULL);
    free(body);
    if(dg != 1){ free(algt); return 0; }

    /* expect string:  <alg>=:<base64(digest)>: */
    char db64[EVP_MAX_MD_SIZE*2]; b64_encode(digest, dlen, db64);
    char expect[EVP_MAX_MD_SIZE*3];
    snprintf(expect, sizeof(expect), "%s=:%s:", algt, db64);
    free(algt);

    char *hv = trimdup(header_value);
    int ok = strcmp(hv, expect)==0;
    free(hv);
    return ok;
}

/* =====================================================================
 * Section 4: fapi_alg  ->  lower(alg) in policy.allowed_algs
 * ===================================================================== */
static int alg_ok(const char *alg, json_t *policy){
    if(!alg) return 0;
    char a[64]; strncpy(a, alg, sizeof(a)-1); a[sizeof(a)-1]=0; lower(a);
    json_t *allowed = json_object_get(policy, "allowed_algs");
    if(!json_is_array(allowed)) return 0;
    size_t i; json_t *c;
    json_array_foreach(allowed, i, c){
        const char *as = json_string_value(c);
        if(as && strcmp(as, a)==0) return 1;
    }
    return 0;
}

/* =====================================================================
 * Section 5: fapi_ps256_verify
 *   RSA-PSS, SHA-256, salt length 32, MGF1-SHA256, over the base64-decoded
 *   signing base, with the RSA public key loaded from SPKI DER.
 * ===================================================================== */
static int ps256_ok(const unsigned char *base, size_t bl,
                    const unsigned char *sig, size_t sl,
                    const unsigned char *spki, size_t spkil){
    const unsigned char *pp = spki;
    EVP_PKEY *key = d2i_PUBKEY(NULL, &pp, (long)spkil);
    if(!key) return 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    int ok = 0;
    if(ctx && EVP_DigestVerifyInit(ctx, &pctx, EVP_sha256(), NULL, key) == 1){
        if(EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) > 0
           && EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 32) > 0
           && EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256()) > 0){
            ok = (EVP_DigestVerify(ctx, sig, sl, base, bl) == 1);
        }
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return ok;
}

/* =====================================================================
 * Section 6: fapi_es256_verify
 *   raw 64-byte r||s. If require_low_s and s > n/2 (n from policy.p256_n, else
 *   the prime256v1 group order) -> reject. Else build an EC public key from the
 *   uncompressed point on prime256v1, wrap (r,s) into an ECDSA_SIG, DER-encode,
 *   and EVP_DigestVerify with SHA-256 over the base64-decoded signing base.
 * ===================================================================== */
static int es256_ok(const unsigned char *base, size_t bl,
                    const unsigned char *sig_raw, size_t sl,
                    const unsigned char *pub, size_t publ,
                    int require_low_s, json_t *policy){
    if(sl != 64) return 0;
    if(publ != 65 || pub[0] != 0x04) return 0;

    BIGNUM *r = BN_bin2bn(sig_raw, 32, NULL);
    BIGNUM *s = BN_bin2bn(sig_raw + 32, 32, NULL);
    EC_GROUP *grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BN_CTX *bctx = BN_CTX_new();
    int rc = 0;
    EC_POINT *pt = NULL; EC_KEY *ec = NULL; EVP_PKEY *key = NULL;
    ECDSA_SIG *es = NULL; unsigned char *der = NULL;

    if(!r || !s || !grp || !bctx) goto done;

    /* order n: policy.p256_n (decimal) if present, else the group order */
    BIGNUM *n = BN_new();
    const char *pn = jstr(policy, "p256_n");
    if(pn){ if(BN_dec2bn(&n, pn) == 0){ BN_free(n); goto done; } }
    else { if(EC_GROUP_get_order(grp, n, bctx) != 1){ BN_free(n); goto done; } }

    if(require_low_s){
        BIGNUM *half = BN_new();
        BN_rshift1(half, n);           /* half = n / 2 */
        int hi = BN_cmp(s, half) > 0;  /* s > n/2 */
        BN_free(half);
        if(hi){ BN_free(n); goto done; }
    }
    BN_free(n);

    /* public key from the uncompressed point (validates on-curve) */
    pt = EC_POINT_new(grp);
    if(!pt || EC_POINT_oct2point(grp, pt, pub, publ, bctx) != 1) goto done;
    ec = EC_KEY_new();
    if(!ec || EC_KEY_set_group(ec, grp) != 1 || EC_KEY_set_public_key(ec, pt) != 1) goto done;
    key = EVP_PKEY_new();
    if(!key || EVP_PKEY_set1_EC_KEY(key, ec) != 1) goto done;

    /* wrap r,s into an ECDSA_SIG -> DER */
    es = ECDSA_SIG_new();
    if(!es || ECDSA_SIG_set0(es, BN_dup(r), BN_dup(s)) != 1) goto done;
    int derlen = i2d_ECDSA_SIG(es, &der);
    if(derlen <= 0) goto done;

    {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if(ctx && EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, key) == 1)
            rc = (EVP_DigestVerify(ctx, der, (size_t)derlen, base, bl) == 1);
        EVP_MD_CTX_free(ctx);
    }

done:
    if(der) OPENSSL_free(der);
    if(es) ECDSA_SIG_free(es);
    if(key) EVP_PKEY_free(key);
    if(ec) EC_KEY_free(ec);
    if(pt) EC_POINT_free(pt);
    if(bctx) BN_CTX_free(bctx);
    if(grp) EC_GROUP_free(grp);
    if(r) BN_free(r);
    if(s) BN_free(s);
    return rc;
}

/* ---------- driver ---------- */
static int total = 0, matched = 0;
static void rec(int ok, const char *sec, json_t *c){
    total++;
    if(ok) matched++;
    else {
        const char *note = jstr(c, "note");
        printf("FAIL  [%s] %s\n", sec, note ? note : "");
    }
}

int main(int argc, char **argv){
    const char *path = argc > 1 ? argv[1]
                                : "../../corpus/fapi_messagesigning_v0/fapi_messagesigning_v0.json";
    json_error_t err;
    json_t *corpus = json_load_file(path, 0, &err);
    if(!corpus){ fprintf(stderr, "cannot load corpus %s: %s\n", path, err.text); return 2; }

    json_t *policy = json_object_get(corpus, "policy");
    if(!policy){ fprintf(stderr, "corpus missing policy\n"); json_decref(corpus); return 2; }

    size_t i; json_t *c; json_t *sec;

    /* 1. fapi_signing_base */
    sec = json_object_get(corpus, "fapi_signing_base");
    json_array_foreach(sec, i, c){
        json_t *in = json_object_get(c, "in");
        const char *spr = jstr(c, "signature_params_raw");
        int cok = jbool(c, "ok");
        const char *b64 = jstr(c, "signing_base_b64");
        size_t dl = 0;
        unsigned char *decoded = b64_decode_alloc(b64, &dl);
        char *built = build_signing_base(in, spr);
        int ok;
        if(!built) ok = !cok;
        else       ok = cok && decoded && strlen(built) == dl && memcmp(built, decoded, dl) == 0;
        free(built);
        free(decoded);
        rec(ok, "fapi_signing_base", c);
    }

    /* 2. fapi_required_coverage */
    sec = json_object_get(corpus, "fapi_required_coverage");
    json_array_foreach(sec, i, c){
        int got = coverage_ok(jstr(c, "message_type"), json_object_get(c, "covered_components"), policy);
        rec(got == jbool(c, "expect_accept"), "fapi_required_coverage", c);
    }

    /* 3. fapi_content_digest */
    sec = json_object_get(corpus, "fapi_content_digest");
    json_array_foreach(sec, i, c){
        int got = content_digest_ok(jstr(c, "body_b64"), jstr(c, "content_digest"),
                                    json_object_get(c, "covered_components"), policy);
        rec(got == jbool(c, "expect_accept"), "fapi_content_digest", c);
    }

    /* 4. fapi_alg */
    sec = json_object_get(corpus, "fapi_alg");
    json_array_foreach(sec, i, c){
        int got = alg_ok(jstr(c, "alg"), policy);
        rec(got == jbool(c, "expect_accept"), "fapi_alg", c);
    }

    /* 5. fapi_ps256_verify */
    sec = json_object_get(corpus, "fapi_ps256_verify");
    json_array_foreach(sec, i, c){
        size_t bl = 0, sl = 0, pl = 0;
        unsigned char *base = b64_decode_alloc(jstr(c, "signing_base_b64"), &bl);
        unsigned char *sig  = hexdec(jstr(c, "sig_hex"), &sl);
        unsigned char *spki = hexdec(jstr(c, "pub_spki_hex"), &pl);
        int v = (base && sig && spki) ? ps256_ok(base, bl, sig, sl, spki, pl) : 0;
        rec(v == jbool(c, "expect_valid"), "fapi_ps256_verify", c);
        free(base); free(sig); free(spki);
    }

    /* 6. fapi_es256_verify */
    sec = json_object_get(corpus, "fapi_es256_verify");
    json_array_foreach(sec, i, c){
        size_t bl = 0, sl = 0, pl = 0;
        unsigned char *base = b64_decode_alloc(jstr(c, "signing_base_b64"), &bl);
        unsigned char *sig  = hexdec(jstr(c, "sig_raw_hex"), &sl);
        unsigned char *pub  = hexdec(jstr(c, "pub_uncompressed_hex"), &pl);
        int rls = jbool(c, "require_low_s");
        int v = (base && sig && pub) ? es256_ok(base, bl, sig, sl, pub, pl, rls, policy) : 0;
        rec(v == jbool(c, "expect_valid"), "fapi_es256_verify", c);
        free(base); free(sig); free(pub);
    }

    printf("\nc (fapi): %d/%d cases matched\n", matched, total);
    json_decref(corpus);
    return matched == total ? 0 : 1;
}
