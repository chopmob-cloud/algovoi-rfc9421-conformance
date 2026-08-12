/* C runner for the JSON Web Signature corpus (jws_v0).
 *
 * Independent C port of the Python reference runner (runners/python/verify_jws.py)
 * and its decision surface (tools/oracle_jws.py). Parses each compact JWS, applies
 * the JOSE security gates in order (reject alg:none, reject any crit, reject
 * alg/key-type mismatch such as HS256 keyed with an RSA public key, select the key
 * by kid when required), then verifies the RS256 / ES256 / EdDSA signature over
 * ASCII(protected)+"."+ASCII(payload). Low-s is NOT enforced (plain JOSE permits a
 * high-s ECDSA signature; low-s is a FAPI rule, not a jws_v0 rule). JSON via
 * jansson; RS256 (RSASSA-PKCS1v15), ES256 (ECDSA P-256, on-curve enforced by
 * EC_POINT_oct2point) and EdDSA (Ed25519) via OpenSSL EVP.
 *
 * Build (matches kaf/run_cells_jws.sh and the sibling verify_fapi.c):
 *   cc -O2 -w -o verify_jws verify_jws.c $(pkg-config --cflags --libs jansson) -lcrypto
 * Corpus path: argv[1], else ../../corpus/jws_v0/jws_v0.json
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <jansson.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>

static const char *jstr(json_t *o, const char *k){
    json_t *v = json_object_get(o, k);
    return (v && json_is_string(v)) ? json_string_value(v) : NULL;
}

/* ---------- strict base64url decode (unpadded, URL-safe alphabet) ---------- */
static int b64url_val(char c){
    if(c>='A'&&c<='Z') return c-'A';
    if(c>='a'&&c<='z') return c-'a'+26;
    if(c>='0'&&c<='9') return c-'0'+52;
    if(c=='-') return 62;
    if(c=='_') return 63;
    return -1;
}
static unsigned char *b64url_decode(const char *s, size_t *outlen){
    if(!s) return NULL;
    size_t n = strlen(s);
    if(n % 4 == 1) return NULL;
    unsigned char *out = malloc(n/4*3 + 3);
    if(!out) return NULL;
    size_t o = 0; uint32_t buf = 0; int bits = 0;
    for(size_t i=0;i<n;i++){
        int v = b64url_val(s[i]);
        if(v < 0){ free(out); return NULL; }
        buf = (buf << 6) | (uint32_t)v;
        bits += 6;
        if(bits >= 8){ bits -= 8; out[o++] = (unsigned char)((buf >> bits) & 0xFF); }
    }
    *outlen = o;
    return out;
}

/* RFC 7518 Section 3.1 alg -> required JWK kty */
static const char *alg_kty(const char *alg){
    if(!alg) return NULL;
    if(strcmp(alg,"RS256")==0) return "RSA";
    if(strcmp(alg,"ES256")==0) return "EC";
    if(strcmp(alg,"EdDSA")==0) return "OKP";
    if(strcmp(alg,"HS256")==0) return "oct";
    return NULL;
}

/* ---------- crypto ---------- */
static int rs256_ok(const unsigned char *base, size_t bl, const unsigned char *sig, size_t sl,
                    const unsigned char *n, size_t nl, const unsigned char *e, size_t el){
    BIGNUM *bn = BN_bin2bn(n, nl, NULL);
    BIGNUM *be = BN_bin2bn(e, el, NULL);
    if(!bn || !be){ BN_free(bn); BN_free(be); return 0; }
    RSA *rsa = RSA_new();
    if(!rsa){ BN_free(bn); BN_free(be); return 0; }
    if(RSA_set0_key(rsa, bn, be, NULL) != 1){ RSA_free(rsa); return 0; }
    EVP_PKEY *key = EVP_PKEY_new();
    if(!key || EVP_PKEY_assign_RSA(key, rsa) != 1){ if(key) EVP_PKEY_free(key); else RSA_free(rsa); return 0; }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = 0;
    if(ctx && EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, key) == 1)
        ok = (EVP_DigestVerify(ctx, sig, sl, base, bl) == 1);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return ok;
}

static int es256_ok(const unsigned char *base, size_t bl, const unsigned char *sig, size_t sl,
                    const unsigned char *x, size_t xl, const unsigned char *y, size_t yl){
    if(sl != 64 || xl != 32 || yl != 32) return 0;
    unsigned char pub[65];
    pub[0] = 0x04; memcpy(pub+1, x, 32); memcpy(pub+33, y, 32);

    EC_GROUP *grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BN_CTX *bctx = BN_CTX_new();
    EC_POINT *pt = NULL; EC_KEY *ec = NULL; EVP_PKEY *key = NULL;
    BIGNUM *r = NULL, *s = NULL; ECDSA_SIG *es = NULL; unsigned char *der = NULL;
    int rc = 0;
    if(!grp || !bctx) goto done;

    /* on-curve validation happens inside EC_POINT_oct2point */
    pt = EC_POINT_new(grp);
    if(!pt || EC_POINT_oct2point(grp, pt, pub, 65, bctx) != 1) goto done;
    ec = EC_KEY_new();
    if(!ec || EC_KEY_set_group(ec, grp) != 1 || EC_KEY_set_public_key(ec, pt) != 1) goto done;
    key = EVP_PKEY_new();
    if(!key || EVP_PKEY_set1_EC_KEY(key, ec) != 1) goto done;

    r = BN_bin2bn(sig, 32, NULL);
    s = BN_bin2bn(sig + 32, 32, NULL);
    es = ECDSA_SIG_new();
    if(!r || !s || !es || ECDSA_SIG_set0(es, r, s) != 1) goto done;
    r = NULL; s = NULL; /* owned by es now */
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
    if(r) BN_free(r);
    if(s) BN_free(s);
    if(key) EVP_PKEY_free(key);
    if(ec) EC_KEY_free(ec);
    if(pt) EC_POINT_free(pt);
    if(bctx) BN_CTX_free(bctx);
    if(grp) EC_GROUP_free(grp);
    return rc;
}

static int eddsa_ok(const unsigned char *base, size_t bl, const unsigned char *sig, size_t sl,
                    const unsigned char *x, size_t xl){
    if(sl != 64 || xl != 32) return 0;
    EVP_PKEY *key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, x, 32);
    if(!key) return 0;
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    int ok = 0;
    if(md && EVP_DigestVerifyInit(md, NULL, NULL, NULL, key) == 1)
        ok = (EVP_DigestVerify(md, sig, 64, base, bl) == 1);
    EVP_MD_CTX_free(md);
    EVP_PKEY_free(key);
    return ok;
}

/* ---------- verdict ---------- */
static json_t *select_key(json_t *header, json_t *keys_obj, json_t *key_names, int select_by_kid){
    if(select_by_kid){
        const char *kid = jstr(header, "kid");
        if(!kid) return NULL;
        size_t i; json_t *nm;
        json_array_foreach(key_names, i, nm){
            const char *name = json_string_value(nm);
            if(!name) continue;
            json_t *jwk = json_object_get(keys_obj, name);
            const char *jkid = jstr(jwk, "kid");
            if(jkid && strcmp(jkid, kid) == 0) return jwk;
        }
        return NULL;
    }
    json_t *first = json_array_get(key_names, 0);
    return first ? json_object_get(keys_obj, json_string_value(first)) : NULL;
}

/* decode a JWK base64url member into a malloc'd buffer */
static unsigned char *jwk_bytes(json_t *jwk, const char *field, size_t *len){
    const char *s = jstr(jwk, field);
    if(!s) return NULL;
    return b64url_decode(s, len);
}

static int verdict(const char *token, json_t *keys_obj, json_t *verify){
    /* split into exactly 3 segments */
    char *dup = strdup(token);
    if(!dup) return 0;
    char *p1 = dup, *p2 = NULL, *p3 = NULL;
    char *dot1 = strchr(p1, '.');
    int result = 0;
    if(!dot1){ free(dup); return 0; }
    *dot1 = 0; p2 = dot1 + 1;
    char *dot2 = strchr(p2, '.');
    if(!dot2){ free(dup); return 0; }
    *dot2 = 0; p3 = dot2 + 1;
    if(strchr(p3, '.')){ free(dup); return 0; } /* a 4th segment */

    size_t hl = 0, pll = 0, sgl = 0;
    unsigned char *hbytes = b64url_decode(p1, &hl);
    unsigned char *plbytes = b64url_decode(p2, &pll);
    unsigned char *sig = b64url_decode(p3, &sgl);
    json_t *header = NULL;

    if(!hbytes || !plbytes || !sig) goto out;
    json_error_t err;
    header = json_loadb((const char *)hbytes, hl, 0, &err);
    if(!header || !json_is_object(header)) goto out;
    if(!json_object_get(header, "alg")) goto out;

    /* signing input = ASCII(p1 "." p2) */
    size_t p1l = strlen(p1), p2l = strlen(p2);
    size_t sil = p1l + 1 + p2l;
    unsigned char *si = malloc(sil ? sil : 1);
    memcpy(si, p1, p1l); si[p1l] = '.'; memcpy(si + p1l + 1, p2, p2l);

    const char *alg = jstr(header, "alg");
    const char *want_kty = alg_kty(alg);
    if(!alg || strcmp(alg, "none") == 0){ free(si); goto out; }
    if(json_object_get(header, "crit")){ free(si); goto out; }
    if(!want_kty){ free(si); goto out; }

    json_t *key_names = json_object_get(verify, "key_names");
    int select_by_kid = json_is_true(json_object_get(verify, "select_by_kid"));
    json_t *jwk = select_key(header, keys_obj, key_names, select_by_kid);
    if(!jwk){ free(si); goto out; }
    const char *kty = jstr(jwk, "kty");
    if(!kty || strcmp(kty, want_kty) != 0){ free(si); goto out; }

    if(strcmp(alg, "RS256") == 0){
        size_t nl = 0, el = 0;
        unsigned char *n = jwk_bytes(jwk, "n", &nl);
        unsigned char *e = jwk_bytes(jwk, "e", &el);
        if(n && e) result = rs256_ok(si, sil, sig, sgl, n, nl, e, el);
        free(n); free(e);
    } else if(strcmp(alg, "ES256") == 0){
        size_t xl = 0, yl = 0;
        unsigned char *x = jwk_bytes(jwk, "x", &xl);
        unsigned char *y = jwk_bytes(jwk, "y", &yl);
        if(x && y) result = es256_ok(si, sil, sig, sgl, x, xl, y, yl);
        free(x); free(y);
    } else if(strcmp(alg, "EdDSA") == 0){
        size_t xl = 0;
        unsigned char *x = jwk_bytes(jwk, "x", &xl);
        if(x) result = eddsa_ok(si, sil, sig, sgl, x, xl);
        free(x);
    }
    free(si);

out:
    if(header) json_decref(header);
    free(hbytes); free(plbytes); free(sig); free(dup);
    return result;
}

/* ---------- driver ---------- */
int main(int argc, char **argv){
    const char *path = argc > 1 ? argv[1] : "../../corpus/jws_v0/jws_v0.json";
    json_error_t err;
    json_t *corpus = json_load_file(path, 0, &err);
    if(!corpus){ fprintf(stderr, "cannot load corpus %s: %s\n", path, err.text); return 2; }

    json_t *keys_obj = json_object_get(corpus, "keys");
    const char *sections[] = {"jws_compact_parse", "jws_alg_none", "jws_alg_confusion",
        "jws_rs256_verify", "jws_es256_verify", "jws_eddsa_verify", "jws_crit", "jws_kid"};

    int total = 0, matched = 0;
    for(size_t si = 0; si < sizeof(sections)/sizeof(sections[0]); si++){
        json_t *sec = json_object_get(corpus, sections[si]);
        size_t i; json_t *c;
        json_array_foreach(sec, i, c){
            const char *token = jstr(c, "jws");
            const char *note = jstr(c, "note");
            int expect = json_is_true(json_object_get(c, "expect_valid"));
            json_t *verify = json_object_get(c, "verify");
            int accept = token ? verdict(token, keys_obj, verify) : 0;
            total++;
            if(accept == expect) matched++;
            else printf("FAIL  [%s] %s\n", sections[si], note ? note : "");
        }
    }
    printf("\nc (jws): %d/%d cases matched\n", matched, total);
    json_decref(corpus);
    return matched == total ? 0 : 1;
}
