/* C runner for the Web Bot Auth profile corpus (webbotauth_v0).
 *
 * Independent C port of the Python reference runner (runners/python/verify_wba.py)
 * and its independent KAT gate (tools/check_kat_wba.py). Every PROFILE rule
 * (signing base, coverage completeness, freshness window, directory keyid
 * resolution, Signature-Agent SSRF, Ed25519 verification) is re-implemented here
 * directly from the corpus `policy` block, NOT imported from a shared oracle, so a
 * runner passing is genuine agreement rather than an echo. This mirrors the ts/go
 * runners case for case. JSON via jansson; Ed25519 via OpenSSL EVP (ED25519).
 *
 * Build (matches the sibling negative_v1.c / tools/run_consensus.sh):
 *   cc -O2 -w -o verify_wba verify_wba.c $(pkg-config --cflags --libs jansson) -lcrypto
 * Corpus path: argv[1], else ../../corpus/webbotauth_v0/webbotauth_v0.json
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <jansson.h>
#include <openssl/evp.h>

/* ---------- small helpers (mirrors of the sibling negative_v1.c) ---------- */
static const char *jstr(json_t *o, const char *k){
    json_t *v = json_object_get(o, k);
    return (v && json_is_string(v)) ? json_string_value(v) : NULL;
}
static int jbool(json_t *o, const char *k){
    json_t *v = json_object_get(o, k);
    return v && json_is_true(v);
}
static void lower(char *s){ for(; *s; s++) if(*s >= 'A' && *s <= 'Z') *s += 32; }

/* ---------- hex decode ---------- */
static int hexnib(char c){
    if(c>='0'&&c<='9') return c-'0';
    if(c>='a'&&c<='f') return c-'a'+10;
    if(c>='A'&&c<='F') return c-'A'+10;
    return -1;
}
static unsigned char *hexdec(const char *s, size_t *out){
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

/* ---------- base64 decode (standard, padded; as emitted by base64.b64encode) --- */
static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static int b64i(char c){ const char *p = strchr(B64, c); return (p && c) ? (int)(p-B64) : -1; }
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

/* ---------- Rule 1: RFC 9421 Section 2.5 signing base, by direct concatenation ----
 * Lowercase the covered-component NAME only; the VALUE is emitted verbatim
 * (mirrors hand_signing_base in tools/check_kat_wba.py, NOT negative_v1's value
 * lowercasing). Returns a malloc'd string, or NULL when the base is unbuildable
 * (missing covered value / missing signature-params). */
static char *build_wba_signing_base(json_t *in, const char *spr){
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
        const char *val = NULL;
        if(strcmp(name, "@authority")==0)      val = jstr(in, "authority");
        else if(strcmp(name, "@method")==0)    val = jstr(in, "method");
        else if(strcmp(name, "@path")==0)      val = jstr(in, "path");
        else { json_t *hs = json_object_get(in, "headers"); val = hs ? jstr(hs, name) : NULL; }
        if(!val){ free(buf); return NULL; }
        int need = snprintf(buf+bl, cap-bl, "%s\"%s\": %s", bl ? "\n" : "", name, val);
        if(need < 0 || (size_t)need >= cap-bl){ free(buf); return NULL; }
        bl += (size_t)need;
    }
    int need = snprintf(buf+bl, cap-bl, "%s\"@signature-params\": %s", bl ? "\n" : "", spr);
    if(need < 0 || (size_t)need >= cap-bl){ free(buf); return NULL; }
    return buf;
}

/* ---------- Rule 2: coverage completeness (every required present, lowercased) ---- */
static int coverage_ok(json_t *covered, json_t *required){
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

/* ---------- Rule 3: freshness window (JSON integers; expires>created;
 *            (created-skew) <= now < expires) ---------- */
static int freshness_ok(json_t *c, long long skew){
    json_t *cr = json_object_get(c, "created");
    json_t *ex = json_object_get(c, "expires");
    json_t *nw = json_object_get(c, "now");
    if(!json_is_integer(cr) || !json_is_integer(ex) || !json_is_integer(nw)) return 0;
    long long created = json_integer_value(cr);
    long long expires = json_integer_value(ex);
    long long now     = json_integer_value(nw);
    if(expires <= created) return 0;
    return (created - skew) <= now && now < expires;
}

/* ---------- Rule 4: directory keyid resolution to a usable Ed25519 JWK ---------- */
static int directory_ok(json_t *dir, const char *keyid){
    size_t i; json_t *j;
    json_array_foreach(dir, i, j){
        const char *kid = jstr(j, "kid");
        if(kid && keyid && strcmp(kid, keyid)==0){
            const char *kty = jstr(j, "kty");
            const char *crv = jstr(j, "crv");
            const char *x   = jstr(j, "x");
            return kty && crv && x
                   && strcmp(kty, "OKP")==0
                   && strcmp(crv, "Ed25519")==0
                   && x[0] != 0;
        }
    }
    return 0;
}

/* ---------- Rule 5: Signature-Agent SSRF guard ----
 * https required; reject userinfo; host IP-literal (v4 or [v6]) else resolved_ip;
 * reject if in ANY denied_cidr of the same IP version. IPv4 AND IPv6 CIDR
 * membership by inet_pton + byte-mask. */
typedef struct { int version; unsigned char b[16]; } ipaddr;

static int parse_ip(const char *s, ipaddr *out){
    struct in_addr  a4;
    struct in6_addr a6;
    if(inet_pton(AF_INET, s, &a4) == 1){ out->version = 4; memcpy(out->b, &a4, 4);  return 1; }
    if(inet_pton(AF_INET6, s, &a6) == 1){ out->version = 6; memcpy(out->b, &a6, 16); return 1; }
    return 0;
}

/* addr in the network described by "host/prefix"; same version only */
static int in_cidr(const ipaddr *addr, const char *cidr){
    const char *slash = strchr(cidr, '/');
    if(!slash) return 0;
    size_t hl = (size_t)(slash - cidr);
    char host[64];
    if(hl >= sizeof(host)) return 0;
    memcpy(host, cidr, hl); host[hl] = 0;
    ipaddr net;
    if(!parse_ip(host, &net)) return 0;
    if(net.version != addr->version) return 0;
    int nbytes = (addr->version == 4) ? 4 : 16;
    int prefix = atoi(slash + 1);
    if(prefix < 0 || prefix > nbytes * 8) return 0;
    int full = prefix / 8, rem = prefix % 8;
    if(full > 0 && memcmp(addr->b, net.b, (size_t)full) != 0) return 0;
    if(rem){
        unsigned char mask = (unsigned char)(0xFF << (8 - rem));
        if((addr->b[full] & mask) != (net.b[full] & mask)) return 0;
    }
    return 1;
}

static int ssrf_ok(const char *url, const char *resolved_ip,
                   int require_https, json_t *denied){
    if(!url) return 0;
    const char *sep = strstr(url, "://");
    /* No authority component: scheme is empty; require_https rejects it and there
     * is no host to evaluate. */
    if(!sep) return 0;
    size_t schlen = (size_t)(sep - url);
    char scheme[16];
    if(schlen >= sizeof(scheme)) return 0;
    memcpy(scheme, url, schlen); scheme[schlen] = 0; lower(scheme);
    if(require_https && strcmp(scheme, "https") != 0) return 0;

    const char *authstart = sep + 3;
    size_t nl = 0;
    while(authstart[nl] && authstart[nl] != '/' && authstart[nl] != '?' && authstart[nl] != '#') nl++;
    char netloc[512];
    if(nl >= sizeof(netloc)) return 0;
    memcpy(netloc, authstart, nl); netloc[nl] = 0;

    /* userinfo present anywhere in the authority -> reject (mirrors "@" in netloc) */
    if(strchr(netloc, '@')) return 0;

    /* host = hostname with any [] stripped and any :port removed */
    char host[256];
    if(netloc[0] == '['){
        const char *end = strchr(netloc, ']');
        if(!end) return 0;
        size_t hl = (size_t)(end - (netloc + 1));
        if(hl >= sizeof(host)) return 0;
        memcpy(host, netloc + 1, hl); host[hl] = 0;
    } else {
        size_t hl = 0;
        while(netloc[hl] && netloc[hl] != ':') hl++;
        if(hl >= sizeof(host)) return 0;
        memcpy(host, netloc, hl); host[hl] = 0;
    }
    if(!host[0]) return 0;

    ipaddr addr;
    if(!parse_ip(host, &addr)){
        /* not an IP literal: fall back to the resolved address */
        if(!resolved_ip) return 0;
        if(!parse_ip(resolved_ip, &addr)) return 0;
    }

    size_t i; json_t *cv;
    json_array_foreach(denied, i, cv){
        const char *cidr = json_string_value(cv);
        if(cidr && in_cidr(&addr, cidr)) return 0;
    }
    return 1;
}

/* ---------- Rule 6: Ed25519 verify of the raw signing-base bytes under a raw
 *            32-byte key (plain verify, mirrors verify_wba.py / check_kat_wba.py;
 *            no small-order / canonical-S gate in the profile runner) ---------- */
static int ed25519_verify(const unsigned char *msg, size_t ml,
                          const unsigned char *sig, size_t sl,
                          const unsigned char *pk, size_t pl){
    if(sl != 64 || pl != 32) return 0;
    EVP_PKEY *key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pk, 32);
    if(!key) return 0;
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    int ok = 0;
    if(md && EVP_DigestVerifyInit(md, NULL, NULL, NULL, key) == 1)
        ok = (EVP_DigestVerify(md, sig, 64, msg, ml) == 1);
    EVP_MD_CTX_free(md);
    EVP_PKEY_free(key);
    return ok;
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
                                : "../../corpus/webbotauth_v0/webbotauth_v0.json";
    json_error_t err;
    json_t *corpus = json_load_file(path, 0, &err);
    if(!corpus){ fprintf(stderr, "cannot load corpus %s: %s\n", path, err.text); return 2; }

    json_t *policy   = json_object_get(corpus, "policy");
    json_t *required = policy ? json_object_get(policy, "required_covered_components") : NULL;
    json_t *ssrf     = policy ? json_object_get(policy, "ssrf") : NULL;
    json_t *denied   = ssrf ? json_object_get(ssrf, "denied_cidrs") : NULL;

    int require_https = 1;
    json_t *rh = ssrf ? json_object_get(ssrf, "require_https") : NULL;
    if(rh && json_is_boolean(rh)) require_https = json_is_true(rh);

    long long skew = 0;
    json_t *sk = policy ? json_object_get(policy, "clock_skew_seconds") : NULL;
    if(sk && json_is_integer(sk)) skew = json_integer_value(sk);

    size_t i; json_t *c; json_t *sec;

    /* 1. wba_signing_base */
    sec = json_object_get(corpus, "wba_signing_base");
    json_array_foreach(sec, i, c){
        json_t *in = json_object_get(c, "in");
        const char *spr = jstr(c, "signature_params_raw");
        int cok = jbool(c, "ok");
        const char *b64 = jstr(c, "signing_base_b64");
        unsigned char decoded[8192]; size_t dl = 0;
        int dok = b64 && b64_decode(b64, decoded, &dl) == 0;
        if(dok) decoded[dl] = 0;
        char *built = build_wba_signing_base(in, spr);
        int ok;
        if(!built) ok = !cok;
        else       ok = cok && dok && strcmp(built, (char *)decoded) == 0;
        free(built);
        rec(ok, "wba_signing_base", c);
    }

    /* 2. wba_coverage */
    sec = json_object_get(corpus, "wba_coverage");
    json_array_foreach(sec, i, c){
        int got = coverage_ok(json_object_get(c, "covered_components"), required);
        rec(got == jbool(c, "expect_accept"), "wba_coverage", c);
    }

    /* 3. wba_freshness */
    sec = json_object_get(corpus, "wba_freshness");
    json_array_foreach(sec, i, c){
        int got = freshness_ok(c, skew);
        rec(got == jbool(c, "expect_accept"), "wba_freshness", c);
    }

    /* 4. wba_directory */
    sec = json_object_get(corpus, "wba_directory");
    json_array_foreach(sec, i, c){
        int got = directory_ok(json_object_get(c, "directory"), jstr(c, "keyid"));
        rec(got == jbool(c, "expect_accept"), "wba_directory", c);
    }

    /* 5. wba_directory_ssrf */
    sec = json_object_get(corpus, "wba_directory_ssrf");
    json_array_foreach(sec, i, c){
        int got = ssrf_ok(jstr(c, "signature_agent_url"), jstr(c, "resolved_ip"),
                          require_https, denied);
        rec(got == jbool(c, "expect_fetch_allowed"), "wba_directory_ssrf", c);
    }

    /* 6. wba_ed25519_verify */
    sec = json_object_get(corpus, "wba_ed25519_verify");
    json_array_foreach(sec, i, c){
        const char *b64 = jstr(c, "signing_base_b64");
        unsigned char base[8192]; size_t bl = 0;
        int dok = b64 && b64_decode(b64, base, &bl) == 0;
        size_t sgl = 0, pl = 0;
        unsigned char *sg = NULL, *pk = NULL;
        const char *sh = jstr(c, "sig_hex");
        const char *ph = jstr(c, "pk_hex");
        if(sh) sg = hexdec(sh, &sgl);
        if(ph) pk = hexdec(ph, &pl);
        int valid = dok && sg && pk && ed25519_verify(base, bl, sg, sgl, pk, pl);
        rec(valid == jbool(c, "expect_valid"), "wba_ed25519_verify", c);
        free(sg); free(pk);
    }

    printf("\nc (wba): %d/%d cases matched\n", matched, total);
    json_decref(corpus);
    return matched == total ? 0 : 1;
}
