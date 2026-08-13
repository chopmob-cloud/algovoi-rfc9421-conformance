/* C runner for the COSE_Sign1 corpus (cose_v0).
 *
 * Independent C port of the Python reference runner (runners/python/verify_cose.py)
 * and its decision surface (tools/oracle_cose.py). Parses each COSE_Sign1 (CBOR array
 * of 4, tagged 18 or untagged), applies the COSE security gates in order (protected
 * header deterministically encoded per RFC 8949 Section 4.2, alg (label 1) present in
 * the protected header, an unknown crit (label 2) label rejected, alg/key-type match),
 * builds the Sig_structure ["Signature1", protected, h'', payload] in deterministic
 * CBOR and verifies the ES256 / EdDSA / PS256 signature. For the deterministic-CBOR
 * section it decides whether the datum is RFC 8949 Section 4.2 canonical. Low-s is NOT
 * enforced (a COSE base rule, not a FAPI rule).
 *
 * The CBOR codec is hand-rolled (a minimal decoder plus an RFC 8949 Section 4.2
 * canonical encoder) so the deterministic judgement and the Sig_structure bytes are
 * byte-identical to the frozen corpus. JSON via jansson; ES256 (ECDSA P-256, on-curve
 * enforced by EC_POINT_oct2point), EdDSA (Ed25519) and PS256 (RSA-PSS SHA-256, salt
 * 32, MGF1-SHA256) via OpenSSL EVP. Keys from the hex COSE material.
 *
 * Build (matches kaf/run_cells_cose.sh):
 *   cc -O2 -w -o verify_cose verify_cose.c $(pkg-config --cflags --libs jansson) -lcrypto
 * Corpus path: argv[1], else ../../corpus/cose_v0/cose_v0.json
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

/* ---------- hex helpers ---------- */
static int hexval(char c){
    if(c>='0'&&c<='9') return c-'0';
    if(c>='a'&&c<='f') return c-'a'+10;
    if(c>='A'&&c<='F') return c-'A'+10;
    return -1;
}
static unsigned char *hexdec(const char *s, size_t *outlen){
    if(!s) return NULL;
    size_t n = strlen(s);
    if(n % 2) return NULL;
    unsigned char *out = malloc(n/2 ? n/2 : 1);
    for(size_t i=0;i<n;i+=2){
        int hi = hexval(s[i]), lo = hexval(s[i+1]);
        if(hi<0||lo<0){ free(out); return NULL; }
        out[i/2] = (unsigned char)((hi<<4)|lo);
    }
    *outlen = n/2;
    return out;
}

/* ---------- growable byte buffer ---------- */
typedef struct { unsigned char *p; size_t len, cap; } buf_t;
static void buf_init(buf_t *b){ b->p=NULL; b->len=0; b->cap=0; }
static void buf_put(buf_t *b, const unsigned char *d, size_t n){
    if(b->len+n > b->cap){ b->cap = (b->len+n)*2 + 16; b->p = realloc(b->p, b->cap); }
    memcpy(b->p+b->len, d, n); b->len += n;
}
static void buf_byte(buf_t *b, unsigned char c){ buf_put(b, &c, 1); }

/* ---------- CBOR value model ---------- */
enum { T_INT, T_BYTES, T_TEXT, T_ARRAY, T_MAP, T_NULL, T_TAG, T_BOOL };
typedef struct cval {
    int t;
    long long i;
    unsigned char *b; size_t blen;   /* bytes / text */
    struct cval **arr; size_t alen;  /* array items; tag uses arr[0] */
    struct cval **mk; struct cval **mv; size_t mlen; /* map */
    unsigned long long tag;
} cval;

static cval *cnew(int t){ cval *v = calloc(1, sizeof(cval)); v->t = t; return v; }

/* ---------- CBOR decode (permissive) ---------- */
static cval *decode(const unsigned char *buf, size_t len, size_t *pos);

static int read_arg(const unsigned char *buf, size_t len, size_t *pos, int ai, unsigned long long *arg){
    if(ai < 24){ *arg = ai; return 1; }
    if(ai == 24){ if(*pos+1>len) return 0; *arg = buf[*pos]; *pos+=1; return 1; }
    if(ai == 25){ if(*pos+2>len) return 0; *arg = ((unsigned long long)buf[*pos]<<8)|buf[*pos+1]; *pos+=2; return 1; }
    if(ai == 26){ if(*pos+4>len) return 0; unsigned long long a=0; for(int i=0;i<4;i++) a=(a<<8)|buf[*pos+i]; *arg=a; *pos+=4; return 1; }
    if(ai == 27){ if(*pos+8>len) return 0; unsigned long long a=0; for(int i=0;i<8;i++) a=(a<<8)|buf[*pos+i]; *arg=a; *pos+=8; return 1; }
    return 0; /* 28-30 reserved, 31 handled by caller */
}

static cval *decode_indef(const unsigned char *buf, size_t len, size_t *pos, int major){
    if(major==2 || major==3){
        buf_t acc; buf_init(&acc);
        for(;;){
            if(*pos>=len){ free(acc.p); return NULL; }
            if(buf[*pos]==0xff){ (*pos)++; break; }
            cval *chunk = decode(buf, len, pos);
            if(!chunk || chunk->t != (major==2?T_BYTES:T_TEXT)){ free(acc.p); return NULL; }
            buf_put(&acc, chunk->b, chunk->blen);
        }
        cval *v = cnew(major==2?T_BYTES:T_TEXT); v->b = acc.p; v->blen = acc.len; return v;
    }
    if(major==4){
        cval *v = cnew(T_ARRAY);
        for(;;){
            if(*pos>=len) return NULL;
            if(buf[*pos]==0xff){ (*pos)++; break; }
            cval *e = decode(buf, len, pos); if(!e) return NULL;
            v->arr = realloc(v->arr, (v->alen+1)*sizeof(cval*)); v->arr[v->alen++] = e;
        }
        return v;
    }
    cval *v = cnew(T_MAP);
    for(;;){
        if(*pos>=len) return NULL;
        if(buf[*pos]==0xff){ (*pos)++; break; }
        cval *k = decode(buf, len, pos); if(!k) return NULL;
        cval *val = decode(buf, len, pos); if(!val) return NULL;
        v->mk = realloc(v->mk,(v->mlen+1)*sizeof(cval*)); v->mv = realloc(v->mv,(v->mlen+1)*sizeof(cval*));
        v->mk[v->mlen]=k; v->mv[v->mlen]=val; v->mlen++;
    }
    return v;
}

static cval *decode(const unsigned char *buf, size_t len, size_t *pos){
    if(*pos>=len) return NULL;
    unsigned char ib = buf[(*pos)++];
    int major = ib>>5, ai = ib&0x1f;
    if(ai==31){ if(major<2||major>5) return NULL; return decode_indef(buf,len,pos,major); }
    unsigned long long arg;
    if(!read_arg(buf,len,pos,ai,&arg)) return NULL;

    switch(major){
    case 0: { cval *v=cnew(T_INT); v->i=(long long)arg; return v; }
    case 1: { cval *v=cnew(T_INT); v->i=-1-(long long)arg; return v; }
    case 2: { if(*pos+arg>len) return NULL; cval *v=cnew(T_BYTES); v->blen=arg; v->b=malloc(arg?arg:1); memcpy(v->b,buf+*pos,arg); *pos+=arg; return v; }
    case 3: { if(*pos+arg>len) return NULL; cval *v=cnew(T_TEXT); v->blen=arg; v->b=malloc(arg?arg:1); memcpy(v->b,buf+*pos,arg); *pos+=arg; return v; }
    case 4: { cval *v=cnew(T_ARRAY); for(unsigned long long i=0;i<arg;i++){ cval *e=decode(buf,len,pos); if(!e) return NULL; v->arr=realloc(v->arr,(v->alen+1)*sizeof(cval*)); v->arr[v->alen++]=e; } return v; }
    case 5: { cval *v=cnew(T_MAP); for(unsigned long long i=0;i<arg;i++){ cval *k=decode(buf,len,pos); if(!k) return NULL; cval *val=decode(buf,len,pos); if(!val) return NULL; v->mk=realloc(v->mk,(v->mlen+1)*sizeof(cval*)); v->mv=realloc(v->mv,(v->mlen+1)*sizeof(cval*)); v->mk[v->mlen]=k; v->mv[v->mlen]=val; v->mlen++; } return v; }
    case 6: { cval *inner=decode(buf,len,pos); if(!inner) return NULL; cval *v=cnew(T_TAG); v->tag=arg; v->arr=malloc(sizeof(cval*)); v->arr[0]=inner; v->alen=1; return v; }
    case 7:
        if(ai==22){ return cnew(T_NULL); }
        if(ai==20){ cval *v=cnew(T_BOOL); v->i=0; return v; }
        if(ai==21){ cval *v=cnew(T_BOOL); v->i=1; return v; }
        return NULL;
    }
    return NULL;
}

/* ---------- canonical encode (RFC 8949 Section 4.2) ---------- */
static void enc_head(buf_t *b, int major, unsigned long long n){
    int base = major<<5;
    if(n<24){ buf_byte(b, base|(int)n); }
    else if(n<0x100ULL){ buf_byte(b, base|24); buf_byte(b, n); }
    else if(n<0x10000ULL){ buf_byte(b, base|25); buf_byte(b,(n>>8)&0xff); buf_byte(b,n&0xff); }
    else if(n<0x100000000ULL){ buf_byte(b, base|26); for(int i=3;i>=0;i--) buf_byte(b,(n>>(8*i))&0xff); }
    else { buf_byte(b, base|27); for(int i=7;i>=0;i--) buf_byte(b,(n>>(8*i))&0xff); }
}

static int encode_into(cval *v, buf_t *out);

typedef struct { buf_t k; buf_t val; } kvpair;
static int kvcmp(const void *a, const void *b){
    const kvpair *x=a, *y=b;
    size_t n = x->k.len < y->k.len ? x->k.len : y->k.len;
    int c = memcmp(x->k.p, y->k.p, n);
    if(c) return c;
    return (x->k.len > y->k.len) - (x->k.len < y->k.len);
}

static int encode_into(cval *v, buf_t *out){
    switch(v->t){
    case T_INT:
        if(v->i>=0) enc_head(out,0,(unsigned long long)v->i);
        else enc_head(out,1,(unsigned long long)(-1-v->i));
        return 1;
    case T_BYTES: enc_head(out,2,v->blen); buf_put(out,v->b,v->blen); return 1;
    case T_TEXT: enc_head(out,3,v->blen); buf_put(out,v->b,v->blen); return 1;
    case T_ARRAY:
        enc_head(out,4,v->alen);
        for(size_t i=0;i<v->alen;i++) if(!encode_into(v->arr[i],out)) return 0;
        return 1;
    case T_MAP: {
        kvpair *pairs = calloc(v->mlen?v->mlen:1, sizeof(kvpair));
        for(size_t i=0;i<v->mlen;i++){
            buf_init(&pairs[i].k); buf_init(&pairs[i].val);
            if(!encode_into(v->mk[i], &pairs[i].k) || !encode_into(v->mv[i], &pairs[i].val)){ free(pairs); return 0; }
        }
        qsort(pairs, v->mlen, sizeof(kvpair), kvcmp);
        enc_head(out,5,v->mlen);
        for(size_t i=0;i<v->mlen;i++){ buf_put(out,pairs[i].k.p,pairs[i].k.len); buf_put(out,pairs[i].val.p,pairs[i].val.len); free(pairs[i].k.p); free(pairs[i].val.p); }
        free(pairs);
        return 1;
    }
    case T_NULL: buf_byte(out,0xf6); return 1;
    default: return 0;
    }
}

static int is_deterministic(const unsigned char *buf, size_t len){
    size_t pos = 0;
    cval *v = decode(buf, len, &pos);
    if(!v || pos != len || v->t == T_TAG) return 0;
    buf_t out; buf_init(&out);
    if(!encode_into(v, &out)){ free(out.p); return 0; }
    int ok = (out.len == len && memcmp(out.p, buf, len) == 0);
    free(out.p);
    return ok;
}

static cval *map_get(cval *m, long long key){
    for(size_t i=0;i<m->mlen;i++) if(m->mk[i]->t==T_INT && m->mk[i]->i==key) return m->mv[i];
    return NULL;
}

/* ---------- COSE_Sign1 parse ---------- */
typedef struct { unsigned char *protected; size_t plen; cval *phdr; unsigned char *payload; size_t payloadlen; unsigned char *sig; size_t siglen; } sign1;

static int parse_sign1(const unsigned char *buf, size_t len, sign1 *out){
    size_t pos = 0;
    cval *top = decode(buf, len, &pos);
    if(!top) return 0;
    cval *arr = top;
    if(top->t == T_TAG){ if(top->tag != 18) return 0; arr = top->arr[0]; }
    if(arr->t != T_ARRAY || arr->alen != 4) return 0;
    cval *prot = arr->arr[0], *uhdr = arr->arr[1], *payload = arr->arr[2], *sig = arr->arr[3];
    if(prot->t != T_BYTES || uhdr->t != T_MAP || sig->t != T_BYTES) return 0;
    if(payload->t != T_BYTES && payload->t != T_NULL) return 0;
    cval *phdr;
    if(prot->blen == 0){ phdr = cnew(T_MAP); }
    else {
        if(!is_deterministic(prot->b, prot->blen)) return 0;
        size_t p2 = 0;
        phdr = decode(prot->b, prot->blen, &p2);
        if(!phdr || phdr->t != T_MAP) return 0;
    }
    out->protected = prot->b; out->plen = prot->blen;
    out->phdr = phdr;
    out->payload = payload->t==T_BYTES ? payload->b : (unsigned char*)""; out->payloadlen = payload->t==T_BYTES ? payload->blen : 0;
    out->sig = sig->b; out->siglen = sig->blen;
    return 1;
}

static void sig_structure(const unsigned char *prot, size_t plen, const unsigned char *payload, size_t payloadlen, buf_t *out){
    cval arr; memset(&arr,0,sizeof(arr)); arr.t=T_ARRAY;
    cval s1; memset(&s1,0,sizeof(s1)); s1.t=T_TEXT; s1.b=(unsigned char*)"Signature1"; s1.blen=10;
    cval p; memset(&p,0,sizeof(p)); p.t=T_BYTES; p.b=(unsigned char*)prot; p.blen=plen;
    cval aad; memset(&aad,0,sizeof(aad)); aad.t=T_BYTES; aad.b=(unsigned char*)""; aad.blen=0;
    cval pl; memset(&pl,0,sizeof(pl)); pl.t=T_BYTES; pl.b=(unsigned char*)payload; pl.blen=payloadlen;
    cval *items[4] = {&s1,&p,&aad,&pl};
    arr.arr = items; arr.alen = 4;
    encode_into(&arr, out);
}

/* ---------- crypto ---------- */
static const char *jstr(json_t *o, const char *k){
    json_t *v = json_object_get(o, k);
    return (v && json_is_string(v)) ? json_string_value(v) : NULL;
}

static int es256_ok(const unsigned char *base, size_t bl, const unsigned char *sig, size_t sl,
                    const char *xhex, const char *yhex){
    if(sl != 64) return 0;
    size_t xl=0, yl=0;
    unsigned char *x = hexdec(xhex,&xl), *y = hexdec(yhex,&yl);
    int rc = 0;
    if(!x||!y||xl!=32||yl!=32){ free(x); free(y); return 0; }
    unsigned char pub[65]; pub[0]=0x04; memcpy(pub+1,x,32); memcpy(pub+33,y,32);
    EC_GROUP *grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BN_CTX *bctx = BN_CTX_new();
    EC_POINT *pt = NULL; EC_KEY *ec = NULL; EVP_PKEY *key = NULL;
    BIGNUM *r=NULL,*s=NULL; ECDSA_SIG *es=NULL; unsigned char *der=NULL;
    if(!grp||!bctx) goto done;
    pt = EC_POINT_new(grp);
    if(!pt || EC_POINT_oct2point(grp,pt,pub,65,bctx)!=1) goto done;
    ec = EC_KEY_new();
    if(!ec || EC_KEY_set_group(ec,grp)!=1 || EC_KEY_set_public_key(ec,pt)!=1) goto done;
    key = EVP_PKEY_new();
    if(!key || EVP_PKEY_set1_EC_KEY(key,ec)!=1) goto done;
    r = BN_bin2bn(sig,32,NULL); s = BN_bin2bn(sig+32,32,NULL);
    es = ECDSA_SIG_new();
    if(!r||!s||!es||ECDSA_SIG_set0(es,r,s)!=1) goto done;
    r=NULL; s=NULL;
    { int derlen = i2d_ECDSA_SIG(es,&der);
      if(derlen<=0) goto done;
      EVP_MD_CTX *ctx = EVP_MD_CTX_new();
      if(ctx && EVP_DigestVerifyInit(ctx,NULL,EVP_sha256(),NULL,key)==1)
          rc = (EVP_DigestVerify(ctx,der,(size_t)derlen,base,bl)==1);
      EVP_MD_CTX_free(ctx);
    }
done:
    if(der) OPENSSL_free(der);
    if(es) ECDSA_SIG_free(es);
    if(r) BN_free(r); if(s) BN_free(s);
    if(key) EVP_PKEY_free(key);
    if(ec) EC_KEY_free(ec);
    if(pt) EC_POINT_free(pt);
    if(bctx) BN_CTX_free(bctx);
    if(grp) EC_GROUP_free(grp);
    free(x); free(y);
    return rc;
}

static int eddsa_ok(const unsigned char *base, size_t bl, const unsigned char *sig, size_t sl, const char *xhex){
    if(sl != 64) return 0;
    size_t xl=0; unsigned char *x = hexdec(xhex,&xl);
    if(!x||xl!=32){ free(x); return 0; }
    EVP_PKEY *key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,NULL,x,32);
    int ok=0;
    if(key){
        EVP_MD_CTX *md = EVP_MD_CTX_new();
        if(md && EVP_DigestVerifyInit(md,NULL,NULL,NULL,key)==1)
            ok = (EVP_DigestVerify(md,sig,64,base,bl)==1);
        EVP_MD_CTX_free(md);
        EVP_PKEY_free(key);
    }
    free(x);
    return ok;
}

static int ps256_ok(const unsigned char *base, size_t bl, const unsigned char *sig, size_t sl,
                    const char *nhex, const char *ehex){
    size_t nl=0, el=0;
    unsigned char *nb = hexdec(nhex,&nl), *eb = hexdec(ehex,&el);
    if(!nb||!eb){ free(nb); free(eb); return 0; }
    BIGNUM *bn = BN_bin2bn(nb,nl,NULL), *be = BN_bin2bn(eb,el,NULL);
    free(nb); free(eb);
    if(!bn||!be){ BN_free(bn); BN_free(be); return 0; }
    RSA *rsa = RSA_new();
    if(!rsa || RSA_set0_key(rsa,bn,be,NULL)!=1){ if(rsa) RSA_free(rsa); else { BN_free(bn); BN_free(be); } return 0; }
    EVP_PKEY *key = EVP_PKEY_new();
    if(!key || EVP_PKEY_assign_RSA(key,rsa)!=1){ if(key) EVP_PKEY_free(key); else RSA_free(rsa); return 0; }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    int ok = 0;
    if(ctx && EVP_DigestVerifyInit(ctx,&pctx,EVP_sha256(),NULL,key)==1){
        if(EVP_PKEY_CTX_set_rsa_padding(pctx,RSA_PKCS1_PSS_PADDING)>0
           && EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx,32)>0
           && EVP_PKEY_CTX_set_rsa_mgf1_md(pctx,EVP_sha256())>0){
            ok = (EVP_DigestVerify(ctx,sig,sl,base,bl)==1);
        }
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return ok;
}

/* ---------- verdict ---------- */
static const char *alg_kty(long long alg){
    if(alg==-7) return "EC2";
    if(alg==-8) return "OKP";
    if(alg==-37) return "RSA";
    return NULL;
}

static int verdict(const unsigned char *buf, size_t len, json_t *key){
    sign1 s;
    if(!parse_sign1(buf, len, &s)) return 0;
    cval *alg = map_get(s.phdr, 1);
    if(!alg || alg->t != T_INT) return 0;
    cval *crit = map_get(s.phdr, 2);
    if(crit){
        if(crit->t != T_ARRAY || crit->alen == 0) return 0;
        for(size_t i=0;i<crit->alen;i++){
            cval *l = crit->arr[i];
            if(l->t != T_INT || l->i < 1 || l->i > 5) return 0;
        }
    }
    const char *want = alg_kty(alg->i);
    if(!want) return 0;
    const char *kty = jstr(key, "kty");
    if(!kty || strcmp(kty, want) != 0) return 0;

    buf_t pre; buf_init(&pre);
    sig_structure(s.protected, s.plen, s.payload, s.payloadlen, &pre);
    int rc = 0;
    if(alg->i == -7) rc = es256_ok(pre.p, pre.len, s.sig, s.siglen, jstr(key,"x"), jstr(key,"y"));
    else if(alg->i == -8) rc = eddsa_ok(pre.p, pre.len, s.sig, s.siglen, jstr(key,"x"));
    else if(alg->i == -37) rc = ps256_ok(pre.p, pre.len, s.sig, s.siglen, jstr(key,"n"), jstr(key,"e"));
    free(pre.p);
    return rc;
}

int main(int argc, char **argv){
    const char *path = argc>1 ? argv[1] : "../../corpus/cose_v0/cose_v0.json";
    json_error_t err;
    json_t *corpus = json_load_file(path, 0, &err);
    if(!corpus){ fprintf(stderr,"cannot load corpus %s: %s\n", path, err.text); return 2; }
    json_t *keys = json_object_get(corpus, "keys");

    const char *sections[] = {"cose_sig_structure","cose_deterministic_cbor","cose_protected_header",
        "cose_es256_verify","cose_eddsa_verify","cose_ps256_verify","cose_crit"};

    int total=0, matched=0;
    for(size_t si=0; si<sizeof(sections)/sizeof(sections[0]); si++){
        json_t *sec = json_object_get(corpus, sections[si]);
        size_t i; json_t *c;
        json_array_foreach(sec, i, c){
            const char *note = jstr(c, "note");
            int expect = json_is_true(json_object_get(c, "expect_valid"));
            int accept = 0;
            if(strcmp(sections[si], "cose_deterministic_cbor") == 0){
                size_t bl=0; unsigned char *b = hexdec(jstr(c,"cbor_hex"), &bl);
                if(b){ accept = is_deterministic(b, bl); free(b); }
            } else {
                size_t bl=0; unsigned char *b = hexdec(jstr(c,"cose_hex"), &bl);
                json_t *key = json_object_get(keys, jstr(c,"key"));
                if(b && key) accept = verdict(b, bl, key);
                free(b);
            }
            total++;
            if(accept == expect) matched++;
            else printf("FAIL  [%s] %s\n", sections[si], note?note:"");
        }
    }
    printf("\nc (cose): %d/%d cases matched\n", matched, total);
    json_decref(corpus);
    return matched==total ? 0 : 1;
}
