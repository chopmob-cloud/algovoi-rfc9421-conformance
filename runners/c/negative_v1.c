/* C runner for the rfc9421_negative_v1 / _v2 CORE cross-language battery.
 *
 * Independent C port of the verdict surface (signing_base.py, parse.py,
 * keycheck.py, verify.py + the algovoi-rfc9421-ecdsa provider). Self-contained
 * (no C RFC 9421 verifier exists); must produce byte-identical verdicts to every
 * other runner. Ed25519 verify via OpenSSL EVP (ED25519) with an explicit
 * canonical-S (S < L) check; the small-order / non-canonical public-key gate is
 * ported from keycheck.py with OpenSSL BIGNUM (RFC 8032 Appendix A arithmetic),
 * applied fail-closed BEFORE verification. ECDSA P-256/P-384 via OpenSSL over a
 * raw r||s signature with explicit range / width / on-curve / strict-low-s checks.
 * JSON via jansson.
 *
 * Build: cc -O2 negative_v1.c -o negative_v1 $(pkg-config --cflags --libs jansson libcrypto)
 * Corpus path: argv[1], else $ALGOVOI_NEGATIVE_V1, else the sibling repo default.
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
#include <openssl/x509.h>

static BN_CTX *CTX;
static BIGNUM *P, *D, *SQRT_M1, *L_ORD, *PP3_8, *PM1_4, *PM2;

/* ---------- hex ---------- */
static int hexnib(char c){ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1; }
static unsigned char *hexdec(const char *s, size_t *out){ size_t n=strlen(s); if(n%2)return NULL; unsigned char *b=malloc(n/2?n/2:1); for(size_t i=0;i<n;i+=2){int h=hexnib(s[i]),l=hexnib(s[i+1]); if(h<0||l<0){free(b);return NULL;} b[i/2]=(h<<4)|l;} *out=n/2; return b; }

/* ---------- base64 ---------- */
static const char B64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static int b64i(char c){ const char *p=strchr(B64,c); return (p&&c)?(int)(p-B64):-1; }
static int b64_decode(const char *s, unsigned char *out, size_t *outlen){
    size_t n=strlen(s); if(n%4) return -1; size_t o=0; int pad=0;
    for(size_t i=0;i<n;i+=4){ int v[4];
        for(int k=0;k<4;k++){ char c=s[i+k]; if(c=='='){ if(i+4<n){return -1;} v[k]=0; pad++; } else { v[k]=b64i(c); if(v[k]<0)return -1; } }
        out[o++]=(v[0]<<2)|(v[1]>>4); if(pad<2)out[o++]=((v[1]&0xf)<<4)|(v[2]>>2); if(pad<1)out[o++]=((v[2]&0x3)<<6)|v[3];
    }
    *outlen=o; return 0;
}
static void b64_encode(const unsigned char *in, size_t len, char *out){
    size_t o=0; for(size_t i=0;i<len;i+=3){ int n=(int)(len-i); uint32_t x=in[i]<<16; if(n>1)x|=in[i+1]<<8; if(n>2)x|=in[i+2];
        out[o++]=B64[(x>>18)&63]; out[o++]=B64[(x>>12)&63]; out[o++]=(n>1)?B64[(x>>6)&63]:'='; out[o++]=(n>2)?B64[x&63]:'='; }
    out[o]=0;
}
static int b64_is_canonical(const char *s){ size_t n=strlen(s); unsigned char *buf=malloc(n+4); size_t dl; if(b64_decode(s,buf,&dl)<0){free(buf);return 0;} char *re=malloc(((dl+2)/3)*4+1); b64_encode(buf,dl,re); int ok=strcmp(re,s)==0; free(buf); free(re); return ok; }

/* ---------- signing base (port of signing_base.py) ---------- */
static const char *jstr(json_t *o, const char *k){ json_t *v=json_object_get(o,k); return (v&&json_is_string(v))?json_string_value(v):NULL; }
static void lower(char *s){ for(;*s;s++) if(*s>='A'&&*s<='Z')*s+=32; }

/* returns malloc'd string, or NULL on build failure */
static char *build_signing_base(json_t *in, const char *mode, const char *spr){
    if(strcmp(mode,"algovoi-v0")&&strcmp(mode,"rfc9421")) return NULL;
    if(!strcmp(mode,"rfc9421")&&!spr) return NULL;
    json_t *cc=json_object_get(in,"covered_components"); if(!json_is_array(cc)) return NULL;
    char *buf=malloc(8192); size_t bl=0; buf[0]=0;
    size_t i; json_t *comp;
    json_array_foreach(cc, i, comp){
        char c[128]; strncpy(c,json_string_value(comp),127); c[127]=0; lower(c);
        char val[2048]; val[0]=0;
        if(!strcmp(c,"@method")){ const char *m=jstr(in,"method"); if(!m){free(buf);return NULL;} strcpy(val,m); if(strcmp(mode,"rfc9421"))lower(val); }
        else if(!strcmp(c,"@authority")){ const char *a=jstr(in,"authority"); if(!a){free(buf);return NULL;} strcpy(val,a); lower(val); }
        else if(!strcmp(c,"@path")){ const char *p=jstr(in,"path"); if(!p){free(buf);return NULL;} strcpy(val,p); }
        else if(!strcmp(c,"@target-uri")){ const char *t=jstr(in,"target_uri"); if(!t){free(buf);return NULL;} strcpy(val,t); }
        else if(!strcmp(c,"@scheme")){ const char *s=jstr(in,"scheme"); if(!s){free(buf);return NULL;} strcpy(val,s); lower(val); }
        else if(!strcmp(c,"@status")){ json_t *st=json_object_get(in,"status"); if(!json_is_integer(st)){free(buf);return NULL;} sprintf(val,"%lld",(long long)json_integer_value(st)); }
        else if(!strcmp(c,"created")||!strcmp(c,"expires")){ json_t *pr=json_object_get(in,"parameters"); json_t *v=pr?json_object_get(pr,c):NULL; if(!v){free(buf);return NULL;} if(json_is_integer(v))sprintf(val,"%lld",(long long)json_integer_value(v)); else strncpy(val,json_string_value(v),2047); }
        else if(c[0]=='@'){ free(buf); return NULL; }
        else { json_t *hs=json_object_get(in,"headers"); const char *hv=NULL; if(hs){ const char *hk; json_t *hvv; json_object_foreach(hs,hk,hvv){ char lk[128]; strncpy(lk,hk,127); lk[127]=0; lower(lk); if(!strcmp(lk,c)){hv=json_string_value(hvv);break;} } } if(!hv){free(buf);return NULL;} strncpy(val,hv,2047); }
        bl+=sprintf(buf+bl, "%s\"%s\": %s", (bl?"\n":""), c, val);
    }
    if(!strcmp(mode,"rfc9421")) bl+=sprintf(buf+bl, "\n\"@signature-params\": %s", spr);
    return buf;
}

/* ---------- structured-field parse (port of parse.py) ---------- */
#include <ctype.h>
static const char *skip_label(const char *h){ /* returns rest after "label=" or h */
    const char *p=h; while(*p==' '||*p=='\t')p++;
    if(isalpha((unsigned char)*p)){ const char *q=p+1; while(isalnum((unsigned char)*q)||*q=='_'||*q=='-')q++; const char *r=q; while(*r==' ')r++; if(*r=='='){ r++; while(*r==' ')r++; return r; } }
    return NULL;
}
static char *trimdup(const char *s){ while(*s==' '||*s=='\t'||*s=='\n'||*s=='\r')s++; size_t n=strlen(s); while(n&&(s[n-1]==' '||s[n-1]=='\t'||s[n-1]=='\n'||s[n-1]=='\r'))n--; char *o=malloc(n+1); memcpy(o,s,n); o[n]=0; return o; }
static int parse_sig_input(const char *hin){ char *h=trimdup(hin); int rc=-1; if(!*h){free(h);return -1;}
    const char *rest=skip_label(h); if(!rest){ if(h[0]=='(')rest=h; else {free(h);return -1;} }
    const char *p=rest; while(*p==' ')p++; if(*p!='('){free(h);return -1;} /* covered list must start */
    p++; while(*p){ while(*p==' ')p++; if(*p==')'){rc=0;break;} if(*p!='"'){rc=-1;break;} p++; while(*p&&*p!='"')p++; if(*p!='"'){rc=-1;break;} p++; }
    free(h); return rc;
}
static int parse_sig_value(const char *hin){ char *h=trimdup(hin); if(!*h){free(h);return -1;}
    const char *rest=skip_label(h); char *r2=NULL; if(rest){ r2=trimdup(rest); } else { if(h[0]==':')r2=trimdup(h); else {free(h);return -1;} }
    free(h); size_t n=strlen(r2); if(n<2||r2[0]!=':'||r2[n-1]!=':'){free(r2);return -1;}
    char *inner=malloc(n-1); memcpy(inner,r2+1,n-2); inner[n-2]=0; free(r2);
    int ok=b64_is_canonical(inner); free(inner); return ok?0:-1;
}

/* ---------- Ed25519 key gate (port of keycheck.py, OpenSSL BN) ---------- */
typedef struct { BIGNUM *X,*Y,*Z,*T; } Pt;
static BIGNUM *bn(void){ return BN_new(); }
static void mm(BIGNUM *r,const BIGNUM*a,const BIGNUM*b){ BN_mod_mul(r,a,b,P,CTX); }
static void ad(BIGNUM *r,const BIGNUM*a,const BIGNUM*b){ BN_mod_add(r,a,b,P,CTX); }
static void sb(BIGNUM *r,const BIGNUM*a,const BIGNUM*b){ BN_mod_sub(r,a,b,P,CTX); }

static int recover_x(BIGNUM *x, const BIGNUM *y, int sign){
    if(BN_cmp(y,P)>=0) return 0;
    BIGNUM *y2=bn(),*num=bn(),*den=bn(),*x2=bn(),*t=bn(),*inv=bn();
    mm(y2,y,y); BN_copy(num,y2); BN_sub_word(num,1); BN_nnmod(num,num,P,CTX);
    mm(den,D,y2); BN_add_word(den,1); BN_nnmod(den,den,P,CTX);
    BN_mod_exp(inv,den,PM2,P,CTX); mm(x2,num,inv);
    int rc=0;
    if(BN_is_zero(x2)){ if(sign){rc=0;} else {BN_zero(x);rc=1;} goto done; }
    BN_mod_exp(x,x2,PP3_8,P,CTX);
    mm(t,x,x); sb(t,t,x2); if(!BN_is_zero(t)){ mm(x,x,SQRT_M1); }
    mm(t,x,x); sb(t,t,x2); if(!BN_is_zero(t)){ rc=0; goto done; }
    if((BN_is_bit_set(x,0)?1:0)!=sign){ BN_sub(x,P,x); }
    rc=1;
done: BN_free(y2);BN_free(num);BN_free(den);BN_free(x2);BN_free(t);BN_free(inv); return rc;
}
static int decode_point(const unsigned char *pk, Pt *pt){
    unsigned char le[32]; for(int i=0;i<32;i++) le[i]=pk[31-i];
    BIGNUM *y=BN_bin2bn(le,32,NULL); int sign=(pk[31]>>7)&1; BN_clear_bit(y,255);
    BIGNUM *x=bn(); if(!recover_x(x,y,sign)){ BN_free(x);BN_free(y);return 0; }
    pt->X=x; pt->Y=y; pt->Z=bn(); BN_one(pt->Z); pt->T=bn(); mm(pt->T,x,y); return 1;
}
static Pt pt_add(Pt p, Pt q){
    BIGNUM *a=bn(),*b=bn(),*c=bn(),*d=bn(),*t1=bn(),*t2=bn();
    sb(t1,p.Y,p.X); sb(t2,q.Y,q.X); mm(a,t1,t2);
    ad(t1,p.Y,p.X); ad(t2,q.Y,q.X); mm(b,t1,t2);
    mm(c,p.T,q.T); ad(c,c,c); mm(c,c,D);
    mm(d,p.Z,q.Z); ad(d,d,d);
    BIGNUM *e=bn(),*f=bn(),*g=bn(),*h=bn(); sb(e,b,a); sb(f,d,c); ad(g,d,c); ad(h,b,a);
    Pt r; r.X=bn();r.Y=bn();r.Z=bn();r.T=bn(); mm(r.X,e,f); mm(r.Y,g,h); mm(r.Z,f,g); mm(r.T,e,h);
    BN_free(a);BN_free(b);BN_free(c);BN_free(d);BN_free(t1);BN_free(t2);BN_free(e);BN_free(f);BN_free(g);BN_free(h);
    return r;
}
static Pt mul8(Pt p){ Pt p2=pt_add(p,p); Pt p4=pt_add(p2,p2); return pt_add(p4,p4); }
static int is_identity(Pt p){ BIGNUM *t=bn(); int r; BN_nnmod(t,p.X,P,CTX); if(!BN_is_zero(t)){BN_free(t);return 0;} sb(t,p.Y,p.Z); r=BN_is_zero(t); BN_free(t); return r; }
static int is_small_order(const unsigned char *pk){ Pt p; if(!decode_point(pk,&p))return 0; return is_identity(mul8(p)); }
static int check_pubkey(const unsigned char *pk){ Pt p; if(!decode_point(pk,&p))return -1; return is_identity(mul8(p))?-1:0; }

/* ---------- Ed25519 verify (port of verify.py) ---------- */
static int ed25519_verify(const unsigned char *msg,size_t ml,const unsigned char *sig,size_t sl,const unsigned char *pk,size_t pl){
    if(sl!=64||pl!=32) return 0;
    if(check_pubkey(pk)!=0) return 0;
    /* canonical-S: reject S >= L */
    unsigned char sle[32]; for(int i=0;i<32;i++) sle[i]=sig[63-i]; BIGNUM *s=BN_bin2bn(sle,32,NULL); int nc=BN_cmp(s,L_ORD)>=0; BN_free(s); if(nc) return 0;
    EVP_PKEY *key=EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519,NULL,pk,32); if(!key) return 0;
    EVP_MD_CTX *md=EVP_MD_CTX_new(); int ok=0;
    if(EVP_DigestVerifyInit(md,NULL,NULL,NULL,key)==1) ok=(EVP_DigestVerify(md,sig,64,msg,ml)==1);
    EVP_MD_CTX_free(md); EVP_PKEY_free(key); return ok;
}

/* ---------- ECDSA verify (port of algovoi-rfc9421-ecdsa) ---------- */
static int ecdsa_verify(const char *curve,const unsigned char *msg,size_t ml,const unsigned char *sig,size_t sl,const unsigned char *pub,size_t publ,int strict){
    int fs = strcmp(curve,"p256")==0 ? 32 : 48;
    int nid = strcmp(curve,"p256")==0 ? NID_X9_62_prime256v1 : NID_secp384r1;
    const EVP_MD *md = strcmp(curve,"p256")==0 ? EVP_sha256() : EVP_sha384();
    if(sl!=(size_t)2*fs) return 0;
    if(publ!=(size_t)1+2*fs || pub[0]!=0x04) return 0;
    EC_GROUP *grp=EC_GROUP_new_by_curve_name(nid); BIGNUM *n=bn(); EC_GROUP_get_order(grp,n,CTX);
    BIGNUM *r=BN_bin2bn(sig,fs,NULL), *s=BN_bin2bn(sig+fs,fs,NULL); int rc=0;
    if(BN_is_zero(r)||BN_cmp(r,n)>=0||BN_is_zero(s)||BN_cmp(s,n)>=0) goto done;
    if(strict){ BIGNUM *half=bn(); BN_rshift1(half,n); if(BN_cmp(s,half)>0){BN_free(half);goto done;} BN_free(half); }
    { EC_POINT *pt=EC_POINT_new(grp);
      if(EC_POINT_oct2point(grp,pt,pub,publ,CTX)!=1){ EC_POINT_free(pt); goto done; } /* validates on-curve */
      EC_KEY *ec=EC_KEY_new(); EC_KEY_set_group(ec,grp); EC_KEY_set_public_key(ec,pt);
      unsigned char h[64]; unsigned int hl=0; EVP_MD_CTX *mc=EVP_MD_CTX_new(); EVP_DigestInit_ex(mc,md,NULL); EVP_DigestUpdate(mc,msg,ml); EVP_DigestFinal_ex(mc,h,&hl); EVP_MD_CTX_free(mc);
      ECDSA_SIG *es=ECDSA_SIG_new(); ECDSA_SIG_set0(es, BN_dup(r), BN_dup(s));
      rc = ECDSA_do_verify(h,hl,es,ec)==1;
      ECDSA_SIG_free(es); EC_KEY_free(ec); EC_POINT_free(pt);
    }
done: BN_free(r);BN_free(s);BN_free(n);EC_GROUP_free(grp); return rc;
}

/* ---------- RSA verify (rsa-pss-sha512 / rsa-v1_5-sha256) ---------- */
static int rsa_verify(const char *alg, const unsigned char *base, size_t bl, const unsigned char *sig, size_t sl, const unsigned char *spki, size_t spkil){
    const unsigned char *pp = spki;
    EVP_PKEY *key = d2i_PUBKEY(NULL, &pp, (long)spkil);
    if(!key) return 0;
    const EVP_MD *md; int pss;
    if(strcmp(alg,"rsa-pss-sha512")==0){ md=EVP_sha512(); pss=1; }
    else if(strcmp(alg,"rsa-v1_5-sha256")==0){ md=EVP_sha256(); pss=0; }
    else { EVP_PKEY_free(key); return 0; }
    EVP_MD_CTX *ctx=EVP_MD_CTX_new(); EVP_PKEY_CTX *pctx=NULL; int ok=0;
    if(EVP_DigestVerifyInit(ctx,&pctx,md,NULL,key)==1){
        if(pss){ EVP_PKEY_CTX_set_rsa_padding(pctx,RSA_PKCS1_PSS_PADDING); EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx,64); EVP_PKEY_CTX_set_rsa_mgf1_md(pctx,EVP_sha512()); }
        ok = (EVP_DigestVerify(ctx,sig,sl,base,bl)==1);
    }
    EVP_MD_CTX_free(ctx); EVP_PKEY_free(key); return ok;
}

/* ---------- driver ---------- */
static int total=0, matched=0;
static void rec(int ok,const char *sec,json_t *c){ total++; if(ok)matched++; else { json_t *note=json_object_get(c,"note"); printf("FAIL  [%s] %s\n",sec, note&&json_is_string(note)?json_string_value(note):""); } }
static int jbool(json_t *o,const char*k){ json_t *v=json_object_get(o,k); return v&&json_is_true(v); }

int main(int argc,char**argv){
    const char *path = argc>1?argv[1]:(getenv("ALGOVOI_NEGATIVE_V1")?getenv("ALGOVOI_NEGATIVE_V1"):"../../corpus/rfc9421_negative_v2/rfc9421_negative_v2.json");
    json_error_t err; json_t *corpus=json_load_file(path,0,&err); if(!corpus){ fprintf(stderr,"load: %s\n",err.text); return 2; }
    CTX=BN_CTX_new();
    P=bn(); BN_set_bit(P,255); BN_sub_word(P,19);
    PM2=bn(); BN_copy(PM2,P); BN_sub_word(PM2,2);
    PP3_8=bn(); BN_copy(PP3_8,P); BN_add_word(PP3_8,3); BN_rshift(PP3_8,PP3_8,3);
    PM1_4=bn(); BN_copy(PM1_4,P); BN_sub_word(PM1_4,1); BN_rshift(PM1_4,PM1_4,2);
    { BIGNUM *a=bn(),*b=bn(); BN_set_word(a,121666); BN_mod_exp(b,a,PM2,P,CTX); BN_set_word(a,121665); BN_sub(a,P,a); D=bn(); mm(D,a,b); BN_free(a);BN_free(b); }
    SQRT_M1=bn(); { BIGNUM *two=bn(); BN_set_word(two,2); BN_mod_exp(SQRT_M1,two,PM1_4,P,CTX); BN_free(two); }
    L_ORD=bn(); BN_hex2bn(&L_ORD,"1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED");

    size_t i; json_t *c;
    json_t *sec;
    sec=json_object_get(corpus,"signing_base"); json_array_foreach(sec,i,c){
        const char *b64=jstr(c,"signing_base_b64"); unsigned char want[8192]; size_t wl=0; b64_decode(b64,want,&wl); want[wl]=0;
        json_t *spr=json_object_get(c,"signature_params_raw");
        char *built=build_signing_base(json_object_get(c,"in"), jstr(c,"mode"), (spr&&json_is_string(spr))?json_string_value(spr):NULL);
        int cok=jbool(c,"ok"); int ok = built ? (cok && strcmp(built,(char*)want)==0) : (!cok);
        free(built); rec(ok,"signing_base",c);
    }
    sec=json_object_get(corpus,"signature_input_parse"); json_array_foreach(sec,i,c){ int p=parse_sig_input(jstr(c,"header"))==0; rec(p==jbool(c,"ok"),"sig_input_parse",c); }
    sec=json_object_get(corpus,"signature_value_parse"); json_array_foreach(sec,i,c){ int p=parse_sig_value(jstr(c,"header"))==0; rec(p==jbool(c,"ok"),"sig_value_parse",c); }
    sec=json_object_get(corpus,"keygate"); json_array_foreach(sec,i,c){ size_t pl; unsigned char *pk=hexdec(jstr(c,"pk_hex"),&pl); int rej=check_pubkey(pk)!=0; json_t *rv=json_object_get(c,"rejected"); int want_rej=rv&&json_is_string(rv); int so=is_small_order(pk); rec(rej==want_rej && so==jbool(c,"small_order"),"keygate",c); free(pk); }
    sec=json_object_get(corpus,"ed25519_verify"); json_array_foreach(sec,i,c){ unsigned char base[8192]; size_t bl=0; b64_decode(jstr(c,"signing_base_b64"),base,&bl); size_t sgl,pl; unsigned char *sg=hexdec(jstr(c,"sig_hex"),&sgl),*pk=hexdec(jstr(c,"pk_hex"),&pl); int v=ed25519_verify(base,bl,sg,sgl,pk,pl); rec(v==jbool(c,"expect_valid"),"ed25519_verify",c); free(sg);free(pk); }
    sec=json_object_get(corpus,"ecdsa_verify"); json_array_foreach(sec,i,c){ size_t ml,sgl,pl; unsigned char *msg=hexdec(jstr(c,"msg_hex"),&ml),*sg=hexdec(jstr(c,"sig_raw_hex"),&sgl),*pub=hexdec(jstr(c,"pub_uncompressed_hex"),&pl); int v=ecdsa_verify(jstr(c,"curve"),msg,ml,sg,sgl,pub,pl,jbool(c,"strict_low_s")); rec(v==jbool(c,"expect_valid"),"ecdsa_verify",c); free(msg);free(sg);free(pub); }

    sec=json_object_get(corpus,"rsa_verify"); if(sec) json_array_foreach(sec,i,c){ unsigned char base[8192]; size_t bl=0; b64_decode(jstr(c,"signing_base_b64"),base,&bl); size_t sl,pl; unsigned char *sg=hexdec(jstr(c,"sig_hex"),&sl),*spki=hexdec(jstr(c,"pub_spki_hex"),&pl); int v=rsa_verify(jstr(c,"alg"),base,bl,sg,sl,spki,pl); rec(v==jbool(c,"expect_valid"),"rsa_verify",c); free(sg);free(spki); }

    printf("\nc: %d/%d cases matched\n",matched,total);
    return matched==total?0:1;
}
