/* C runner for the Structured Field Values corpus (sfv_v0).
 *
 * Independently reproduces every verdict in the frozen corpus: parse `input` as
 * its declared field type (item|list|dictionary), and if it parses, serialize it
 * canonically (RFC 8941 Section 4.1) and compare to the frozen `canonical`. A
 * case matches iff parse_ok == expect_parse_ok and, when ok, the canonical bytes
 * are equal.
 *
 * No canonical RFC 8941 library exists for C, so this is a compact hand-rolled
 * RFC 8941 parser + canonical serializer, ported from the reference
 * tools/oracle_sfv.py. JSON via jansson. A per-case bump arena owns all parse
 * allocations, so error paths abort with setjmp/longjmp and the whole arena is
 * freed after each case. Independence for the profile comes from the five
 * native-library runners (typescript/go/rust/ruby/php) and the http_sfv KAT gate.
 *
 * Build (matches tools/run_consensus_sfv.sh / kaf/run_cells_sfv.sh):
 *   cc -O2 -w -o verify_sfv verify_sfv.c $(pkg-config --cflags --libs jansson)
 * Corpus path: argv[1], else ../../corpus/sfv_v0/sfv_v0.json
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <setjmp.h>
#include <jansson.h>

#define INT_MIN_SFV (-999999999999999LL)
#define INT_MAX_SFV (999999999999999LL)

static const char DIGITS[] = "0123456789";
static const char LCALPHA[] = "abcdefghijklmnopqrstuvwxyz";
static const char UCALPHA[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char TOKEN_TAIL[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-.^_`|~:/";
static const char KEY_TAIL[] = "abcdefghijklmnopqrstuvwxyz0123456789_-.*";
static const char B64_ALPHABET[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
static const char B64_ENC[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int inset(const char *set, int c) { return c >= 0 && strchr(set, c) != NULL && c != 0; }

/* ---- per-case bump arena + failure handling ---- */
static char *ARENA;
static size_t APOS, ACAP;
static jmp_buf JB;

static void fail(void) { longjmp(JB, 1); }
static void *aalloc(size_t n) {
    n = (n + 7) & ~((size_t)7);
    if (APOS + n > ACAP) fail();
    void *p = ARENA + APOS;
    APOS += n;
    return p;
}
static char *adup(const char *src, size_t len) {
    char *p = aalloc(len + 1);
    memcpy(p, src, len);
    p[len] = 0;
    return p;
}

/* ---- value model ---- */
enum { K_INT, K_DEC, K_STR, K_TOK, K_BYTES, K_BOOL };

typedef struct {
    int kind;
    long long i;
    char *dec;          /* decimal canonical text */
    char *s;            /* string / token value */
    unsigned char *by;  /* bytes */
    size_t bylen;
    int b;              /* boolean */
} Bare;

typedef struct { char *key; Bare *val; } Param;
typedef struct { Param *a; int n, cap; } Params;

typedef struct Node Node;
typedef struct { Bare *bare; Params params; } Member;
struct Node {
    int inner;
    Bare *bare;
    Params params;
    Member *members;
    int nmembers;
};
typedef struct { char *key; Node *node; } Entry;

static void params_init(Params *p) { p->a = NULL; p->n = 0; p->cap = 0; }
static void params_push_dedup(Params *p, const char *key, Bare *val) {
    for (int i = 0; i < p->n; i++) {
        if (strcmp(p->a[i].key, key) == 0) {
            for (int j = i; j < p->n - 1; j++) p->a[j] = p->a[j + 1];
            p->n--;
            break;
        }
    }
    if (p->n >= p->cap) {
        int nc = p->cap ? p->cap * 2 : 8;
        Param *na = aalloc(sizeof(Param) * nc);
        if (p->a) memcpy(na, p->a, sizeof(Param) * p->n);
        p->a = na;
        p->cap = nc;
    }
    p->a[p->n].key = (char *)key;
    p->a[p->n].val = val;
    p->n++;
}

/* ---- parser state ---- */
static const char *S;
static int I, LEN;

static int peekc(void) { return I < LEN ? (unsigned char)S[I] : -1; }

static void discard_sp(void) { while (I < LEN && S[I] == ' ') I++; }
static void discard_ows(void) { while (I < LEN && (S[I] == ' ' || S[I] == '\t')) I++; }

static Bare *bare_item(void);
static Params parameters(void);
static Node *item_node(void);
static Node *inner_list(void);
static Node *item_or_inner_list(void);

/* strict base64 decode: mirrors python base64.b64decode(validate=True). */
static void strict_b64(const char *content, size_t len, unsigned char **out, size_t *outlen) {
    if (len % 4 != 0) fail();
    int pad = 0;
    for (size_t k = 0; k < len; k++) {
        char c = content[k];
        if (c == '=') {
            pad++;
            if (k < len - 2) fail();
        } else {
            if (pad > 0) fail();
            if (!inset(B64_ALPHABET, c) || c == '=') fail();
        }
    }
    size_t o = 0;
    unsigned char *buf = aalloc(len ? (len / 4) * 3 + 3 : 1);
    for (size_t i = 0; i < len; i += 4) {
        int v[4], p = 0;
        for (int k = 0; k < 4; k++) {
            char c = content[i + k];
            if (c == '=') { v[k] = 0; p++; }
            else { const char *q = strchr(B64_ENC, c); if (!q) fail(); v[k] = (int)(q - B64_ENC); }
        }
        buf[o++] = (unsigned char)((v[0] << 2) | (v[1] >> 4));
        if (p < 2) buf[o++] = (unsigned char)(((v[1] & 0xf) << 4) | (v[2] >> 2));
        if (p < 1) buf[o++] = (unsigned char)(((v[2] & 0x3) << 6) | v[3]);
    }
    *out = buf;
    *outlen = o;
}

static char *ser_decimal(int sign, const char *intpart, size_t ilen, const char *frac, size_t flen) {
    char frac3[4];
    for (int k = 0; k < 3; k++) frac3[k] = (size_t)k < flen ? frac[k] : '0';
    frac3[3] = 0;
    int end = 3;
    while (end > 0 && frac3[end - 1] == '0') end--;
    if (end == 0) { frac3[0] = '0'; end = 1; }
    frac3[end] = 0;
    /* normalize integer part */
    long long whole = 0;
    for (size_t k = 0; k < ilen; k++) whole = whole * 10 + (intpart[k] - '0');
    if (whole >= 1000000000000LL) fail();
    int is_zero = (whole == 0) && (strcmp(frac3, "0") == 0);
    char *buf = aalloc(32);
    snprintf(buf, 32, "%s%lld.%s", (sign < 0 && !is_zero) ? "-" : "", whole, frac3);
    return buf;
}

static Bare *number(void) {
    int sign = 1, is_decimal = 0;
    char num[32];
    int nl = 0;
    if (peekc() == '-') { I++; sign = -1; }
    if (I >= LEN || !inset(DIGITS, peekc())) fail();
    for (;;) {
        int c = peekc();
        if (inset(DIGITS, c)) { if (nl < 31) num[nl++] = (char)c; else fail(); I++; }
        else if (!is_decimal && c == '.') {
            if (nl > 12) fail();
            if (nl < 31) num[nl++] = '.'; else fail();
            is_decimal = 1; I++;
        } else break;
        if (!is_decimal && nl > 15) fail();
        if (is_decimal && nl > 16) fail();
    }
    num[nl] = 0;
    Bare *b = aalloc(sizeof(Bare));
    memset(b, 0, sizeof(Bare));
    if (!is_decimal) {
        long long v = 0;
        for (int k = 0; k < nl; k++) v = v * 10 + (num[k] - '0');
        v *= sign;
        if (v < INT_MIN_SFV || v > INT_MAX_SFV) fail();
        b->kind = K_INT; b->i = v;
        return b;
    }
    if (num[nl - 1] == '.') fail();
    int dot = (int)(strchr(num, '.') - num);
    if (nl - dot - 1 > 3) fail();
    b->kind = K_DEC;
    b->dec = ser_decimal(sign, num, dot, num + dot + 1, nl - dot - 1);
    return b;
}

static char *parse_string(void) {
    I++; /* opening quote */
    char *out = aalloc(LEN + 1);
    int o = 0;
    while (I < LEN) {
        char c = S[I]; I++;
        if (c == '\\') {
            if (I >= LEN) fail();
            char nxt = S[I]; I++;
            if (nxt != '"' && nxt != '\\') fail();
            out[o++] = nxt;
        } else if (c == '"') {
            out[o] = 0;
            return out;
        } else if ((unsigned char)c < 0x20 || (unsigned char)c > 0x7E) {
            fail();
        } else {
            out[o++] = c;
        }
    }
    fail();
    return NULL;
}

static char *token(void) {
    int start = I; I++;
    while (I < LEN && inset(TOKEN_TAIL, (unsigned char)S[I])) I++;
    return adup(S + start, I - start);
}

static char *key_str(void) {
    int c = peekc();
    if (!(inset(LCALPHA, c) || c == '*')) fail();
    int start = I; I++;
    while (I < LEN && inset(KEY_TAIL, (unsigned char)S[I])) I++;
    return adup(S + start, I - start);
}

static Bare *bare_item(void) {
    int c = peekc();
    Bare *b = aalloc(sizeof(Bare));
    memset(b, 0, sizeof(Bare));
    if (c < 0) fail();
    if (c == '-' || inset(DIGITS, c)) return number();
    if (c == '"') { b->kind = K_STR; b->s = parse_string(); return b; }
    if (c == ':') {
        I++;
        int start = I;
        while (I < LEN && S[I] != ':') {
            if (!inset(B64_ALPHABET, (unsigned char)S[I])) fail();
            I++;
        }
        if (I >= LEN) fail();
        int clen = I - start;
        I++; /* closing ':' */
        b->kind = K_BYTES;
        strict_b64(S + start, clen, &b->by, &b->bylen);
        return b;
    }
    if (c == '?') {
        I++;
        int n = peekc();
        if (n == '1') { I++; b->kind = K_BOOL; b->b = 1; return b; }
        if (n == '0') { I++; b->kind = K_BOOL; b->b = 0; return b; }
        fail();
    }
    if (c == '*' || inset(LCALPHA, c) || inset(UCALPHA, c)) { b->kind = K_TOK; b->s = token(); return b; }
    fail();
    return NULL;
}

static Params parameters(void) {
    Params p; params_init(&p);
    while (peekc() == ';') {
        I++;
        discard_sp();
        char *k = key_str();
        Bare *val;
        if (peekc() == '=') { I++; val = bare_item(); }
        else { val = aalloc(sizeof(Bare)); memset(val, 0, sizeof(Bare)); val->kind = K_BOOL; val->b = 1; }
        params_push_dedup(&p, k, val);
    }
    return p;
}

static Node *item_node(void) {
    Node *n = aalloc(sizeof(Node));
    memset(n, 0, sizeof(Node));
    n->inner = 0;
    n->bare = bare_item();
    n->params = parameters();
    return n;
}

static Node *inner_list(void) {
    I++; /* '(' */
    Node *n = aalloc(sizeof(Node));
    memset(n, 0, sizeof(Node));
    n->inner = 1;
    int cap = 8;
    n->members = aalloc(sizeof(Member) * cap);
    n->nmembers = 0;
    for (;;) {
        discard_sp();
        if (peekc() == ')') {
            I++;
            n->params = parameters();
            return n;
        }
        if (I >= LEN) fail();
        Bare *bare = bare_item();
        Params ps = parameters();
        if (n->nmembers >= cap) {
            int nc = cap * 2;
            Member *nm = aalloc(sizeof(Member) * nc);
            memcpy(nm, n->members, sizeof(Member) * n->nmembers);
            n->members = nm; cap = nc;
        }
        n->members[n->nmembers].bare = bare;
        n->members[n->nmembers].params = ps;
        n->nmembers++;
        int c = peekc();
        if (c != ' ' && c != ')') fail();
    }
}

static Node *item_or_inner_list(void) {
    if (peekc() == '(') return inner_list();
    return item_node();
}

/* parse a whole field; sets *out_nodes/out_entries via kind. Returns arrays. */
typedef struct { Node **nodes; int n; } NodeList;
typedef struct { Entry *a; int n; } EntryList;

static NodeList parse_list(void) {
    NodeList r; r.nodes = NULL; r.n = 0;
    int cap = 8;
    r.nodes = aalloc(sizeof(Node *) * cap);
    discard_sp();
    if (I >= LEN) return r;
    for (;;) {
        if (r.n >= cap) { int nc = cap * 2; Node **nn = aalloc(sizeof(Node *) * nc); memcpy(nn, r.nodes, sizeof(Node *) * r.n); r.nodes = nn; cap = nc; }
        r.nodes[r.n++] = item_or_inner_list();
        discard_ows();
        if (I >= LEN) return r;
        if (peekc() != ',') fail();
        I++;
        discard_ows();
        if (I >= LEN) fail();
    }
}

static EntryList parse_dictionary(void) {
    EntryList r; r.a = NULL; r.n = 0;
    int cap = 8;
    r.a = aalloc(sizeof(Entry) * cap);
    discard_sp();
    if (I >= LEN) return r;
    for (;;) {
        char *k = key_str();
        Node *value;
        if (peekc() == '=') { I++; value = item_or_inner_list(); }
        else {
            Params ps = parameters();
            value = aalloc(sizeof(Node)); memset(value, 0, sizeof(Node));
            value->inner = 0;
            value->bare = aalloc(sizeof(Bare)); memset(value->bare, 0, sizeof(Bare));
            value->bare->kind = K_BOOL; value->bare->b = 1;
            value->params = ps;
        }
        /* dedup by key, keep later position */
        for (int i = 0; i < r.n; i++) {
            if (strcmp(r.a[i].key, k) == 0) {
                for (int j = i; j < r.n - 1; j++) r.a[j] = r.a[j + 1];
                r.n--;
                break;
            }
        }
        if (r.n >= cap) { int nc = cap * 2; Entry *na = aalloc(sizeof(Entry) * nc); memcpy(na, r.a, sizeof(Entry) * r.n); r.a = na; cap = nc; }
        r.a[r.n].key = k; r.a[r.n].node = value; r.n++;
        discard_ows();
        if (I >= LEN) return r;
        if (peekc() != ',') fail();
        I++;
        discard_ows();
        if (I >= LEN) fail();
    }
}

/* ---- output buffer ---- */
typedef struct { char *buf; size_t len, cap; } Out;
static void oinit(Out *o) { o->cap = 256; o->buf = malloc(o->cap); o->len = 0; o->buf[0] = 0; }
static void oputs(Out *o, const char *s) {
    size_t n = strlen(s);
    while (o->len + n + 1 > o->cap) { o->cap *= 2; o->buf = realloc(o->buf, o->cap); }
    memcpy(o->buf + o->len, s, n);
    o->len += n;
    o->buf[o->len] = 0;
}
static void oputc(Out *o, char c) { char t[2] = {c, 0}; oputs(o, t); }

static void ser_bare(Out *o, Bare *b);
static void ser_params(Out *o, Params *p);

static void ser_bare(Out *o, Bare *b) {
    char tmp[64];
    switch (b->kind) {
        case K_INT:
            if (b->i < INT_MIN_SFV || b->i > INT_MAX_SFV) fail();
            snprintf(tmp, sizeof(tmp), "%lld", b->i);
            oputs(o, tmp);
            break;
        case K_DEC:
            oputs(o, b->dec);
            break;
        case K_STR: {
            oputc(o, '"');
            for (char *p = b->s; *p; p++) {
                unsigned char c = (unsigned char)*p;
                if (c < 0x20 || c > 0x7E) fail();
                if (c == '"' || c == '\\') oputc(o, '\\');
                oputc(o, (char)c);
            }
            oputc(o, '"');
            break;
        }
        case K_TOK:
            oputs(o, b->s);
            break;
        case K_BYTES: {
            oputc(o, ':');
            size_t i;
            for (i = 0; i + 2 < b->bylen; i += 3) {
                unsigned v = (b->by[i] << 16) | (b->by[i + 1] << 8) | b->by[i + 2];
                oputc(o, B64_ENC[(v >> 18) & 63]); oputc(o, B64_ENC[(v >> 12) & 63]);
                oputc(o, B64_ENC[(v >> 6) & 63]); oputc(o, B64_ENC[v & 63]);
            }
            size_t rem = b->bylen - i;
            if (rem == 1) {
                unsigned v = b->by[i] << 16;
                oputc(o, B64_ENC[(v >> 18) & 63]); oputc(o, B64_ENC[(v >> 12) & 63]);
                oputc(o, '='); oputc(o, '=');
            } else if (rem == 2) {
                unsigned v = (b->by[i] << 16) | (b->by[i + 1] << 8);
                oputc(o, B64_ENC[(v >> 18) & 63]); oputc(o, B64_ENC[(v >> 12) & 63]);
                oputc(o, B64_ENC[(v >> 6) & 63]); oputc(o, '=');
            }
            oputc(o, ':');
            break;
        }
        case K_BOOL:
            oputs(o, b->b ? "?1" : "?0");
            break;
    }
}

static int is_bool_true(Bare *b) { return b->kind == K_BOOL && b->b; }

static void ser_params(Out *o, Params *p) {
    for (int i = 0; i < p->n; i++) {
        oputc(o, ';');
        oputs(o, p->a[i].key);
        if (!is_bool_true(p->a[i].val)) { oputc(o, '='); ser_bare(o, p->a[i].val); }
    }
}

static void ser_member(Out *o, Node *node) {
    if (node->inner) {
        oputc(o, '(');
        for (int k = 0; k < node->nmembers; k++) {
            if (k > 0) oputc(o, ' ');
            ser_bare(o, node->members[k].bare);
            ser_params(o, &node->members[k].params);
        }
        oputc(o, ')');
        ser_params(o, &node->params);
    } else {
        ser_bare(o, node->bare);
        ser_params(o, &node->params);
    }
}

/* verdict: returns 1 (ok) with canonical in *canon (malloc'd), or 0 (reject). */
static int verdict(const char *field_type, const char *input, char **canon) {
    *canon = NULL;
    ACAP = 1 << 16;
    ARENA = malloc(ACAP);
    APOS = 0;
    int rc = 0;
    if (setjmp(JB)) { free(ARENA); ARENA = NULL; return 0; }

    /* non-ASCII rejection */
    for (const char *p = input; *p; p++) if ((unsigned char)*p > 0x7F) fail();

    S = input; LEN = (int)strlen(input); I = 0;

    Out o;
    if (strcmp(field_type, "item") == 0) {
        discard_sp();
        Node *n = item_node();
        discard_sp();
        if (I < LEN) fail();
        oinit(&o);
        ser_member(&o, n);
    } else if (strcmp(field_type, "list") == 0) {
        NodeList nl = parse_list();
        discard_sp();
        if (I < LEN) fail();
        oinit(&o);
        for (int k = 0; k < nl.n; k++) { if (k > 0) oputs(&o, ", "); ser_member(&o, nl.nodes[k]); }
    } else if (strcmp(field_type, "dictionary") == 0) {
        EntryList el = parse_dictionary();
        discard_sp();
        if (I < LEN) fail();
        oinit(&o);
        for (int k = 0; k < el.n; k++) {
            if (k > 0) oputs(&o, ", ");
            Entry *e = &el.a[k];
            if (!e->node->inner && is_bool_true(e->node->bare)) { oputs(&o, e->key); ser_params(&o, &e->node->params); }
            else { oputs(&o, e->key); oputc(&o, '='); ser_member(&o, e->node); }
        }
    } else {
        free(ARENA); ARENA = NULL;
        return 0;
    }
    *canon = strdup(o.buf);
    free(o.buf);
    free(ARENA); ARENA = NULL;
    rc = 1;
    return rc;
}

static const char *SECTIONS[] = {
    "sfv_item", "sfv_list", "sfv_dictionary",
    "sfv_parameters", "sfv_canonical", "sfv_reject"
};

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "../../corpus/sfv_v0/sfv_v0.json";
    json_error_t err;
    json_t *corpus = json_load_file(path, 0, &err);
    if (!corpus) { fprintf(stderr, "cannot load corpus %s: %s\n", path, err.text); return 2; }

    int total = 0, matched = 0;
    for (size_t si = 0; si < sizeof(SECTIONS) / sizeof(SECTIONS[0]); si++) {
        json_t *sec = json_object_get(corpus, SECTIONS[si]);
        if (!json_is_array(sec)) continue;
        size_t i; json_t *c;
        json_array_foreach(sec, i, c) {
            const char *ft = json_string_value(json_object_get(c, "field_type"));
            const char *input = json_string_value(json_object_get(c, "input"));
            const char *note = json_string_value(json_object_get(c, "note"));
            int expect = json_is_true(json_object_get(c, "expect_parse_ok"));
            json_t *canon_j = json_object_get(c, "canonical");
            const char *want = json_is_string(canon_j) ? json_string_value(canon_j) : NULL;

            char *got = NULL;
            int ok = verdict(ft, input, &got);
            int match = (ok == expect) && (!ok || (want && got && strcmp(got, want) == 0));
            free(got);
            total++;
            if (match) matched++;
            else printf("FAIL  [%s] %s\n", SECTIONS[si], note ? note : "");
        }
    }
    printf("\nc (sfv): %d/%d cases matched\n", matched, total);
    json_decref(corpus);
    return matched == total ? 0 : 1;
}
