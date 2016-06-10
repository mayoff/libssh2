//
// Created by Rob Mayoff on 6/6/16.
//

#include "libssh2_priv.h"

#ifdef LIBSSH2_LIBTOMCRYPT

#define LTM_DESC

#include "crypto.h"
#include "libtomcrypt.h"
#include <tomcrypt.h>
#include <tomcrypt_math.h>

// HMAC API.

typedef struct LibTomCrypt_HMACState {
    hmac_state state;
    size_t outlen;
} HMACState;

void
libssh2_hmac_ctx_init(libssh2_hmac_ctx ctx) {
    // Nothing to do.
    (void)ctx;
}

void
libssh2_hmac_update(libssh2_hmac_ctx ctx, const unsigned char *data, unsigned long datalen) {
    hmac_process(&ctx->state, data, datalen);
}

void
libssh2_hmac_final(libssh2_hmac_ctx ctx, unsigned char output[]) {
    unsigned long outlen = ctx->outlen;
    hmac_done(&ctx->state, output, &outlen);
}

void
libssh2_hmac_cleanup(libssh2_hmac_ctx *ctxp) {
    free(*ctxp);
}

// HMAC implementation details.

static void
generic_hmac_init(char const *hashname, libssh2_hmac_ctx *ctxp, const void *key, unsigned long keylen)
{
    int hash = find_hash(hashname);
    if (hash == -1) {
        // No way to return an error state, except this I guess...
        *ctxp = NULL;
        return;
    }

    HMACState *state = (HMACState *)calloc(1, sizeof *state);
    if (state == NULL) {
        *ctxp = NULL;
        return;
    }

    int rc = hmac_init(&state->state, hash, key, keylen);
    if (rc != CRYPT_OK) {
        free(state);
        *ctxp = NULL;
        return;
    }

    state->outlen = hash_descriptor[hash].hashsize;
    *ctxp = state;
}


// SHA-1 API.

typedef struct LibTomCrypt_SHA1State {
    hash_state state;
} SHA1State;

int
libssh2_sha1_init(libssh2_sha1_ctx *ctxp)
{
    SHA1State *state = (SHA1State *)calloc(1, sizeof *state);
    if (state == NULL) { return -1; }
    sha1_init(&state->state);
    *ctxp = state;
    return 0;
}

void
libssh2_sha1_update(libssh2_sha1_ctx ctx, const unsigned char *data, size_t len) {
    sha1_process(&ctx->state, data, len);
}

void
libssh2_sha1_final(libssh2_sha1_ctx ctx, unsigned char output[SHA_DIGEST_LENGTH]) {
    sha1_done(&ctx->state, output);
    free(ctx);
}

void
libssh2_hmac_sha1_init(libssh2_hmac_ctx *ctxp, const void *key, unsigned long keylen)
{
    generic_hmac_init("sha1", ctxp, key, keylen);
}

// SHA-256 API.

typedef struct LibTomCrypt_SHA256State {
    hash_state state;
} SHA256State;

int
libssh2_sha256_init(libssh2_sha256_ctx *ctxp)
{
    SHA256State *state = (SHA256State *)calloc(1, sizeof *state);
    if (state == NULL) { return -1; }
    sha256_init(&state->state);
    *ctxp = state;
    return 0;
}

void
libssh2_sha256_update(libssh2_sha256_ctx ctx, const unsigned char *data, size_t len)
{
    sha256_process(&ctx->state, data, len);
}

void
libssh2_sha256_final(libssh2_sha256_ctx ctx, unsigned char output[SHA256_DIGEST_LENGTH])
{
    sha256_done(&ctx->state, output);
    free(ctx);
}

void
libssh2_hmac_sha256_init(libssh2_hmac_ctx *ctxp, const void *key, unsigned long keylen)
{
    generic_hmac_init("sha256", ctxp, key, keylen);
}

// SHA-512 API (HMAC only).

void
libssh2_hmac_sha512_init(libssh2_hmac_ctx *ctxp, const void *key, unsigned long keylen)
{
    generic_hmac_init("sha512", ctxp, key, keylen);
}

// MD5 API.

typedef struct LibTomCrypt_MD5State {
    hash_state state;
} MD5State;

int
libssh2_md5_init(libssh2_md5_ctx *ctxp)
{
    MD5State *state = (MD5State *)calloc(1, sizeof *state);
    if (state == NULL) { return -1; }
    md5_init(&state->state);
    *ctxp = state;
    return 0;
}

void libssh2_md5_update(libssh2_md5_ctx ctx, const unsigned char *data, size_t len)
{
    md5_process(&ctx->state, data, len);
}

void
libssh2_md5_final(libssh2_md5_ctx ctx, unsigned char output[MD5_DIGEST_LENGTH])
{
    md5_done(&ctx->state, output);
    free(ctx);
}

void
libssh2_hmac_md5_init(libssh2_hmac_ctx *ctxp, const void *key, unsigned long keylen)
{
    generic_hmac_init("md5", ctxp, key, keylen);
}

// RIPEMD-160 API (HMAC only).

void
libssh2_hmac_ripemd160_init(libssh2_hmac_ctx *ctxp, const void *key, unsigned long keylen)
{
    generic_hmac_init("rmd160", ctxp, key, keylen);
}

// Symmetric cipher implementation details.

typedef struct LibTomCrypt_CipherContext CipherContext;

typedef struct CipherMethods {
    int (*const init)(CipherContext *ctx, int cipher, const unsigned char *iv, const unsigned char *key);
    int (*const encrypt)(CipherContext *ctx, unsigned char *block, size_t blocksize);
    int (*const decrypt)(CipherContext *context, unsigned char *block, size_t blocksize);
    void (*const dtor)(CipherContext *ctx);
} CipherMethods;

typedef struct LibTomCrypt_CipherType {
    const char *cipher_name;
    const int keylen; // in bytes
    const CipherMethods *const methods;
} CipherType;

typedef struct LibTomCrypt_CipherContext {
    const CipherType *type; // Needed because _libssh2_cipher_dtor doesn't get this as an argument.
    union {
        symmetric_CBC cbc;
        symmetric_CTR ctr;
    };
} CipherContext;

static const int NumRoundsAutomatic = 0; // tells libtomcrypt to use the default/correct number of rounds.

// CBC-mode implementation details.

static int
cbc_init(CipherContext *context, int cipher, const unsigned char *iv, const unsigned char *key)
{
    return cbc_start(cipher, iv, key, context->type->keylen, NumRoundsAutomatic, &context->cbc);
}

static int
cbc_encrypt_wrapper(CipherContext *context, unsigned char *block, size_t blocksize)
{
    return cbc_encrypt(block, block, blocksize, &context->cbc);
}

static int
cbc_decrypt_wrapper(CipherContext *context, unsigned char *block, size_t blocksize)
{
    return cbc_decrypt(block, block, blocksize, &context->cbc);
}

static void
cbc_dtor(CipherContext *context)
{
    cbc_done(&context->cbc);
}

static CipherMethods cbc_methods = {
    .init = cbc_init,
    .encrypt = cbc_encrypt_wrapper,
    .decrypt = cbc_decrypt_wrapper,
    .dtor = cbc_dtor
};

// CTR-mode implementation details.

static int
ctr_init(CipherContext *context, int cipher, const unsigned char *iv, const unsigned char *key)
{
    // dropbear uses CTR_COUNTER_BIG_ENDIAN so I assume that's correct.
    return ctr_start(cipher, iv, key, context->type->keylen, NumRoundsAutomatic, CTR_COUNTER_BIG_ENDIAN, &context->ctr);
}

static int
ctr_encrypt_wrapper(CipherContext *context, unsigned char *block, size_t blocksize)
{
    return ctr_encrypt(block, block, blocksize, &context->ctr);
}

static int
ctr_decrypt_wrapper(CipherContext *context, unsigned char *block, size_t blocksize)
{
    return ctr_decrypt(block, block, blocksize, &context->ctr);
}

static void
ctr_dtor(CipherContext *context)
{
    ctr_done(&context->ctr);
}

static CipherMethods ctr_methods = {
    .init = ctr_init,
    .encrypt = ctr_encrypt_wrapper,
    .decrypt = ctr_decrypt_wrapper,
    .dtor = ctr_dtor
};

// AES-CBC cipher definitions.

static const CipherType CipherType_AES128 = {
        .cipher_name = "aes",
        .keylen = 128 / 8,
        .methods = &cbc_methods
};
const _libssh2_cipher_type _libssh2_cipher_aes128 = &CipherType_AES128;

static const CipherType CipherType_AES192 = {
        .cipher_name = "aes",
        .keylen = 192 / 8,
        .methods = &cbc_methods
};
const _libssh2_cipher_type _libssh2_cipher_aes192 = &CipherType_AES192;

static const CipherType CipherType_AES256 = {
        .cipher_name = "aes",
        .keylen = 256 / 8,
        .methods = &cbc_methods
};
const _libssh2_cipher_type _libssh2_cipher_aes256 = &CipherType_AES256;

// AES-CTR cipher definitions.

static const CipherType CipherType_AES128CTR = {
        .cipher_name = "aes",
        .keylen = 128 / 8,
        .methods = &ctr_methods
};
const _libssh2_cipher_type _libssh2_cipher_aes128ctr = &CipherType_AES128CTR;

static const CipherType CipherType_AES192CTR = {
        .cipher_name = "aes",
        .keylen = 192 / 8,
        .methods = &ctr_methods
};
const _libssh2_cipher_type _libssh2_cipher_aes192ctr = &CipherType_AES192CTR;

static const CipherType CipherType_AES256CTR = {
        .cipher_name = "aes",
        .keylen = 256 / 8,
        .methods = &ctr_methods
};
const _libssh2_cipher_type _libssh2_cipher_aes256ctr = &CipherType_AES256CTR;

// BLOWFISH-CBC cipher definition.

static const CipherType CipherType_Blowfish = {
    .cipher_name = "blowfish",
    .keylen = 64 / 8,
    .methods = &cbc_methods
};
const _libssh2_cipher_type _libssh2_cipher_blowfish = &CipherType_Blowfish;

// CAST5-CBC cipher definition.

static const CipherType CipherType_CAST5 = {
    .cipher_name = "cast5",
    .keylen = 128 / 8,
    .methods = &cbc_methods
};
const _libssh2_cipher_type  _libssh2_cipher_cast5 = &CipherType_CAST5;

// 3DES-CBC cipher definition.

static const CipherType CipherType_3DES = {
    .cipher_name = "3des",
    .keylen = 24,
    .methods = &cbc_methods
};
const _libssh2_cipher_type _libssh2_cipher_3des = &CipherType_3DES;

// Symmetric cipher API

int
_libssh2_cipher_init(_libssh2_cipher_ctx *ctx,
                         _libssh2_cipher_type type,
                         unsigned char *iv,
                         unsigned char *secret, int encrypt)
{
    (void)encrypt;

    CipherContext *context = (CipherContext *)calloc(1, sizeof *context);
    if (context == NULL) {
        return -1;
    }
    context->type = type;
    const int cipher = find_cipher(type->cipher_name);
    int rc = type->methods->init(context, cipher, iv, secret);
    if (rc != CRYPT_OK) {
        free(context);
    }
    *ctx = context;
    return 0;
}

int
_libssh2_cipher_crypt(_libssh2_cipher_ctx *ctx,
                          _libssh2_cipher_type type,
                          int encrypt, unsigned char *block, size_t blocksize)
{
    (void)type;

    // Note that all of the *_encrypt and *_decrypt functions seem to allow
    // the same pointer for pt and ct, allowing for the in-place transformation
    // this function needs to provide.

    CipherContext *context = *ctx;
    int rc;
    if (encrypt) {
        rc = context->type->methods->encrypt(context, block, blocksize);
    } else {
        rc = context->type->methods->decrypt(context, block, blocksize);
    }
    return rc == CRYPT_OK ? 0 : -1;
}

void
_libssh2_cipher_dtor(_libssh2_cipher_ctx *ctx)
{
    (*ctx)->type->methods->dtor(*ctx);
    free(*ctx);
    *ctx = NULL;
}

// RSA API

int
_libssh2_rsa_new(libssh2_rsa_ctx ** rsap,
                 const unsigned char *edata,
                 unsigned long elen,
                 const unsigned char *ndata,
                 unsigned long nlen,
                 const unsigned char *ddata,
                 unsigned long dlen,
                 const unsigned char *pdata,
                 unsigned long plen,
                 const unsigned char *qdata,
                 unsigned long qlen,
                 const unsigned char *e1data,
                 unsigned long e1len,
                 const unsigned char *e2data,
                 unsigned long e2len,
                 const unsigned char *coeffdata, unsigned long coefflen) {
    rsa_key key;
    memset(&key, 0, sizeof key);
    key.type = (ddata == NULL || dlen == 0) ? PK_PUBLIC : PK_PRIVATE;

    int status = ltc_init_multi(&key.e, &key.d, &key.N, &key.p, &key.q, &key.qP, &key.dP, &key.dQ, NULL);
    if (status == CRYPT_OK) status = ltc_mp.unsigned_read(&key.e, (unsigned char *) edata, elen);
    if (status == CRYPT_OK) status = ltc_mp.unsigned_read(&key.N, (unsigned char *) ndata, nlen);
    if (status == CRYPT_OK) status = ltc_mp.unsigned_read(&key.d, (unsigned char *) ddata, dlen);
    if (status == CRYPT_OK) status = ltc_mp.unsigned_read(&key.p, (unsigned char *) pdata, plen);
    if (status == CRYPT_OK) status = ltc_mp.unsigned_read(&key.q, (unsigned char *) qdata, qlen);
    if (status == CRYPT_OK) status = ltc_mp.unsigned_read(&key.qP, (unsigned char *) coeffdata, coefflen);
    if (status == CRYPT_OK) status = ltc_mp.unsigned_read(&key.dP, (unsigned char *) e1data, e1len);
    if (status == CRYPT_OK) status = ltc_mp.unsigned_read(&key.dQ, (unsigned char *) e2data, e2len);

    if (status != CRYPT_OK) {
        rsa_free(&key);
        return -1;
    }

    libssh2_rsa_ctx *rsa = (libssh2_rsa_ctx *)calloc(1, sizeof *rsa);
    if (rsa == NULL) {
        rsa_free(&key);
        return -1;
    }

    *rsa = key;
    *rsap = rsa;
    return 0;
}

void
_libssh2_rsa_free(libssh2_rsa_ctx *rsa)
{
    rsa_free(rsa);
    free(rsa);
}

// Miscellaneous crypto API.

void
libssh2_crypto_init(void)
{
    ltc_mp = ltm_desc;
    register_hash(&sha1_desc);
    register_hash(&sha256_desc);
    register_hash(&sha512_desc);
    register_hash(&md5_desc);
    register_hash(&rmd160_desc);
    register_cipher(&aes_desc);
    register_cipher(&blowfish_desc);
    register_cipher(&cast5_desc);
    register_cipher(&des3_desc);
}

void
libssh2_crypto_exit(void)
{
}

#endif
