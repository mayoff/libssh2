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

// Symmetric cipher implementation details.

typedef struct LibTomCrypt_CipherContext CipherContext;

typedef struct LibTomCrypt_CipherType {
    const char *cipher_name;
    int keylen; // in bytes
    int (*init)(CipherContext *ctx, const unsigned char *iv, const unsigned char *key);
    int (*encrypt)(CipherContext *ctx, unsigned char *block, size_t blocksize);
    int (*decrypt)(CipherContext *context, unsigned char *block, size_t blocksize);
    void (*dtor)(CipherContext *ctx);
} CipherType;

typedef struct LibTomCrypt_CipherContext {
    const CipherType *type;
    union {
        symmetric_CBC cbc;
        symmetric_CTR ctr;
    };
} CipherContext;

// AES-CTR implementation details.

static int
ctr_init(CipherContext *context, const unsigned char *iv, const unsigned char *key)
{
    const CipherType *type = context->type;
    const int cipher = find_cipher(type->cipher_name);
    const int num_rounds = 0; // libtomcrypt will compute the correct number of rounds for keylen.
    // dropbear uses CTR_COUNTER_BIG_ENDIAN so I assume that's correct.
    return ctr_start(cipher, iv, key, type->keylen, num_rounds, CTR_COUNTER_BIG_ENDIAN, &context->ctr);
}

static int
ctr_encrypt_wrapper(CipherContext *context, unsigned char *block, size_t blocksize)
{
    // I inspected the ctr_encrypt source code.
    // It appears to be safe to pass the same pointer for pt and ct.
    // Ditto for all the other *_encrypt and *_decrypt functions.
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

static const CipherType CipherType_AES128CTR = {
        .cipher_name = "aes",
        .keylen = 128 / 8,
        .init = ctr_init,
        .encrypt = ctr_encrypt_wrapper,
        .decrypt = ctr_decrypt_wrapper,
        .dtor = ctr_dtor,
};
const _libssh2_cipher_type _libssh2_cipher_aes128ctr = &CipherType_AES128CTR;

static const CipherType CipherType_AES192CTR = {
        .cipher_name = "aes",
        .keylen = 192 / 8,
        .init = ctr_init,
        .encrypt = ctr_encrypt_wrapper,
        .decrypt = ctr_decrypt_wrapper,
        .dtor = ctr_dtor,
};
const _libssh2_cipher_type _libssh2_cipher_aes192ctr = &CipherType_AES192CTR;

static const CipherType CipherType_AES256CTR = {
        .cipher_name = "aes",
        .keylen = 256 / 8,
        .init = ctr_init,
        .encrypt = ctr_encrypt_wrapper,
        .decrypt = ctr_decrypt_wrapper,
        .dtor = ctr_dtor,
};
const _libssh2_cipher_type _libssh2_cipher_aes256ctr = &CipherType_AES256CTR;

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
    int rc = type->init(context, iv, secret);
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
    CipherContext *context = *ctx;
    int rc;
    if (encrypt) {
        rc = context->type->encrypt(context, block, blocksize);
    } else {
        rc = context->type->decrypt(context, block, blocksize);
    }
    return rc == CRYPT_OK ? 0 : -1;
}

void
_libssh2_cipher_dtor(_libssh2_cipher_ctx *ctx)
{
    (*ctx)->type->dtor(*ctx);
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
}


#endif
