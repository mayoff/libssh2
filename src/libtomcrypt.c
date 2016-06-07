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

void
libssh2_crypto_init(void)
{
    ltc_mp = ltm_desc;
}

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

#endif
