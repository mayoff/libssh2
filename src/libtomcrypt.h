
#include <tomcrypt.h>

void libssh2_crypto_init(void);
void libssh2_crypto_exit(void);

#define SHA_DIGEST_LENGTH 20
typedef struct LibTomCrypt_SHA1State *libssh2_sha1_ctx;
int libssh2_sha1_init(libssh2_sha1_ctx *ctxp);
void libssh2_sha1_update(libssh2_sha1_ctx ctx, const unsigned char *data, size_t len);
void libssh2_sha1_final(libssh2_sha1_ctx ctx, unsigned char output[SHA_DIGEST_LENGTH]);

#define SHA256_DIGEST_LENGTH 32
typedef struct LibTomCrypt_SHA256State *libssh2_sha256_ctx;
int libssh2_sha256_init(libssh2_sha256_ctx *ctxp);
void libssh2_sha256_update(libssh2_sha256_ctx ctx, const unsigned char *data, size_t len);
void libssh2_sha256_final(libssh2_sha256_ctx ctx, unsigned char output[SHA_DIGEST_LENGTH]);

#define MD5_DIGEST_LENGTH 16
typedef struct LibTomCrypt_MD5State *libssh2_md5_ctx;
int libssh2_md5_init(libssh2_md5_ctx *ctxp);
void libssh2_md5_update(libssh2_md5_ctx ctx, const unsigned char *data, size_t len);
void libssh2_md5_final(libssh2_md5_ctx ctx, unsigned char output[MD5_DIGEST_LENGTH]);

typedef struct LibTomCrypt_CipherContext *_libssh2_cipher_ctx;
typedef const struct LibTomCrypt_CipherType *const _libssh2_cipher_type;
void _libssh2_cipher_dtor(_libssh2_cipher_ctx *ctx);

#define LIBSSH2_AES 1
extern _libssh2_cipher_type _libssh2_cipher_aes128;
extern _libssh2_cipher_type _libssh2_cipher_aes192;
extern _libssh2_cipher_type _libssh2_cipher_aes256;

#define LIBSSH2_AES_CTR 1
extern _libssh2_cipher_type _libssh2_cipher_aes128ctr;
extern _libssh2_cipher_type _libssh2_cipher_aes192ctr;
extern _libssh2_cipher_type _libssh2_cipher_aes256ctr;

#define LIBSSH2_BLOWFISH 1
extern _libssh2_cipher_type _libssh2_cipher_blowfish;

#define LIBSSH2_CAST 1
extern _libssh2_cipher_type _libssh2_cipher_cast5;

#define LIBSSH2_3DES 1
extern _libssh2_cipher_type _libssh2_cipher_3des;

#define LIBSSH2_RSA 1
typedef struct Rsa_key libssh2_rsa_ctx;
void _libssh2_rsa_free(libssh2_rsa_ctx *rsa);
