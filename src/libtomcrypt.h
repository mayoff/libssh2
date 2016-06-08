
#define LIBSSH2_RSA 1
#define LIBSSH2_AES 1
#define LIBSSH2_AES_CTR 1

void libssh2_crypto_init(void);

typedef struct LibTomCrypt_CipherContext *_libssh2_cipher_ctx;
typedef const struct LibTomCrypt_CipherType *const _libssh2_cipher_type;
void _libssh2_cipher_dtor(_libssh2_cipher_ctx *ctx);

extern _libssh2_cipher_type _libssh2_cipher_aes128;
extern _libssh2_cipher_type _libssh2_cipher_aes192;
extern _libssh2_cipher_type _libssh2_cipher_aes256;
extern _libssh2_cipher_type _libssh2_cipher_aes128ctr;
extern _libssh2_cipher_type _libssh2_cipher_aes192ctr;
extern _libssh2_cipher_type _libssh2_cipher_aes256ctr;

typedef struct Rsa_key libssh2_rsa_ctx;
void _libssh2_rsa_free(libssh2_rsa_ctx *rsa);
