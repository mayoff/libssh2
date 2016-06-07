
# define LIBSSH2_RSA 1

void libssh2_crypto_init(void);

typedef struct Rsa_key libssh2_rsa_ctx;
void _libssh2_rsa_free(libssh2_rsa_ctx *rsa);
