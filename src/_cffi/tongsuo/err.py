# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.

INCLUDES = """
#include <openssl/err.h>
"""

TYPES = """
static const int CIPHER_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH;

static const int EVP_F_EVP_ENCRYPTFINAL_EX;
static const int EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH;
static const int EVP_R_BAD_DECRYPT;
static const int EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM;
static const int PKCS12_R_PKCS12_CIPHERFINAL_ERROR;
static const int PEM_R_UNSUPPORTED_ENCRYPTION;
static const int EVP_R_XTS_DUPLICATED_KEYS;

static const int ERR_LIB_EVP;
static const int ERR_LIB_PEM;
static const int ERR_LIB_PROV;
static const int ERR_LIB_ASN1;
static const int ERR_LIB_PKCS12;

static const int SSL_TLSEXT_ERR_OK;
static const int SSL_TLSEXT_ERR_ALERT_FATAL;
static const int SSL_TLSEXT_ERR_NOACK;

static const int X509_R_CERT_ALREADY_IN_HASH_TABLE;

static const int SSL_R_UNEXPECTED_EOF_WHILE_READING;

static const int Cryptography_HAS_UNEXPECTED_EOF_WHILE_READING;
"""

FUNCTIONS = """
void ERR_error_string_n(unsigned long, char *, size_t);
const char *ERR_lib_error_string(unsigned long);
const char *ERR_func_error_string(unsigned long);
const char *ERR_reason_error_string(unsigned long);
unsigned long ERR_get_error(void);
unsigned long ERR_peek_error(void);
void ERR_clear_error(void);
void ERR_put_error(int, int, int, const char *, int);

int ERR_GET_LIB(unsigned long);
int ERR_GET_REASON(unsigned long);

"""

CUSTOMIZATIONS = """
/* This define is tied to provider support and is conditionally
   removed if Cryptography_HAS_PROVIDERS is false */
#ifndef ERR_LIB_PROV
#define ERR_LIB_PROV 0
#endif

#if !CRYPTOGRAPHY_OPENSSL_111D_OR_GREATER
static const int EVP_R_XTS_DUPLICATED_KEYS = 0;
#endif

static const int CIPHER_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH = 0;

/* SSL_R_UNEXPECTED_EOF_WHILE_READING is needed for pyOpenSSL
   with OpenSSL 3+ */
#if defined(SSL_R_UNEXPECTED_EOF_WHILE_READING)
#define Cryptography_HAS_UNEXPECTED_EOF_WHILE_READING 1
#else
#define Cryptography_HAS_UNEXPECTED_EOF_WHILE_READING 0
#define SSL_R_UNEXPECTED_EOF_WHILE_READING 0
#endif
"""
