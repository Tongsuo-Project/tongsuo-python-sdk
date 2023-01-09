# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.


INCLUDES = """
#include <openssl/hmac.h>
"""

TYPES = """
typedef ... HMAC_CTX;
"""

FUNCTIONS = """
int HMAC_Init_ex(HMAC_CTX *, const void *, int, const EVP_MD *, ENGINE *);
int HMAC_Update(HMAC_CTX *, const unsigned char *, size_t);
int HMAC_Final(HMAC_CTX *, unsigned char *, unsigned int *);
int HMAC_CTX_copy(HMAC_CTX *, HMAC_CTX *);

HMAC_CTX *HMAC_CTX_new(void);
void HMAC_CTX_free(HMAC_CTX *ctx);
"""

CUSTOMIZATIONS = """
"""
