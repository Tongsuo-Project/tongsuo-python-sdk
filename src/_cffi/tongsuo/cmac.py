# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.


INCLUDES = """
#if !defined(OPENSSL_NO_CMAC)
#include <openssl/cmac.h>
#endif
"""

TYPES = """
typedef ... CMAC_CTX;
"""

FUNCTIONS = """
CMAC_CTX *CMAC_CTX_new(void);
int CMAC_Init(CMAC_CTX *, const void *, size_t, const EVP_CIPHER *, ENGINE *);
int CMAC_Update(CMAC_CTX *, const void *, size_t);
int CMAC_Final(CMAC_CTX *, unsigned char *, size_t *);
int CMAC_CTX_copy(CMAC_CTX *, const CMAC_CTX *);
void CMAC_CTX_free(CMAC_CTX *);
"""

CUSTOMIZATIONS = """
"""
