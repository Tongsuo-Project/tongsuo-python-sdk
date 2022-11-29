# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.


INCLUDES = """
#include <openssl/engine.h>
"""

TYPES = """
typedef ... ENGINE;
typedef ... UI_METHOD;

static const long Cryptography_HAS_ENGINE;
"""

FUNCTIONS = """
ENGINE *ENGINE_by_id(const char *);
int ENGINE_init(ENGINE *);
int ENGINE_finish(ENGINE *);
ENGINE *ENGINE_get_default_RAND(void);
int ENGINE_set_default_RAND(ENGINE *);
void ENGINE_unregister_RAND(ENGINE *);
int ENGINE_ctrl_cmd(ENGINE *, const char *, long, void *, void (*)(void), int);
int ENGINE_free(ENGINE *);
const char *ENGINE_get_name(const ENGINE *);

// These bindings are unused by cryptography or pyOpenSSL but are present
// for advanced users who need them.
int ENGINE_ctrl_cmd_string(ENGINE *, const char *, const char *, int);
void ENGINE_load_builtin_engines(void);
EVP_PKEY *ENGINE_load_private_key(ENGINE *, const char *, UI_METHOD *, void *);
EVP_PKEY *ENGINE_load_public_key(ENGINE *, const char *, UI_METHOD *, void *);
"""

CUSTOMIZATIONS = """
#ifdef OPENSSL_NO_ENGINE
static const long Cryptography_HAS_ENGINE = 0;

/* Despite being OPENSSL_NO_ENGINE, BoringSSL defines these symbols. */
int (*ENGINE_free)(ENGINE *) = NULL;
void (*ENGINE_load_builtin_engines)(void) = NULL;

ENGINE *(*ENGINE_by_id)(const char *) = NULL;
int (*ENGINE_init)(ENGINE *) = NULL;
int (*ENGINE_finish)(ENGINE *) = NULL;
ENGINE *(*ENGINE_get_default_RAND)(void) = NULL;
int (*ENGINE_set_default_RAND)(ENGINE *) = NULL;
void (*ENGINE_unregister_RAND)(ENGINE *) = NULL;
int (*ENGINE_ctrl_cmd)(ENGINE *, const char *, long, void *,
                       void (*)(void), int) = NULL;

const char *(*ENGINE_get_id)(const ENGINE *) = NULL;
const char *(*ENGINE_get_name)(const ENGINE *) = NULL;

int (*ENGINE_ctrl_cmd_string)(ENGINE *, const char *, const char *,
                              int) = NULL;
EVP_PKEY *(*ENGINE_load_private_key)(ENGINE *, const char *, UI_METHOD *,
                                     void *) = NULL;
EVP_PKEY *(*ENGINE_load_public_key)(ENGINE *, const char *,
                                    UI_METHOD *, void *) = NULL;

#else
static const long Cryptography_HAS_ENGINE = 1;
#endif
"""
