/******************************************************************************
 * Copyright © 2024 Exact Realty Limited                                      *
 * Copyright © 2018 Aalto University                                          *
 * Secure Systems Group, https://ssg.aalto.fi                                 *
 *                                                                            *
 * Author: Ricardo Iván Vieitez Parra                                         *
 *                                                                            *
 * Licensed under the Apache License, Version 2.0 (the "License");            *
 * you may not use this file except in compliance with the License.           *
 * You may obtain a copy of the License at                                    *
 *                                                                            *
 *     http://www.apache.org/licenses/LICENSE-2.0                             *
 *                                                                            *
 * Unless required by applicable law or agreed to in writing, software        *
 * distributed under the License is distributed on an "AS IS" BASIS,          *
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   *
 * See the License for the specific language governing permissions and        *
 * limitations under the License.                                             *
 ******************************************************************************/

#pragma once
#ifndef TINYCRYPTO_H
#define TINYCRYPTO_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef TINYCRYPTO_NAME
#define TINYCRYPTO_NAME(NAME) TINYCRYPTO_ ## NAME
#endif

#ifndef TINYCRYPTO_CIPHER_AES_CTR_RFC3686
#define TINYCRYPTO_CIPHER_AES_CTR_RFC3686 1
#endif

#ifndef TINYCRYPTO_CIPHER_AES_CBC_PKCS7
#define TINYCRYPTO_CIPHER_AES_CBC_PKCS7 2
#endif

#include <stddef.h>

#ifndef TINYCRYPTO_OK
#define TINYCRYPTO_OK 0
#endif

#ifndef TINYCRYPTO_ERR_UNKNOWN
#define TINYCRYPTO_ERR_UNKNOWN -1
#endif

#ifndef TINYCRYPTO_ERR_NOMEM
#define TINYCRYPTO_ERR_NOMEM -2
#endif

#ifndef TINYCRYPTO_ERR_INVALID_ARGUMENTS
#define TINYCRYPTO_ERR_INVALID_ARGUMENTS -3
#endif

#ifdef WITH_SHA256
int TINYCRYPTO_NAME(sha256_digest_init)(void * digest_context_p);
int TINYCRYPTO_NAME(sha256_digest_update)(void * digest_context_p, uint8_t const * data_p, size_t data_len);
int TINYCRYPTO_NAME(sha256_digest_final)(void * digest_context_p, uint8_t output[static 32]);
#ifdef WITH_ALLOC
int TINYCRYPTO_NAME(sha256_digest_alloc)(void ** digest_context_pp);
void TINYCRYPTO_NAME(sha256_digest_cleanup)(void * digest_context_p);
#endif
size_t TINYCRYPTO_NAME(sha256_digest_ctx_sz)(void);
int TINYCRYPTO_NAME(sha256_digest_ctx_import)(void * digest_context_p);
int TINYCRYPTO_NAME(sha256_digest_ctx_export)(void * digest_context_p);
#endif

#ifdef WITH_SHA512
int TINYCRYPTO_NAME(sha512_digest_init)(void * digest_context_p);
int TINYCRYPTO_NAME(sha512_digest_update)(void * digest_context_p, uint8_t const * data_p, size_t data_len);
int TINYCRYPTO_NAME(sha512_digest_final)(void * digest_context_p, uint8_t output[static 64]);
#ifdef WITH_ALLOC
int TINYCRYPTO_NAME(sha512_digest_alloc)(void ** digest_context_pp);
void TINYCRYPTO_NAME(sha512_digest_cleanup)(void * digest_context_p);
#endif
size_t TINYCRYPTO_NAME(sha512_digest_ctx_sz)(void);
int TINYCRYPTO_NAME(sha512_digest_ctx_import)(void * digest_context_p);
int TINYCRYPTO_NAME(sha512_digest_ctx_export)(void * digest_context_p);
#endif

#ifdef __cplusplus
}
#endif
#endif
