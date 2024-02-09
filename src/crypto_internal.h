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
#ifndef CRYPTO_INTERNAL_H
#define CRYPTO_INTERNAL_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef __STDC_WANT_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1
#endif
#include <string.h>

#ifdef TINYCRYPTO_ADDL_INCLUDE_HEADER
#include TINYCRYPTO_ADDL_INCLUDE_HEADER
#endif

#include "tinycrypto.h"

#ifdef HAVE_TMMINTRIN_H
#include <tmmintrin.h>
#endif
#ifdef HAVE_WMMINTRIN_H
#include <wmmintrin.h>
#endif

#ifdef __STDC_LIB_EXT1__
#define SAFE_MEMSET(DEST, CH, COUNT) do { if ((COUNT) != 0) memset_s(DEST, COUNT, CH, COUNT); } while(0)
#else

#if defined(__clang__) && defined(__has_attribute)
#if __has_attribute(optnone)
#define ATTR_OPTIMIZE_0 __attribute__((optnone))
#endif
#elif !defined(__clang__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 7))
#define ATTR_OPTIMIZE_0 __attribute__((optimize("-O0")))
#endif

#ifndef ATTR_OPTIMIZE_0
#define ATTR_OPTIMIZE_0 /* */
#ifdef _MSC_VER
#pragma optimize("", off)
#endif
#endif

#ifndef HIDDEN_SYMBOL
#if __GNUC__ >= 4
#define HIDDEN_SYMBOL __attribute__ ((visibility ("hidden")))
#else
#define HIDDEN_SYMBOL /**/
#endif 
#endif

inline static void ATTR_OPTIMIZE_0 HIDDEN_SYMBOL __crypto_safe_memset(void * const dest, int const ch, size_t count) {
	char volatile * vcdest = (char volatile *)dest;
	if (dest == NULL) return;
	for (; count != 0; count--) {
		vcdest[0] = (char)ch;
		vcdest++;
	}
}
#define SAFE_MEMSET(DEST, CH, COUNT) __crypto_safe_memset(DEST, CH, COUNT)
#endif

#define TINYCRYPTO_NAME_INTERNAL(NAME) INTERNAL_ ## NAME

#ifndef MIN
#define MIN(a, b) (((a) > (b)) ? (b) : (a))
#endif

#define BASICPASTE(A, B) A ## B
#define PASTE(A, B) BASICPASTE(A, B)

#define BASICTOKENIZE(A) #A
#define TOKENIZE(A) BASICTOKENIZE(A)

#ifndef DEBUG_PRINTF_CALL
#define DEBUG_PRINTF_CALL(...) fprintf(stderr, __VA_ARGS__)
#endif
#define DEBUG_PRINTF(SRC, STR, ...) DEBUG_PRINTF_CALL("%s:%d:[%s] " STR, __FILE__, __LINE__, SRC, __VA_ARGS__)

#ifndef __has_builtin
#define __has_builtin(X) (0)
#endif

#if !defined(UNREACHABLE_CODE)
#if (defined(__GNUC__) && defined(__GNUC_MINOR__) && defined(__GNUC_PATCHLEVEL__) && \
	((__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__) >= 40500) \
) || __has_builtin(__builtin_unreachable)
#define UNREACHABLE_CODE()  __builtin_unreachable()
#elif defined(_MSC_VER) && _MSC_VER >= 1400 /* MSVC 2005 and newer. __assume is probably older than this but I'm unsure
 * of the exact version it appeared in. For the purposes of this code, 2005 should suffice. */
#define UNREACHABLE_CODE() __assume(0)
#endif
#endif

#if !defined(UNREACHABLE_CODE)
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#include <stdnoreturn.h>
static _Noreturn void UNREACHABLE_CODE() {
    return;
}
#else
#include <stdlib.h>
static inline void UNREACHABLE_CODE() {
	abort();
    return;
}
#endif
#endif

#include "sse_intrinsics.h"

#endif
