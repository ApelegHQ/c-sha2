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

#include "crypto_internal.h"

#if defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif

#if defined(HAVE_XMMINTRIN_H) && defined(HAVE__MM_MALLOC) && defined(HAVE__MM_FREE)
#include <xmmintrin.h>
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && defined(HAVE_ALIGNED_ALLOC)
#include <stdlib.h>
#elif ((defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200112L) || (defined(_XOPEN_SOURCE) && _XOPEN_SOURCE >= 600)) && defined(HAVE_POSIX_MEMALIGN)
#include <stdlib.h>
#elif defined(HAVE_MEMALIGN__MALLOC_H)
#include <malloc.h>
#elif defined(HAVE_MEMALIGN__STDLIB_H)
#include <stdlib.h>
#elif defined(_MSC_VER) && defined(HAVE__ALIGNED_MALLOC)
#include <malloc.h>
#endif

#if defined(TINYCRYPTO_DEBUG_SHA2_DIGEST)
#include <inttypes.h>
#else
#include <stdint.h>
#endif

#if defined(__SSE2__) && defined(HAVE_EMMINTRIN_H)
#include <emmintrin.h>
#endif

#if defined(TINYCRYPTO_DEBUG_SHA2_DIGEST)
#define SHA2_DIGEST_DEBUG_PRINTF(...) DEBUG_PRINTF(__VA_ARGS__)
#define SHA2_DIGEST_DEBUG_BASICPRINTF(...) DEBUG_PRINTF_CALL(__VA_ARGS__)

inline static void sha2_printInput(uint8_t const * const input, size_t const sz) {
	size_t i;
	for (i = 0; i < sz; i++) {
		SHA2_DIGEST_DEBUG_BASICPRINTF("%s%02" PRIX8, (i != 0 && (i % 4) == 0) ? " " : "", input[i]);
	}
	SHA2_DIGEST_DEBUG_BASICPRINTF("\n");
}

inline static void sha2_printState32(uint32_t const * const state, size_t const sz) {
	size_t i;
	for (i = 0; i < sz; i++) {
		SHA2_DIGEST_DEBUG_BASICPRINTF("%08" PRIX32 " ", state[i]);
	}
	SHA2_DIGEST_DEBUG_BASICPRINTF("\n");
}

inline static void sha2_printState64(uint64_t const * const state, size_t const sz) {
	size_t i;
	for (i = 0; i < sz; i++) {
		SHA2_DIGEST_DEBUG_BASICPRINTF("%016" PRIX64 " ", state[i]);
	}
	SHA2_DIGEST_DEBUG_BASICPRINTF("\n");
}

#else
#define SHA2_DIGEST_DEBUG_PRINTF(...)
#define SHA2_DIGEST_DEBUG_BASICPRINTF(...)
#define sha2_printInput(...)
#define sha2_printState32(...)
#define sha2_printState64(...)
#endif

#ifdef WITH_ALLOC
#if defined(HAVE_XMMINTRIN_H) && defined(HAVE__MM_MALLOC) && defined(HAVE__MM_FREE)
#define ALIGNED_ALLOC(A, SZ) _mm_malloc(SZ, A)
#define ALIGNED_FREE(P) _mm_free(P)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && defined(HAVE_ALIGNED_ALLOC)
#define ALIGNED_ALLOC(A, SZ) aligned_alloc(A, SZ)
#define ALIGNED_FREE(P) free(P)
#elif ((defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200112L) || (defined(_XOPEN_SOURCE) && _XOPEN_SOURCE >= 600)) && defined(HAVE_POSIX_MEMALIGN)
inline static void * TINYCRYPTO_NAME_INTERNAL(posix_memalign_wrapper)(size_t const alignment, size_t const size);

inline static void * TINYCRYPTO_NAME_INTERNAL(posix_memalign_wrapper)(size_t const alignment, size_t const size) {
	void *memptr;
	int r;

	r = posix_memalign(&memptr, alignment, size);
	if (0 == r) {
		return memptr;
	} else {
		return NULL;
	}
}

#define ALIGNED_ALLOC(A, SZ) TINYCRYPTO_NAME_INTERNAL(posix_memalign_wrapper)(A, SZ)
#define ALIGNED_FREE(P) free(P)
#elif defined(HAVE_MEMALIGN__MALLOC_H) || defined(HAVE_MEMALIGN__STDLIB_H)
#define ALIGNED_ALLOC(A, SZ) memalign(A, SZ)
#if defined(__GLIBC__)
#define ALIGNED_FREE(P) free(P)
#else
/* Some implementations provide no means of deallocating memalign-allocated blocks */
#define ALIGNED_FREE(P) do { (void)(P); } while(0)
#endif
#elif defined(_MSC_VER) && defined(HAVE__ALIGNED_MALLOC)
#define ALIGNED_ALLOC(A, SZ) _aligned_malloc(SZ, A)
#define ALIGNED_FREE(P) free(P)
#else

#warning "This system may not supported aligned memory allocation, which may result in runtime failures. It is recommended to build with an aligned memory allocator."
#define ALIGNED_ALLOC(A, SZ) malloc(SZ)
#define ALIGNED_FREE(P) free(P)
#endif
#endif

#define SHA2_COMPRESS(SRC, FAMILY, NAME, PREPEND, STATE, BLOCK) do { \
	size_t SHA2_COMPRESS_i; \
	(void)SHA2_COMPRESS_i; \
	SHA2_DIGEST_DEBUG_PRINTF(SRC, PREPEND "%s_compress(%s=%p, %s=%p)\n", #FAMILY, TOKENIZE(STATE), (void *)(STATE), TOKENIZE(BLOCK), (void *)(BLOCK)); \
	FAMILY ## _compress(STATE, BLOCK); \
\
	SHA2_DIGEST_DEBUG_PRINTF(SRC, "%s\t> ", ""); \
	sha2_printInput(BLOCK, FAMILY ## _BLOCK_SIZE); \
	SHA2_DIGEST_DEBUG_PRINTF(SRC, "%s\t= ", ""); \
	PASTE(sha2_printState, NAME ## _STATE_SELECTOR_W)(STATE, sizeof(STATE) / sizeof(STATE[0])); \
} while(0)

#define SHA2_DIGEST_INIT(FAMILY, NAME) \
inline static void TINYCRYPTO_NAME_INTERNAL(NAME ## _digest_init_ctx)(struct FAMILY ## _digest_context * const ctx_p) { \
	if (ctx_p == NULL) { \
		UNREACHABLE_CODE(); \
	} \
\
	/* Initial block state */ \
	memcpy(&(ctx_p->state.FAMILY ## _STATE_SELECTOR), NAME ## _INITIAL_BLOCK_STATE, sizeof(ctx_p->state.FAMILY ## _STATE_SELECTOR)); \
	ctx_p->sb.sz = 0; \
	ctx_p->len.sz = 0; \
} \
\
int TINYCRYPTO_NAME(NAME ## _digest_init)(void * digest_context_p_) { \
	struct FAMILY ## _digest_context * digest_context_p; \
\
	if (digest_context_p_ == NULL) { \
		return TINYCRYPTO_ERR_INVALID_ARGUMENTS; \
	} \
\
	digest_context_p = digest_context_p_; \
\
	TINYCRYPTO_NAME_INTERNAL(NAME ## _digest_init_ctx)(digest_context_p); \
\
	return TINYCRYPTO_OK; \
\
}

#define SHA2_DIGEST_UPDATE(FAMILY, NAME) \
int TINYCRYPTO_NAME(NAME ## _digest_update)(void * restrict digest_context_p, const uint8_t * restrict data_p, size_t const _data_len) { \
	size_t data_len = _data_len; \
\
	struct FAMILY ## _digest_context * const ctx_p = (struct FAMILY ## _digest_context *)digest_context_p; \
\
	SHA2_DIGEST_DEBUG_PRINTF(#NAME "_digest_update", ">> (digest_context_p=%p, data_p=%p, _data_len=%zu)\n", digest_context_p, data_p, _data_len); \
	if (ctx_p == NULL) { \
		return TINYCRYPTO_ERR_INVALID_ARGUMENTS; \
	} \
\
	if (ctx_p->sb.sz > 0 && _data_len > 0) { \
		SHA2_DIGEST_DEBUG_PRINTF(#NAME "_digest_update", " (PB) memcpy(ctx_p->b.u8=%p + ctx_p->sb.sz=%zu, data_p=%p, %zu)\n", ctx_p->b.u8, ctx_p->sb.sz, data_p, MIN(FAMILY ## _BLOCK_SIZE - ctx_p->sb.sz, _data_len)); \
		memcpy(ctx_p->b.u8 + ctx_p->sb.sz, data_p, MIN(FAMILY ## _BLOCK_SIZE - ctx_p->sb.sz, _data_len)); \
		data_p += MIN(FAMILY ## _BLOCK_SIZE - ctx_p->sb.sz, _data_len); \
		data_len -= MIN(FAMILY ## _BLOCK_SIZE - ctx_p->sb.sz, _data_len); \
		ctx_p->sb.sz += MIN(FAMILY ## _BLOCK_SIZE - ctx_p->sb.sz, _data_len); \
\
		if (ctx_p->sb.sz == FAMILY ## _BLOCK_SIZE) { \
			SHA2_COMPRESS(#NAME "_digest_update", FAMILY, NAME, "(FB) ", ctx_p->state.FAMILY ## _STATE_SELECTOR, ctx_p->b.u8); \
			ctx_p->sb.sz = 0; \
		} \
	} \
\
	SHA2_DIGEST_DEBUG_PRINTF(#NAME "_digest_update", "data_len=%zu\n", data_len);\
\
	while(data_len >= FAMILY ## _BLOCK_SIZE) { \
		SHA2_COMPRESS(#NAME "_digest_update", FAMILY, NAME, "", ctx_p->state.FAMILY ## _STATE_SELECTOR, (uint8_t *)data_p); \
		data_p += FAMILY ## _BLOCK_SIZE; \
		data_len -= FAMILY ## _BLOCK_SIZE; \
	} \
\
	if (data_len > 0) { \
		SHA2_DIGEST_DEBUG_PRINTF(#NAME "_digest_update", "memcpy(ctx_p->b.u8=%p, data_p=%p, data_len=%zu);\n", ctx_p->b.u8, data_p, data_len);\
		memcpy(ctx_p->b.u8, data_p, data_len); \
		SHA2_DIGEST_DEBUG_PRINTF(#NAME "_digest_update", "ctx_p->sb.sz=%zu += data_len=%zu\n", ctx_p->sb.sz, data_len);\
		ctx_p->sb.sz += data_len; \
		SHA2_DIGEST_DEBUG_PRINTF(#NAME "_digest_update", "ctx_p->len.sz=%zu += _data_len=%zu\n", ctx_p->len.sz, _data_len);\
	} \
	ctx_p->len.sz += _data_len; \
\
	return TINYCRYPTO_OK; \
}

#if defined(__SSE2__) && defined(HAVE_EMMINTRIN_H)
#define TO_BIG_ENDIAN_STR(S, SIZE, WIDTH) \
do {\
	size_t TO_BIG_ENDIAN_STR_i; \
	__m128i TO_BIG_ENDIAN_STR_temp;\
	for (TO_BIG_ENDIAN_STR_i = 0; TO_BIG_ENDIAN_STR_i < (((SIZE) << 3) / 128) ; TO_BIG_ENDIAN_STR_i++) { \
		TO_BIG_ENDIAN_STR_temp = _mm_loadu_si128( \
			(__m128i const *) &(S).m128i[TO_BIG_ENDIAN_STR_i] \
		); \
		_mm_storeu_si128( \
			&(S).m128i[TO_BIG_ENDIAN_STR_i], \
			PASTE(_mm_bswap_epi, WIDTH)(TO_BIG_ENDIAN_STR_temp) \
		); \
	} \
} while(0)

#define FROM_BIG_ENDIAN_STR(S, SIZE, WIDTH) TO_BIG_ENDIAN_STR(S, SIZE, WIDTH)
#else
#define TO_BIG_ENDIAN_STR(S, SIZE, WIDTH) \
do {\
	size_t TO_BIG_ENDIAN_STR_i, TO_BIG_ENDIAN_STR_j; \
	for (TO_BIG_ENDIAN_STR_i = 0; TO_BIG_ENDIAN_STR_i < (((SIZE) << 3) / WIDTH) ; TO_BIG_ENDIAN_STR_i++) { \
		PASTE(PASTE(uint, WIDTH), _t) TO_BIG_ENDIAN_STR_temp = \
			(S).PASTE(u, WIDTH)[TO_BIG_ENDIAN_STR_i]; \
		for (TO_BIG_ENDIAN_STR_j = 0; TO_BIG_ENDIAN_STR_j < (WIDTH >> 3); TO_BIG_ENDIAN_STR_j++) { \
			(S).u8[(TO_BIG_ENDIAN_STR_i * (WIDTH >> 3)) + TO_BIG_ENDIAN_STR_j] = \
				(TO_BIG_ENDIAN_STR_temp >> (WIDTH - 8 - (TO_BIG_ENDIAN_STR_j << 3))) & 0xFFU; \
		} \
	} \
} while(0)

#define FROM_BIG_ENDIAN_STR(S, SIZE, WIDTH) \
do {\
	size_t FROM_BIG_ENDIAN_STR_i, FROM_BIG_ENDIAN_STR_j; \
	for (FROM_BIG_ENDIAN_STR_i = 0; FROM_BIG_ENDIAN_STR_i < (((SIZE) << 3) / WIDTH) ; FROM_BIG_ENDIAN_STR_i++) { \
		PASTE(PASTE(uint, WIDTH), _t) FROM_BIG_ENDIAN_STR_temp = 0; \
		for (FROM_BIG_ENDIAN_STR_j = 0; FROM_BIG_ENDIAN_STR_j < (WIDTH >> 3); FROM_BIG_ENDIAN_STR_j++) { \
			FROM_BIG_ENDIAN_STR_temp |= \
				(S).u8[(FROM_BIG_ENDIAN_STR_i * (WIDTH >> 3)) + FROM_BIG_ENDIAN_STR_j] \
					<< (WIDTH - 8 - (FROM_BIG_ENDIAN_STR_j << 3)); \
		} \
		(S).PASTE(u, WIDTH)[FROM_BIG_ENDIAN_STR_i] = FROM_BIG_ENDIAN_STR_temp; \
	} \
} while(0)
#endif

#define TO_BIG_ENDIAN_SZ(S) \
do {\
	size_t TO_BIG_ENDIAN_SZ_i; \
    size_t TO_BIG_ENDIAN_SZ_temp = (S).sz; \
    for (TO_BIG_ENDIAN_SZ_i = 0; TO_BIG_ENDIAN_SZ_i < sizeof(size_t); TO_BIG_ENDIAN_SZ_i++) { \
        (S).u8[TO_BIG_ENDIAN_SZ_i] = \
            (TO_BIG_ENDIAN_SZ_temp >> \
                ((sizeof(size_t) << 3) - 8 - (TO_BIG_ENDIAN_SZ_i << 3))) & 0xFFU; \
    } \
} while(0)
#define FROM_BIG_ENDIAN_SZ(S) \
do {\
	size_t FROM_BIG_ENDIAN_SZ_i; \
    size_t FROM_BIG_ENDIAN_SZ_temp = 0; \
    for (FROM_BIG_ENDIAN_SZ_i = 0; FROM_BIG_ENDIAN_SZ_i < sizeof(size_t); FROM_BIG_ENDIAN_SZ_i++) { \
        FROM_BIG_ENDIAN_SZ_temp |= \
            (S).u8[FROM_BIG_ENDIAN_SZ_i] \
                << ((sizeof(size_t) << 3) - 8 - (FROM_BIG_ENDIAN_SZ_i << 3)); \
    } \
    (S).sz = FROM_BIG_ENDIAN_SZ_temp; \
} while(0)


#define SHA2_DIGEST_FINAL(FAMILY, NAME) \
inline static void TINYCRYPTO_NAME_INTERNAL(NAME ## _digest_final_pre)(struct FAMILY ## _digest_context * ctx_p) { \
	size_t len, i; \
\
	SHA2_DIGEST_DEBUG_PRINTF(#NAME "_digest_final_pre", ">> (digest_context_p=%p)\n", digest_context_p); \
	if (ctx_p == NULL) { \
		UNREACHABLE_CODE(); \
	} \
\
	SHA2_DIGEST_DEBUG_PRINTF(#NAME "_digest_final_pre", "ctx_p->b.u8=%p[ctx_p->sb.sz=%zu] = 0x80; \n", ctx_p->b.u8, ctx_p->sb.sz); \
	ctx_p->b.u8[ctx_p->sb.sz] = 0x80; \
\
	if (FAMILY ## _BLOCK_SIZE - ctx_p->sb.sz <= FAMILY ## _LENGTH_SIZE) { \
		SHA2_DIGEST_DEBUG_PRINTF(#NAME "_digest_final_pre", "(SB) SAFE_MEMSET(ctx_p->b.u8=%p + ctx_p->sb.sz=%zu + 1, 0, %zu - ctx_p->sb.sz=%zu - 1); \n", ctx_p->b.u8, ctx_p->sb.sz, FAMILY ## _BLOCK_SIZE, ctx_p->sb.sz); \
		SAFE_MEMSET(ctx_p->b.u8 + ctx_p->sb.sz + 1, 0, FAMILY ## _BLOCK_SIZE - ctx_p->sb.sz - 1); \
		SHA2_COMPRESS(#NAME "_digest_final_pre", FAMILY, NAME, "(SB) ", ctx_p->state.FAMILY ## _STATE_SELECTOR, ctx_p->b.u8); \
		SHA2_DIGEST_DEBUG_PRINTF(#NAME "_digest_final_pre", "(SB) SAFE_MEMSET(ctx_p->b.u8=%p, 0, %zu - %zu); \n", ctx_p->b.u8, FAMILY ## _BLOCK_SIZE, FAMILY ## _LENGTH_SIZE); \
		SAFE_MEMSET(ctx_p->b.u8, 0, FAMILY ## _BLOCK_SIZE - FAMILY ## _LENGTH_SIZE); \
	} else { \
		SHA2_DIGEST_DEBUG_PRINTF(#NAME "_digest_final_pre", "SAFE_MEMSET(ctx_p->b.u8=%p + ctx_p->sb.sz=%zu + 1, 0, %zu - ctx_p->sb.sz=%zu - 1 - %zu); \n", ctx_p->b.u8, ctx_p->sb.sz, FAMILY ## _BLOCK_SIZE , ctx_p->sb.sz, FAMILY ## _LENGTH_SIZE); \
		SAFE_MEMSET(ctx_p->b.u8 + ctx_p->sb.sz + 1, 0, FAMILY ## _BLOCK_SIZE - ctx_p->sb.sz - 1 - FAMILY ## _LENGTH_SIZE); \
	} \
\
	len = ctx_p->len.sz; \
	ctx_p->b.u8[FAMILY ## _BLOCK_SIZE - 1] = (uint8_t)((len & 0x1FU) << 3); \
	len >>= 5; \
	for (i = 1; i < FAMILY ## _LENGTH_SIZE; i++, len >>= 8) { \
		ctx_p->b.u8[FAMILY ## _BLOCK_SIZE - 1 - i] = (uint8_t)(len & 0xFFU); \
	} \
\
	SHA2_COMPRESS(#NAME "_digest_final_pre", FAMILY, NAME, "", ctx_p->state.FAMILY ## _STATE_SELECTOR, ctx_p->b.u8); \
	/* Convert to big endian string */ \
	TO_BIG_ENDIAN_STR(ctx_p->state, FAMILY ## _DIGEST_SIZE, FAMILY ## _STATE_SELECTOR_W); \
} \
\
int TINYCRYPTO_NAME(NAME ## _digest_final)(void * digest_context_p, uint8_t output[static NAME ## _DIGEST_SIZE]) { \
	struct FAMILY ## _digest_context * const ctx_p = (struct FAMILY ## _digest_context *)digest_context_p; \
\
	if (ctx_p != NULL) { \
		TINYCRYPTO_NAME_INTERNAL(NAME ## _digest_final_pre)(digest_context_p); \
		memcpy(output, ctx_p->state.u8, NAME ## _DIGEST_SIZE); \
		return TINYCRYPTO_OK; \
	} \
	return TINYCRYPTO_ERR_INVALID_ARGUMENTS; \
}

#ifdef WITH_ALLOC
#define SHA2_DIGEST_ALLOC(FAMILY, NAME) \
int TINYCRYPTO_NAME(NAME ## _digest_alloc)(void ** digest_context_pp) { \
	struct FAMILY ## _digest_context * digest_context_p; \
\
	if (digest_context_pp == NULL) { \
		return TINYCRYPTO_ERR_INVALID_ARGUMENTS; \
	} \
\
	digest_context_p = ALIGNED_ALLOC(16, sizeof(*digest_context_p)); \
\
	if (digest_context_p == NULL) { \
		return TINYCRYPTO_ERR_NOMEM; \
	}; \
\
	*digest_context_pp = digest_context_p; \
\
	TINYCRYPTO_NAME_INTERNAL(NAME ## _digest_init_ctx)(digest_context_p); \
\
	return TINYCRYPTO_OK; \
\
}

#define SHA2_DIGEST_CLEANUP(FAMILY, NAME) \
void TINYCRYPTO_NAME(NAME ## _digest_cleanup)(void * digest_context_p) { \
	if (digest_context_p != NULL) { \
		SAFE_MEMSET(digest_context_p, 0, sizeof(struct FAMILY ## _digest_context)); \
		ALIGNED_FREE(digest_context_p); \
	} \
}
#else
#define SHA2_DIGEST_ALLOC(FAMILY, NAME) /* not implemented */
#define SHA2_DIGEST_CLEANUP(FAMILY, NAME) /* not implemented */
#endif

#define SHA2_DIGEST_CTX_SZ(FAMILY, NAME) \
size_t TINYCRYPTO_NAME(NAME ## _digest_ctx_sz)(void) { \
	return sizeof(struct FAMILY ## _digest_context);\
}

#define SHA2_DIGEST_CTX_IMPORT_EXPORT(FAMILY, NAME) \
int TINYCRYPTO_NAME(NAME ## _digest_ctx_export)(void * digest_context_p) { \
	struct FAMILY ## _digest_context * const ctx_p = (struct FAMILY ## _digest_context *)digest_context_p; \
\
	if (ctx_p != NULL) { \
		TO_BIG_ENDIAN_STR(ctx_p->state, FAMILY ## _DIGEST_SIZE, FAMILY ## _STATE_SELECTOR_W); \
		SAFE_MEMSET(ctx_p->b.u8 + ctx_p->sb.sz, 0, FAMILY ## _BLOCK_SIZE - ctx_p->sb.sz); \
		TO_BIG_ENDIAN_SZ(ctx_p->sb); \
		TO_BIG_ENDIAN_SZ(ctx_p->len); \
		return TINYCRYPTO_OK; \
	} \
	return TINYCRYPTO_ERR_INVALID_ARGUMENTS; \
} \
int TINYCRYPTO_NAME(NAME ## _digest_ctx_import)(void * digest_context_p) { \
	struct FAMILY ## _digest_context * const ctx_p = (struct FAMILY ## _digest_context *)digest_context_p; \
\
	if (ctx_p != NULL) { \
		FROM_BIG_ENDIAN_STR(ctx_p->state, FAMILY ## _DIGEST_SIZE, FAMILY ## _STATE_SELECTOR_W); \
		FROM_BIG_ENDIAN_SZ(ctx_p->sb); \
		FROM_BIG_ENDIAN_SZ(ctx_p->len); \
		return TINYCRYPTO_OK; \
	} \
	return TINYCRYPTO_ERR_INVALID_ARGUMENTS; \
}

#define SHA2_GENERATE_HELPERS(FAMILY, NAME) \
SHA2_DIGEST_INIT(FAMILY, NAME) \
SHA2_DIGEST_UPDATE(FAMILY, NAME) \
SHA2_DIGEST_FINAL(FAMILY, NAME) \
SHA2_DIGEST_ALLOC(FAMILY, NAME) \
SHA2_DIGEST_CLEANUP(FAMILY, NAME) \
SHA2_DIGEST_CTX_SZ(FAMILY, NAME) \
SHA2_DIGEST_CTX_IMPORT_EXPORT(FAMILY, NAME)

#ifdef WITH_SHA256
#include "sha256.h"

#define sha256_DIGEST_SIZE ((size_t)32)
#define sha256_BLOCK_SIZE ((size_t)64)
#define sha256_LENGTH_SIZE ((size_t)8)
#define sha256_STATE_SELECTOR u32
#define sha256_STATE_SELECTOR_W 32

#define sha256_INITIAL_BLOCK_STATE (uint32_t [8]){UINT32_C(0X6A09E667), UINT32_C(0XBB67AE85), UINT32_C(0X3C6EF372), UINT32_C(0XA54FF53A), \
                                                  UINT32_C(0X510E527F), UINT32_C(0X9B05688C), UINT32_C(0X1F83D9AB), UINT32_C(0X5BE0CD19)}

union sha256_digest {
	uint32_t u32[sha256_DIGEST_SIZE / 4];
	unsigned char u8[sha256_DIGEST_SIZE];
#if defined(__SSE2__) && defined(HAVE_XMMINTRIN_H)
	__m128i m128i[sha256_DIGEST_SIZE / 16];
#endif
};

union sha256_block {
	uint32_t u32[sha256_BLOCK_SIZE / 4];
	unsigned char u8[sha256_BLOCK_SIZE];
#if defined(__SSE2__) && defined(HAVE_XMMINTRIN_H)
	__m128i m128i[sha256_BLOCK_SIZE / 16];
#endif
};

struct sha256_digest_context {
	/* SHA-256 state */
	union sha256_digest state;
	/* Partial block */
	union sha256_block b;
	/* Size of data in partial block */
	union {
		size_t sz;
		uint8_t u8[sizeof(size_t)];
	} sb;
	/* Length of the data */
	union {
		size_t sz;
		uint8_t u8[sizeof(size_t)];
	} len;
};

SHA2_GENERATE_HELPERS(sha256, sha256)
#endif

#ifdef WITH_SHA512
#include "sha512.h"
#define sha512_DIGEST_SIZE ((size_t)64)
#define sha512_BLOCK_SIZE ((size_t)128)
#define sha512_LENGTH_SIZE ((size_t)16)
#define sha512_STATE_SELECTOR u64
#define sha512_STATE_SELECTOR_W 64

#define sha512_INITIAL_BLOCK_STATE (uint64_t [8]){UINT64_C(0X6A09E667F3BCC908), UINT64_C(0XBB67AE8584CAA73B), \
                                                  UINT64_C(0X3C6EF372FE94F82B), UINT64_C(0XA54FF53A5F1D36F1), \
												  UINT64_C(0X510E527FADE682D1), UINT64_C(0X9B05688C2B3E6C1F), \
												  UINT64_C(0X1F83D9ABFB41BD6B), UINT64_C(0X5BE0CD19137E2179)}

union sha512_digest {
	uint64_t u64[sha512_DIGEST_SIZE / 8];
	unsigned char u8[sha512_DIGEST_SIZE];
#if defined(__SSE2__) && defined(HAVE_XMMINTRIN_H)
	__m128i m128i[sha512_DIGEST_SIZE / 16];
#endif
};

union sha512_block {
	uint64_t u64[sha512_BLOCK_SIZE / 8];
	unsigned char u8[sha512_BLOCK_SIZE];
#if defined(__SSE2__) && defined(HAVE_XMMINTRIN_H)
	__m128i m128i[sha512_BLOCK_SIZE / 16];
#endif
};

struct sha512_digest_context {
	/* SHA-512 state */
	union sha512_digest state;
	/* Partial block */
	union sha512_block b;
	/* Size of data in partial block */
	union {
		size_t sz;
		uint8_t u8[sizeof(size_t)];
	} sb;
	/* Length of the data */
	union {
		size_t sz;
		uint8_t u8[sizeof(size_t)];
	} len;
};

SHA2_GENERATE_HELPERS(sha512, sha512)
#endif

#ifdef WITH_HMAC
#define HMAC_I_PAD UINT32_C(0x36363636)
#define HMAC_O_PAD UINT32_C(0x5C5C5C5C)

#ifdef WITH_SHA256
struct hmac_sha256_context {
	struct sha256_digest_context digest_context_i;
	struct sha256_digest_context digest_context_o;
};

inline static void TINYCRYPTO_NAME_INTERNAL(hmac_sha256_init_ctx)(struct hmac_sha256_context * restrict hmac_context_p,
                                                                  const uint8_t * restrict key_p, size_t key_len) {
	union sha256_block i_key_pad, o_key_pad;
	struct sha256_digest_context digest_context_key;
	size_t i;

	if (hmac_context_p == NULL) {
		UNREACHABLE_CODE();
	}

	TINYCRYPTO_NAME_INTERNAL(sha256_digest_init_ctx)(&(hmac_context_p->digest_context_i));
	TINYCRYPTO_NAME_INTERNAL(sha256_digest_init_ctx)(&(hmac_context_p->digest_context_o));

	/* If key is larger than one block, hash it */
	if (key_len > sha256_BLOCK_SIZE) {
		digest_context_key.sb = 0;
		digest_context_key.len = 0;
		TINYCRYPTO_NAME_INTERNAL(sha256_digest_init_ctx)(&digest_context_key);
		if (TINYCRYPTO_NAME(sha256_digest_update)(&digest_context_key, key_p, key_len) != TINYCRYPTO_OK) {
			UNREACHABLE_CODE();
		}
		TINYCRYPTO_NAME_INTERNAL(sha256_digest_final_pre)(&digest_context_key);
		memcpy(digest_context_key.b.u32, digest_context_key.state.u32, sha256_DIGEST_SIZE);
		key_len = sha256_DIGEST_SIZE;
	} else {
		/* Key fits in one block. In this case, set the key. */
		memcpy(digest_context_key.b.u8, key_p, key_len);
	}

	SAFE_MEMSET(digest_context_key.b.u8 + key_len, 0, sha256_BLOCK_SIZE - key_len);

	for (i = 0; i < sha256_BLOCK_SIZE / 4; i++) {
		i_key_pad.u32[i] = digest_context_key.b.u32[i] ^ HMAC_I_PAD;
		o_key_pad.u32[i] = digest_context_key.b.u32[i] ^ HMAC_O_PAD;
	}

	TINYCRYPTO_NAME(sha256_digest_update)(&hmac_context_p->digest_context_i, i_key_pad.u8, sha256_BLOCK_SIZE);
	TINYCRYPTO_NAME(sha256_digest_update)(&hmac_context_p->digest_context_o, o_key_pad.u8, sha256_BLOCK_SIZE);

	SAFE_MEMSET(&digest_context_key, 0, sizeof(digest_context_key));
	SAFE_MEMSET(&i_key_pad, 0, sizeof(i_key_pad));
	SAFE_MEMSET(&o_key_pad, 0, sizeof(o_key_pad));

	return;
}

int TINYCRYPTO_NAME(hmac_sha256_init)(void * * restrict hmac_context_pp, const uint8_t * restrict key_p, size_t key_len) {
	struct hmac_sha256_context *hmac_context_p;

	if (hmac_context_pp == NULL) {
		return TINYCRYPTO_ERR_INVALID_ARGUMENTS;
	}

	hmac_context_p = ALIGNED_ALLOC(16, sizeof(*hmac_context_p));

	if (hmac_context_p == NULL) {
		return TINYCRYPTO_ERR_NOMEM;
	}

	TINYCRYPTO_NAME_INTERNAL(hmac_sha256_init_ctx)(hmac_context_p, key_p, key_len);

	*hmac_context_pp = hmac_context_p;

	return TINYCRYPTO_OK;
}

int TINYCRYPTO_NAME(hmac_sha256_reset)(void * restrict hmac_context_p, const uint8_t * restrict key_p, size_t key_len) {
	if (hmac_context_p == NULL) {
		return TINYCRYPTO_ERR_INVALID_ARGUMENTS;
	}

	TINYCRYPTO_NAME_INTERNAL(hmac_sha256_init_ctx)(hmac_context_p, key_p, key_len);

	return TINYCRYPTO_OK;
}

int TINYCRYPTO_NAME(hmac_sha256_update)(void * restrict hmac_context_p, const uint8_t * restrict data_p, size_t data_len) {
	struct hmac_sha256_context * const ctx_p = (struct hmac_sha256_context *)hmac_context_p;

	if (ctx_p == NULL) {
		return TINYCRYPTO_ERR_INVALID_ARGUMENTS;
	}

	return TINYCRYPTO_NAME(sha256_digest_update)(&ctx_p->digest_context_i, data_p, data_len);
}

int TINYCRYPTO_NAME(hmac_sha256_final)(void * restrict hmac_context_p, uint8_t output[static sha256_DIGEST_SIZE]) {
	struct hmac_sha256_context * const ctx_p = (struct hmac_sha256_context *)hmac_context_p;
	int r;

	TINYCRYPTO_NAME_INTERNAL(sha256_digest_final_pre)(&ctx_p->digest_context_i);
	
	if ((r = TINYCRYPTO_NAME(sha256_digest_update)(&ctx_p->digest_context_o, ctx_p->digest_context_i.state.u8, sha256_DIGEST_SIZE)) == TINYCRYPTO_OK) {
		r = TINYCRYPTO_NAME(sha256_digest_final)(&ctx_p->digest_context_o, output);
	}

	return r;
}

void TINYCRYPTO_NAME(hmac_sha256_cleanup)(void * hmac_context_p) {
	struct hmac_sha256_context * const ctx_p = (struct hmac_sha256_context *)hmac_context_p;
	if (ctx_p != NULL) {
		/* No calls to TINYCRYPTO_NAME(sha256_digest_cleanup) are needed because
		the contexts are not pointers */
		SAFE_MEMSET(hmac_context_p, 0, sizeof(struct hmac_sha256_context));
		ALIGNED_FREE(hmac_context_p);
	}
}
#endif
#endif
