#pragma once
#ifndef TEST_DIGEST_H
#define TEST_DIGEST_H
#include <stdint.h>
#include <stdlib.h>
#ifdef __cplusplus
extern "C" {
#endif

#define ERR_HASH_UNEXPECTED_SUCCESS 0x1F
#define ERR_HASH_MISMATCH 0x11
#define ERR_HASH_NOMEM 0x12

typedef int (* digest_final_callback)(void * digest_context_p, uint8_t output[]);

union digest_data_pointer {
	uint8_t const * u8;
	uint32_t const * u32;
	uint64_t const * u64;
};

struct digest_callbacks {
	int (* const digest_init)(void ** digest_context_pp);
	int (* const digest_update)(void * digest_context_p, const uint8_t * data_p, size_t data_len);
	int (* const digest_final)(void * digest_context_p, uint8_t output[]);
	void (* const digest_cleanup)(void * digest_context_p);
};

struct test_digest_params {
	uint8_t const * in;
	size_t in_len;
	union digest_data_pointer out;
};

int digest_assert_equal(struct test_digest_params const * params, size_t out_len, int expect, struct digest_callbacks const * fn);

#ifdef __cplusplus
}
#endif
#endif
