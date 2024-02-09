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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "tinycrypto.h"
#include "test_digest.h"

#ifndef TEST_PADDING
#define TEST_PADDING "\xDE\xAD\xBE\xEF" "\xDE\xAD\xBE\xEF" "\xDE\xAD\xBE\xEF" "\xDE\xAD\xBE\xEF" "\xDE\xAD\xBE\xEF" "\xDE\xAD\xBE\xEF" "\xDE\xAD\xBE\xEF" "\xDE\xAD\xBE\xEF" "\xDE\xAD\xBE\xEF" "\xDE\xAD\xBE\xEF"
#endif

#define A2U8V(S) (uint8_t const *)(S TEST_PADDING)
#define A2U8VU(S) { A2U8V(S) }

struct digest_callbacks const sha256_digest_callbacks = {
	TINYCRYPTO_NAME(sha256_digest_alloc),
	TINYCRYPTO_NAME(sha256_digest_update),
	TINYCRYPTO_NAME(sha256_digest_final),
	TINYCRYPTO_NAME(sha256_digest_cleanup)
};

struct test_digest_params const sha256_invalid_hashes[] = {
	{
		(uint8_t *)NULL,
		0,
		A2U8VU("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
	},
};

struct test_digest_params const sha256_test_values[] = {
	{
		A2U8V(""),
		0,
		A2U8VU("\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55"),
	},
	{
		A2U8V("abc"),
		3,
		A2U8VU("\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad"),
	},
	{
		A2U8V("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
		56,
		A2U8VU("\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39\xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1"),
	},
	{
		A2U8V("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
		112,
		A2U8VU("\xcf\x5b\x16\xa7\x78\xaf\x83\x80\x03\x6c\xe5\x9e\x7b\x04\x92\x37\x0b\x24\x9b\x11\xe8\xf0\x7a\x51\xaf\xac\x45\x03\x7a\xfe\xe9\xd1"),
	},
	{
		A2U8V("The quick brown fox jumps over the lazy dog"),
		43,
		A2U8VU("\xd7\xa8\xfb\xb3\x07\xd7\x80\x94\x69\xca\x9a\xbc\xb0\x08\x2e\x4f\x8d\x56\x51\xe4\x6d\x3c\xdb\x76\x2d\x02\xd0\xbf\x37\xc9\xe5\x92"),
	},
	{
		A2U8V("The quick brown fox jumps over the lazy dof"),
		43,
		A2U8VU("\xa1\xcb\xac\x0e\x93\x07\x5a\xb6\x6a\xd5\x9f\xf5\x4c\x32\xc8\xab\xca\xeb\x53\x3f\x05\x68\xe1\x09\x28\x1e\xd5\x7e\xb5\x19\x68\x55"),
	},
};

int main(int argc, char * * argv) {
	int r, f = 0;
	size_t i;
	(void)argc;
	(void)argv;

	r = digest_assert_equal(sha256_invalid_hashes, 32, ERR_HASH_MISMATCH, &sha256_digest_callbacks);
	if (r == ERR_HASH_MISMATCH) {
		printf("Test [%zu/%zu]: %s\n", (size_t)1, 1 + (sizeof(sha256_test_values) / sizeof(*sha256_test_values)), "PASS");
		r = TINYCRYPTO_OK;
	} else {
		printf("Test [%zu/%zu]: %s\n", (size_t)1, 1 + (sizeof(sha256_test_values) / sizeof(*sha256_test_values)), "FAIL");
		f |= 1;
		r = ERR_HASH_UNEXPECTED_SUCCESS;
	}

	for (i = 0; i < (sizeof(sha256_test_values) / sizeof(*sha256_test_values)); i++) {
		r = digest_assert_equal(&(sha256_test_values[i]), 32, TINYCRYPTO_OK, &sha256_digest_callbacks);
		printf("Test [%zu/%zu]: %s\n", i + 2, 1 + (sizeof(sha256_test_values) / sizeof(*sha256_test_values)), (r == TINYCRYPTO_OK) ? "PASS" : "FAIL");
		if (r != TINYCRYPTO_OK) f |= 1;
	}
	return (f == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
