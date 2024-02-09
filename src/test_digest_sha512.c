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

struct digest_callbacks const sha512_digest_callbacks = {
	TINYCRYPTO_NAME(sha512_digest_alloc),
	TINYCRYPTO_NAME(sha512_digest_update),
	TINYCRYPTO_NAME(sha512_digest_final),
	TINYCRYPTO_NAME(sha512_digest_cleanup)
};

struct test_digest_params const sha512_invalid_hashes[] = {
	{
		(uint8_t *)NULL,
		0,
		A2U8VU("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
	},
};

struct test_digest_params const sha512_test_values[] = {
	{
		A2U8V(""),
		0,
		A2U8VU("\xcf\x83\xe1\x35\x7e\xef\xb8\xbd\xf1\x54\x28\x50\xd6\x6d\x80\x07\xd6\x20\xe4\x05\x0b\x57\x15\xdc\x83\xf4\xa9\x21\xd3\x6c\xe9\xce\x47\xd0\xd1\x3c\x5d\x85\xf2\xb0\xff\x83\x18\xd2\x87\x7e\xec\x2f\x63\xb9\x31\xbd\x47\x41\x7a\x81\xa5\x38\x32\x7a\xf9\x27\xda\x3e"),
	},
	{
		A2U8V("abc"),
		3,
		A2U8VU("\xdd\xaf\x35\xa1\x93\x61\x7a\xba\xcc\x41\x73\x49\xae\x20\x41\x31\x12\xe6\xfa\x4e\x89\xa9\x7e\xa2\x0a\x9e\xee\xe6\x4b\x55\xd3\x9a\x21\x92\x99\x2a\x27\x4f\xc1\xa8\x36\xba\x3c\x23\xa3\xfe\xeb\xbd\x45\x4d\x44\x23\x64\x3c\xe8\x0e\x2a\x9a\xc9\x4f\xa5\x4c\xa4\x9f"),
	},
	{
		A2U8V("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
		56,
		A2U8VU("\x20\x4a\x8f\xc6\xdd\xa8\x2f\x0a\x0c\xed\x7b\xeb\x8e\x08\xa4\x16\x57\xc1\x6e\xf4\x68\xb2\x28\xa8\x27\x9b\xe3\x31\xa7\x03\xc3\x35\x96\xfd\x15\xc1\x3b\x1b\x07\xf9\xaa\x1d\x3b\xea\x57\x78\x9c\xa0\x31\xad\x85\xc7\xa7\x1d\xd7\x03\x54\xec\x63\x12\x38\xca\x34\x45"),
	},
	{
		A2U8V("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
		112,
		A2U8VU("\x8e\x95\x9b\x75\xda\xe3\x13\xda\x8c\xf4\xf7\x28\x14\xfc\x14\x3f\x8f\x77\x79\xc6\xeb\x9f\x7f\xa1\x72\x99\xae\xad\xb6\x88\x90\x18\x50\x1d\x28\x9e\x49\x00\xf7\xe4\x33\x1b\x99\xde\xc4\xb5\x43\x3a\xc7\xd3\x29\xee\xb6\xdd\x26\x54\x5e\x96\xe5\x5b\x87\x4b\xe9\x09"),
	},
	{
		A2U8V("The quick brown fox jumps over the lazy dog"),
		43,
		A2U8VU("\x07\xe5\x47\xd9\x58\x6f\x6a\x73\xf7\x3f\xba\xc0\x43\x5e\xd7\x69\x51\x21\x8f\xb7\xd0\xc8\xd7\x88\xa3\x09\xd7\x85\x43\x6b\xbb\x64\x2e\x93\xa2\x52\xa9\x54\xf2\x39\x12\x54\x7d\x1e\x8a\x3b\x5e\xd6\xe1\xbf\xd7\x09\x78\x21\x23\x3f\xa0\x53\x8f\x3d\xb8\x54\xfe\xe6"),
	},
	{
		A2U8V("The quick brown fox jumps over the lazy dof"),
		43,
		A2U8VU("\xcb\xfc\x84\x86\xe9\xd9\xe1\x8f\x30\x58\x07\x5a\x5f\x9a\x04\xbd\x5f\x1b\x28\x03\x32\x55\xc9\x3f\x17\x12\x31\x02\x3e\xf8\x7e\xd3\x87\x60\xab\xa8\x40\xdf\x8a\x82\xae\x3a\x83\x90\x47\x82\xcc\x2f\xc2\x96\x80\xa0\x43\x73\xb1\xb4\x49\x62\x25\xa9\x67\x50\x74\xd6"),
	},
};

int main(int argc, char * * argv) {
	int r, f = 0;
	size_t i;
	(void)argc;
	(void)argv;
	
	r = digest_assert_equal(sha512_invalid_hashes, 64, ERR_HASH_MISMATCH, &sha512_digest_callbacks);
	if (r == ERR_HASH_MISMATCH) {
		fprintf(stderr, "Test [%zu/%zu]: %s\n", (size_t)1, 1 + (sizeof(sha512_test_values) / sizeof(*sha512_test_values)), "PASS");
		r = TINYCRYPTO_OK;
	} else {
		fprintf(stderr, "Test [%zu/%zu]: %s\n", (size_t)1, 1 + (sizeof(sha512_test_values) / sizeof(*sha512_test_values)), "FAIL");
		f |= 1;
		r = ERR_HASH_UNEXPECTED_SUCCESS;
	}

	for (i = 0; i < (sizeof(sha512_test_values) / sizeof(*sha512_test_values)); i++) {
		r = digest_assert_equal(&(sha512_test_values[i]), 64, TINYCRYPTO_OK, &sha512_digest_callbacks);
		fprintf(stderr, "Test [%zu/%zu]: %s\n", i + 2, 1 + (sizeof(sha512_test_values) / sizeof(*sha512_test_values)), (r == TINYCRYPTO_OK) ? "PASS" : "FAIL");
		if (r != TINYCRYPTO_OK) f |= 1;
	}
	return f == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
