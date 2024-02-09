/******************************************************************************
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

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "tinycrypto.h"
#include "test_digest.h"

int digest_assert_equal(struct test_digest_params const * params, size_t const out_len, int expect, struct digest_callbacks const * fn) {
	int r;
	void * digest_context_p;
	void * buffer;
	size_t i;
	
	union digest_data_pointer data_p;

	r = fn->digest_init(&digest_context_p);

	if (r == TINYCRYPTO_OK) {
		r = fn->digest_update(digest_context_p, params->in, params->in_len / 2);
		if (r == TINYCRYPTO_OK) {
			r = fn->digest_update(digest_context_p, params->in + params->in_len / 2,
			                      params->in_len - (params->in_len / 2));
		}
		if (r == TINYCRYPTO_OK) {
			if ((buffer = malloc(out_len)) != NULL) {
				r = fn->digest_final(digest_context_p, buffer);
				if (r == TINYCRYPTO_OK) {
					data_p.u8 = buffer;
					r = memcmp(data_p.u32, params->out.u32, out_len);
					if (r != 0) {
						if (expect != ERR_HASH_MISMATCH) {
							fprintf(stderr, "Hashes differ. Expected ");
							for (i = 0; i < out_len / 4; i++) {
								fprintf(stderr, "%08x", params->out.u32[i]);
							}
							fprintf(stderr, ", got ");
							for (i = 0; i < out_len / 4; i++) {
								fprintf(stderr, "%08x", data_p.u32[i]);
							}
							fprintf(stderr, ".\n");
						}
						r = ERR_HASH_MISMATCH;
					} else {
						r = TINYCRYPTO_OK;
						if (expect == ERR_HASH_MISMATCH) {
							fprintf(stderr, "Hashes match. Expected mismatch.\n");
						}
					}
				}
				free(buffer);
			} else {
				r = ERR_HASH_NOMEM;
			}
		}
		fn->digest_cleanup(digest_context_p);
	}

	return r;
}

