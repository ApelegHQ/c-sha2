/******************************************************************************
 * Copyright © 2024 Exact Realty Limited                                      *
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

#ifndef __EMSCRIPTEN__
#error "This file is meant only for Emscripten"
#endif

#include <string.h>
#include "crypto_internal.h"

void * HIDDEN_SYMBOL memcpy(void * const dest, void const * const src, size_t const n) {
    for (size_t i = 0; i < n; i++) {
        ((char *) dest)[i] = ((char const *) src)[i];
    }
    return dest;
}
