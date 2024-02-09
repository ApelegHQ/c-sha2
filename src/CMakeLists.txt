##############################################################################
# Copyright © 2024 Exact Realty Limited                                      #
# Copyright © 2018 Aalto University                                          #
# Secure Systems Group, https://ssg.aalto.fi                                 #
#                                                                            #
# Author: Ricardo Iván Vieitez Parra                                         #
#                                                                            #
# Licensed under the Apache License, Version 2.0 (the "License");            #
# you may not use this file except in compliance with the License.           #
# You may obtain a copy of the License at                                    #
#                                                                            #
#     http://www.apache.org/licenses/LICENSE-2.0                             #
#                                                                            #
# Unless required by applicable law or agreed to in writing, software        #
# distributed under the License is distributed on an "AS IS" BASIS,          #
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   #
# See the License for the specific language governing permissions and        #
# limitations under the License.                                             #
##############################################################################

set(CRYPTO_SHA2_SOURCES sha256.c sha512.c)

set(TINYCRYPTO_REQUIRED_LIBRARIES ${TINYCRYPTO_REQUIRED_LIBRARIES} m)

add_library(tinycrypto ${CRYPTO_SHA2_SOURCES} sha2.c)

if ("${CMAKE_SYSTEM_NAME}" STREQUAL "Emscripten")
    add_executable(sha2 sha2-wasm.c)
    target_link_libraries(sha2 tinycrypto ${TINYCRYPTO_REQUIRED_LIBRARIES})

    add_custom_command(
        TARGET sha2 POST_BUILD
        COMMAND wasm2js -O4 --emscripten --deterministic --vacuum --post-emscripten --symbols-file "$<TARGET_FILE:sha2>.wasm2js.symbols" -o "$<TARGET_FILE:sha2>" "$<TARGET_FILE_DIR:sha2>/$<TARGET_FILE_PREFIX:sha2>$<TARGET_FILE_BASE_NAME:sha2>.wasm"
        COMMAND node -e "const {readFileSync,writeFileSync}=require('node:fs');eval(readFileSync(process.argv[1]).toString());writeFileSync(process.argv[2], '/** @const */\\r\\nvar $exportTable='+require('node:util').inspect(Object.fromEntries(Object.entries(instantiate({})).map(([a,b]) => [typeof b === 'function' ? b.name.replace(/^${TINYCRYPTO_PREFIX}/, '_SYM_TINYCRYPTO_') : typeof b === 'object' && b.buffer ? 'memory': void a, a]).filter(([a]) => !!a)))+';\\r\\n');" "$<TARGET_FILE:sha2>" "$<TARGET_FILE:sha2>.table.js"
        COMMENT "Transpiling to asm.js using wasm2js"
        VERBATIM
    )

    add_custom_command(
        OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/index.mjs" "${CMAKE_CURRENT_BINARY_DIR}/sha2.mjs"
        COMMAND ${CMAKE_COMMAND} -E cat "${CMAKE_CURRENT_SOURCE_DIR}/js/preamble.js.in" "${CMAKE_CURRENT_SOURCE_DIR}/js/esm-output-preamble.mjs.in" "$<TARGET_FILE:sha2>" "$<TARGET_FILE:sha2>.table.js" "${CMAKE_CURRENT_SOURCE_DIR}/js/sha2-wasm-wrapper.js.in" "${CMAKE_CURRENT_SOURCE_DIR}/js/esm-output-epilogue.mjs.in" > "${CMAKE_CURRENT_BINARY_DIR}/sha2.mjs"
        COMMAND google-closure-compiler -O ADVANCED --jscomp_off globalThis --jscomp_off checkTypes --strict_mode_input --assume_function_wrapper --isolation_mode NONE --js_output_file "${CMAKE_CURRENT_BINARY_DIR}/index.mjs" "${CMAKE_CURRENT_BINARY_DIR}/sha2.mjs"
        COMMAND perl -pi -e "s/self\\s*\\[\\s*(['\"])------\\1\\s*\\]\\s*=/export default /" "${CMAKE_CURRENT_BINARY_DIR}/index.mjs"
        DEPENDS sha2 "js/preamble.js.in" "js/sha2-wasm-wrapper.js.in" "js/esm-output-preamble.mjs.in" "js/esm-output-epilogue.mjs.in"
        COMMENT "ESM target"
        VERBATIM
    )

    add_custom_command(
        OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/index.cjs" "${CMAKE_CURRENT_BINARY_DIR}/sha2.cjs"
        COMMAND ${CMAKE_COMMAND} -E cat "${CMAKE_CURRENT_SOURCE_DIR}/js/preamble.js.in" "${CMAKE_CURRENT_SOURCE_DIR}/js/umd-output-preamble.cjs.in" "$<TARGET_FILE:sha2>" "$<TARGET_FILE:sha2>.table.js" "${CMAKE_CURRENT_SOURCE_DIR}/js/sha2-wasm-wrapper.js.in" "${CMAKE_CURRENT_SOURCE_DIR}/js/umd-output-epilogue.cjs.in" > "${CMAKE_CURRENT_BINARY_DIR}/sha2.cjs"
        COMMAND google-closure-compiler -O ADVANCED --jscomp_off checkTypes --js_output_file "${CMAKE_CURRENT_BINARY_DIR}/index.cjs" "${CMAKE_CURRENT_BINARY_DIR}/sha2.cjs"
        DEPENDS sha2 "js/preamble.js.in" "js/sha2-wasm-wrapper.js.in" "js/umd-output-preamble.cjs.in" "js/umd-output-epilogue.cjs.in"
        COMMENT "UMD target"
        VERBATIM
    )

    add_custom_target(js-targets ALL DEPENDS index.cjs index.mjs)

    install(
        FILES
            ${CMAKE_SOURCE_DIR}/LICENSE-2.0.txt
            js/package.json
            js/index.d.ts
            js/index.d.cts
            js/LICENSE
            ${CMAKE_SOURCE_DIR}/README.md
            ${CMAKE_CURRENT_BINARY_DIR}/index.cjs
            ${CMAKE_CURRENT_BINARY_DIR}/index.mjs
        DESTINATION pkg
    )
endif()

IF (BUILD_TESTING)
IF (WITH_SHA256)
add_executable(sha256-test sha256-test.c ${CRYPTO_SHA2_SOURCES})
add_test(NAME sha256_compress_test COMMAND sha256-test)

add_executable(test_digest_sha256 test_digest.c test_digest_sha256.c)
target_link_libraries(test_digest_sha256 tinycrypto ${TINYCRYPTO_REQUIRED_LIBRARIES})
add_test(NAME test_digest_sha256 COMMAND test_digest_sha256)
ENDIF (WITH_SHA256)

IF (WITH_SHA512)
add_executable(sha512-test sha512-test.c ${CRYPTO_SHA2_SOURCES})
add_test(NAME sha512_compress_test COMMAND sha512-test)

add_executable(test_digest_sha512 test_digest.c test_digest_sha512.c)
target_link_libraries(test_digest_sha512 tinycrypto ${TINYCRYPTO_REQUIRED_LIBRARIES})
add_test(NAME test_digest_sha512 COMMAND test_digest_sha512)
ENDIF (WITH_SHA512)
ENDIF (BUILD_TESTING)
