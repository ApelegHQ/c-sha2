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

include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)
include(CheckCCompilerFlagSSP)
include(CheckCXXCompilerFlagSSP)
include(CMakeDetermineCompilerId)

set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

function(CHECK_COMPILER_FLAG _LANGUAGE _FLAG _VAR)
	if (${LANGUAGE} STREQUAL "C")
		check_c_compiler_flag("${_FLAG}" "${_VAR}")
	elseif (${LANGUAGE} STREQUAL "CXX")
		check_cxx_compiler_flag("${_FLAG}" "${_VAR}")
	endif()
endfunction()

function(CHECK_COMPILER_FLAG_SSP _LANGUAGE _FLAG _VAR)
	if (${LANGUAGE} STREQUAL "C")
		check_c_compiler_flag_ssp("${_FLAG}" "${_VAR}")
	elseif (${LANGUAGE} STREQUAL "CXX")
		check_cxx_compiler_flag_ssp("${_FLAG}" "${_VAR}")
	endif()
endfunction()

function(CHECK_AND_SET_COMPILER_FLAG _LANGUAGE _FLAG)
	check_compiler_flag_ssp("${_LANGUAGE}" "${_FLAG}" "_CHECK_AND_SET_TEMP")
	if (_CHECK_AND_SET_TEMP)
		set(CMAKE_${_LANGUAGE}_FLAGS "${CMAKE_${_LANGUAGE}_FLAGS} ${_FLAG}" PARENT_SCOPE)
	endif()
endfunction()

function(SET_COMPILER_FLAGS LANGUAGE)
	if ("${CMAKE_${LANGUAGE}_COMPILER_ID}" MATCHES "(GNU|Clang|Intel)")
		check_compiler_flag("${LANGUAGE}" "-fPIC" WITH_FPIC)
		# Architecture flags
		check_and_set_compiler_flag("${LANGUAGE}" "-march=native")
		if ("${CMAKE_SYSTEM_NAME}" STREQUAL "Emscripten")
			# For some reason, check_c_source_complies doesn't work
			# check_and_set_compiler_flag("${LANGUAGE}" "-msimd128")
			# Emscripten-specific flags
			set(CMAKE_${LANGUAGE}_FLAGS "${CMAKE_${LANGUAGE}_FLAGS} -flto -s STRICT -s SIDE_MODULE=0")
			if ("${LANGUAGE}" STREQUAL "CXX")
				set(CMAKE_${LANGUAGE}_FLAGS "${CMAKE_${LANGUAGE}_FLAGS} -s DISABLE_EXCEPTION_CATCHING=1")
			endif()
		endif()
		check_and_set_compiler_flag("${LANGUAGE}" "-maes -msse -msse2 -msse3 -msse4.2")

		set(CMAKE_${LANGUAGE}_FLAGS "${CMAKE_${LANGUAGE}_FLAGS} -pedantic -pedantic-errors")
		set(CMAKE_${LANGUAGE}_FLAGS "${CMAKE_${LANGUAGE}_FLAGS} -Wall -Wextra -Wshadow -Wstrict-overflow=5")
		set(CMAKE_${LANGUAGE}_FLAGS "${CMAKE_${LANGUAGE}_FLAGS} -Wunused -Wfloat-equal -Wpointer-arith -Wwrite-strings -Wformat-security")
		set(CMAKE_${LANGUAGE}_FLAGS "${CMAKE_${LANGUAGE}_FLAGS} -Wmissing-format-attribute -Wundef -Werror")

		set(DISABLE_${LANGUAGE}_WARNING_STRICTNESS_FLAGS "-Wno-pedantic -Wno-error" PARENT_SCOPE)

		if ("${LANGUAGE}" STREQUAL "C")
			if (CMAKE_VERSION VERSION_LESS "3.1")
				set(CMAKE_${LANGUAGE}_FLAGS "${CMAKE_${LANGUAGE}_FLAGS} -std=c${CMAKE_C_STANDARD}")
			endif()
			set(CMAKE_${LANGUAGE}_FLAGS "${CMAKE_${LANGUAGE}_FLAGS} -Wmissing-prototypes")
		elseif("${LANGUAGE}" STREQUAL "CXX")
			if (CMAKE_VERSION VERSION_LESS "3.1")
				set(CMAKE_${LANGUAGE}_FLAGS "${CMAKE_${LANGUAGE}_FLAGS} -std=c++${CMAKE_CXX_STANDARD}")
			endif()
		endif()

		if (${CMAKE_${LANGUAGE}_COMPILER_ID} MATCHES "Intel")
			check_compiler_flag("${LANGUAGE}" "-ansi-alias" WITH_STRICT_ALIASING)
			if (WITH_STRICT_ALIASING)
				set(CMAKE_${LANGUAGE}_FLAGS "${CMAKE_${LANGUAGE}_FLAGS} -ansi-alias")
			endif()
		else()
			check_compiler_flag("${LANGUAGE}" "-fstrict-aliasing" WITH_STRICT_ALIASING)
			if (WITH_STRICT_ALIASING)
				#set(CMAKE_${LANGUAGE}_FLAGS "${CMAKE_${LANGUAGE}_FLAGS} -fstrict-aliasing")
			endif()
		endif()

		if ((CMAKE_VERSION VERSION_LESS "2.8.8") AND (CMAKE_POSITION_INDEPENDENT_CODE))
			check_compiler_flag("${LANGUAGE}" "-fPIC" WITH_FPIC)
			if (WITH_FPIC)
				set(CMAKE_${LANGUAGE}_FLAGS "${CMAKE_${LANGUAGE}_FLAGS} -fPIC")
			endif()
		endif()

		check_compiler_flag("${LANGUAGE}" "-Wno-error=unused-command-line-argument" WITH_NO_ERROR_UNUSED_CLI_ARG)
		if (WITH_NO_ERROR_UNUSED_CLI_ARG)
			set(CMAKE_${LANGUAGE}_FLAGS "${CMAKE_${LANGUAGE}_FLAGS} -Wno-error=unused-command-line-argument")
		endif()

		if (UNIX)
			if (REPRODUCIBLE_BUILDS)
				check_compiler_flag_ssp("${LANGUAGE}" "-frandom-seed=\"$<\"" WITH_FRANDOM_SEED)
			endif()

			check_compiler_flag_ssp("${LANGUAGE}" "-fstack-protector-strong" WITH_STACK_PROTECTOR_STRONG)
			check_compiler_flag_ssp("${LANGUAGE}" "-fstack-protector-all" WITH_STACK_PROTECTOR_ALL)
			check_compiler_flag_ssp("${LANGUAGE}" "-fstack-protector" WITH_STACK_PROTECTOR)

			if (REPRODUCIBLE_BUILDS AND WITH_FRANDOM_SEED)
				set(CMAKE_${LANGUAGE}_FLAGS "${CMAKE_${LANGUAGE}_FLAGS} -frandom-seed=\"$<\"")
			endif()

			if (WITH_STACK_PROTECTOR_STRONG)
				set(CMAKE_${LANGUAGE}_FLAGS "${CMAKE_${LANGUAGE}_FLAGS} -fstack-protector-strong")
			elseif(WITH_STACK_PROTECTOR_ALL)
				set(CMAKE_${LANGUAGE}_FLAGS "${CMAKE_${LANGUAGE}_FLAGS} -fstack-protector-all")
			elseif(WITH_STACK_PROTECTOR)
				set(CMAKE_${LANGUAGE}_FLAGS "${CMAKE_${LANGUAGE}_FLAGS} -fstack-protector")
			endif()
		endif()

		check_compiler_flag("${LANGUAGE}" "-fno-sanitize=all" WITH_NO_SANITIZE_ALL)
		if (WITH_NO_SANITIZE_ALL)
			set(${LANGUAGE}_NO_SANITIZE "-fno-sanitize=all" PARENT_SCOPE)
		endif()


		if (CMAKE_BUILD_TYPE)
			 string(TOLOWER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_LOWER)
			 if (CMAKE_BUILD_TYPE_LOWER MATCHES "(release|relwithdebinfo|minsizerel)")
				check_compiler_flag("${LANGUAGE}" "-Wp,-D_FORTIFY_SOURCE=2" WITH_FORTIFY_SOURCE)
				if (WITH_FORTIFY_SOURCE)
					set(CMAKE_${LANGUAGE}_FLAGS "${CMAKE_${LANGUAGE}_FLAGS} -Wp,-D_FORTIFY_SOURCE=2")
				endif()
			endif()

			if (CMAKE_BUILD_TYPE_LOWER MATCHES "(debug|relwithdebinfo)")
				check_compiler_flag("${LANGUAGE}" "-fno-omit-frame-pointer" WITH_NO_OMIT_FRAME_POINTER)

				if (WITH_NO_OMIT_FRAME_POINTER)
					set(CMAKE_${LANGUAGE}_FLAGS "${CMAKE_${LANGUAGE}_FLAGS} -fno-omit-frame-pointer")
				endif()

				if (ASAN)
					set(CMAKE_REQUIRED_FLAGS_OLD "${CMAKE_REQUIRED_FLAGS}")
					set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -fsanitize=address")
					check_compiler_flag("${LANGUAGE}" "-fsanitize=address" WITH_SANITIZE_ADDRESS)
					set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS_OLD}")
					if (WITH_SANITIZE_ADDRESS)
						set(CMAKE_${LANGUAGE}_FLAGS "${CMAKE_${LANGUAGE}_FLAGS} -fsanitize=address")
						set(ASAN_ENABLED TRUE CACHE INTERNAL "USAN enabled")
					else()
						set(ASAN_ENABLED FALSE CACHE INTERNAL "USAN enabled")
					endif()
				endif()

				if (USAN)
					set(CMAKE_REQUIRED_FLAGS_OLD "${CMAKE_REQUIRED_FLAGS}")
					set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -fsanitize=undefined")
					check_compiler_flag("${LANGUAGE}" "-fsanitize=undefined" WITH_SANITIZE_UNDEFINED)
					set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS_OLD}")
					if (WITH_SANITIZE_UNDEFINED)
						set(CMAKE_${LANGUAGE}_FLAGS "${CMAKE_${LANGUAGE}_FLAGS} -fsanitize=undefined")
						set(USAN_ENABLED TRUE CACHE INTERNAL "USAN enabled")
					else()
						set(USAN_ENABLED FALSE CACHE INTERNAL "USAN enabled")
					endif()
				endif()
			endif()
		endif()
	elseif(${CMAKE_${LANGUAGE}_COMPILER_ID} STREQUAL "MSVC")
		if (ARCH_AMD64)
			set(CMAKE_${LANGUAGE}_FLAGS "${CMAKE_${LANGUAGE}_FLAGS} /favor:INTEL64")
		endif()
		set(CMAKE_${LANGUAGE}_FLAGS "${CMAKE_${LANGUAGE}_FLAGS} /Wall /WX /GS /sdl /utf-8")
		set(CMAKE_${LANGUAGE}_FLAGS "${CMAKE_${LANGUAGE}_FLAGS} /D _CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES=1")
		set(CMAKE_${LANGUAGE}_FLAGS "${CMAKE_${LANGUAGE}_FLAGS} /D _CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES_COUNT=1")
		set(CMAKE_${LANGUAGE}_FLAGS "${CMAKE_${LANGUAGE}_FLAGS} /D _CRT_NONSTDC_NO_WARNINGS=1 /D _CRT_SECURE_NO_WARNINGS=1")

		set(DISABLE_${LANGUAGE}_WARNING_STRICTNESS_FLAGS "/w" PARENT_SCOPE)

		if (${LANGUAGE} STREQUAL "C")
			set(CMAKE_${LANGUAGE}_FLAGS "${CMAKE_${LANGUAGE}_FLAGS} /TC /Wall /WX")
		elseif("${LANGUAGE}" STREQUAL "CXX")
			set(CMAKE_${LANGUAGE}_FLAGS "${CMAKE_${LANGUAGE}_FLAGS} /TP /Wall /WX")
			if (CMAKE_VERSION VERSION_LESS "3.1")
				set(CMAKE_${LANGUAGE}_FLAGS "${CMAKE_${LANGUAGE}_FLAGS} /std:c++${CMAKE_CXX_STANDARD}")
			endif()
		endif()

	endif()

	set(CMAKE_${LANGUAGE}_FLAGS "${CMAKE_${LANGUAGE}_FLAGS}" PARENT_SCOPE)

endfunction()

if ((${CMAKE_EXECUTABLE_FORMAT} STREQUAL "ELF") AND (${CMAKE_C_COMPILER_ID} MATCHES "(GNU|Clang|Intel)"))
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -z relro")
	set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -z relro")
	set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -z relro")
endif()

if (${CMAKE_C_COMPILER_ID} MATCHES "(GNU|Clang|Intel)")
	if ("${CMAKE_SYSTEM_NAME}" STREQUAL "Emscripten")
		set(EXPORTED_FUNCTIONS "stackSave, stackRestore")
		if (WITH_SHA256)
			set(EXPORTED_FUNCTIONS "${EXPORTED_FUNCTIONS}, _${TINYCRYPTO_PREFIX}sha256_digest_init, _${TINYCRYPTO_PREFIX}sha256_digest_update, _${TINYCRYPTO_PREFIX}sha256_digest_final, _${TINYCRYPTO_PREFIX}sha256_digest_ctx_sz, _${TINYCRYPTO_PREFIX}sha256_digest_ctx_import, _${TINYCRYPTO_PREFIX}sha256_digest_ctx_export")
			if (WITH_ALLOC)
				set(EXPORTED_FUNCTIONS "${EXPORTED_FUNCTIONS}, _${TINYCRYPTO_PREFIX}sha256_digest_alloc, _${TINYCRYPTO_PREFIX}sha256_digest_cleanup")
			endif()
		endif()
		if (WITH_SHA512)
			set(EXPORTED_FUNCTIONS "${EXPORTED_FUNCTIONS}, _${TINYCRYPTO_PREFIX}sha512_digest_init, _${TINYCRYPTO_PREFIX}sha512_digest_update, _${TINYCRYPTO_PREFIX}sha512_digest_final, _${TINYCRYPTO_PREFIX}sha512_digest_ctx_sz, _${TINYCRYPTO_PREFIX}sha512_digest_ctx_import, _${TINYCRYPTO_PREFIX}sha512_digest_ctx_export")
			if (WITH_ALLOC)
				set(EXPORTED_FUNCTIONS "${EXPORTED_FUNCTIONS}, _${TINYCRYPTO_PREFIX}sha512_digest_alloc, _${TINYCRYPTO_PREFIX}sha512_digest_cleanup")
			endif()
		endif()
		# Maximum optimization set to O2 to prevent renaming symbols
		set(EMSCRIPTEN_LINKER_FLAGS "-Wl,--no-entry  -lc -Wl,-static -static -Q -v -O3 -g2 --memory-init-file 0 -s MALLOC=none -s INITIAL_MEMORY=131072 -s ALLOW_MEMORY_GROWTH=0 -s AUTO_JS_LIBRARIES=0 -s MAYBE_WASM2JS=1 -s WASM=1 -s IGNORE_MISSING_MAIN=1 -s DEFAULT_LIBRARY_FUNCS_TO_INCLUDE='[]' -s EXPORTED_FUNCTIONS='[${EXPORTED_FUNCTIONS}]' --emit-symbol-map")
		set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${EMSCRIPTEN_LINKER_FLAGS}")
		set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${EMSCRIPTEN_LINKER_FLAGS}")
		set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${EMSCRIPTEN_LINKER_FLAGS}")
	else()
		# These flags aren't compatible with Emscripten
		set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -z now -z noexecstack -z noexecheap -z nodlopen -z defs")
		set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -z now -z noexecstack -z noexecheap -z nodlopen -z defs")
		set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -z now -z noexecstack -z noexecheap -z nodlopen -z defs")
	endif()

	if ((CMAKE_VERSION VERSION_LESS "2.8.8") AND (CMAKE_POSITION_INDEPENDENT_CODE))
		set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie")
		set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -pic")
		set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -pic")
	endif()
endif()

SET_COMPILER_FLAGS("C")
SET_COMPILER_FLAGS("CXX")

message("-- CMAKE_SYSTEM_NAME: ${CMAKE_SYSTEM_NAME}")
message("-- CMAKE_C_FLAGS: ${CMAKE_C_FLAGS}")
message("-- CMAKE_CXX_FLAGS: ${CMAKE_CXX_FLAGS}")
message("-- CMAKE_EXE_LINKER_FLAGS: ${CMAKE_EXE_LINKER_FLAGS}")
message("-- CMAKE_SHARED_LINKER_FLAGS: ${CMAKE_SHARED_LINKER_FLAGS}")
message("-- CMAKE_MODULE_LINKER_FLAGS: ${CMAKE_MODULE_LINKER_FLAGS}")
