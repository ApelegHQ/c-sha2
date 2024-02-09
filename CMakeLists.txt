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

cmake_minimum_required(VERSION 2.8...4.0)

project(App1 C CXX)

option(ASAN "Enable AddressSanitizer" OFF)
option(USAN "Enable Undefined Sanitizer" OFF)

option(TINYCRYPTO_DEBUG_SHA2_DIGEST "Enable debugging output from SHA-2 digest functions" OFF)
option(TINYCRYPTO_DEBUG_AES "Enable debugging output from AES encryption functions" OFF)

set(TINYCRYPTO_PREFIX "TINYCRYPTO_" CACHE STRING "Name prefix (default TINYCRYPTO_)")

option(WITH_ALLOC "Enable dynamic memory allocation" OFF)
option(WITH_SHA256 "Enable building SHA256" ON)
option(WITH_SHA512 "Enable building SHA512" OFF)

option(REPRODUCIBLE_BUILDS "Build deterministic binaries" ON)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)

enable_testing()

include(CheckIncludeFiles)
include(CheckSymbolExists)
include(CheckTypeSize)
include(FindPackageHandleStandardArgs)

find_package(Threads)

if(CMAKE_USE_PTHREADS_INIT)
	set(WITH_THREAD_PTHREADS 1)
endif()
if(CMAKE_HP_PTHREADS_INIT)
	set(WITH_THREAD_HP_PTHREADS 1)
endif()
if(CMAKE_USE_SPROC_INIT)
	set(WITH_THREAD_SPROC 1)
endif()
if(CMAKE_USE_WIN32_THREADS_INIT)
	set(WITH_THREAD_WIN32 1)
endif()

if ("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "x86_64")
	set(ARCH_AMD64 TRUE)
	set(SYSTEM_BITS "64")
elseif("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "i.386")
	set(ARCH_IA32 TRUE)
	set(SYSTEM_BITS "32")
endif()

include(DefineCompilerFlags)

check_include_files("malloc.h" HAVE_MALLOC_H)
check_include_files("unistd.h" HAVE_UNISTD_H)
check_include_files("stdint.h" HAVE_STDINT_H)
check_include_files("emmintrin.h" HAVE_EMMINTRIN_H)
check_include_files("immintrin.h" HAVE_IMMINTRIN_H)
check_include_files("nmmintrin.h" HAVE_NMMINTRIN_H)
check_include_files("tmmintrin.h" HAVE_TMMINTRIN_H)
check_include_files("wmmintrin.h" HAVE_WMMINTRIN_H)
check_include_files("xmmintrin.h" HAVE_XMMINTRIN_H)

set(CMAKE_REQUIRED_FLAGS_ORIG "${CMAKE_REQUIRED_FLAGS}")
set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} ${DISABLE_C_WARNING_STRICTNESS_FLAGS}")
check_symbol_exists(memalign malloc.h HAVE_MEMALIGN__MALLOC_H)
check_symbol_exists(memalign stdlib.h HAVE_MEMALIGN__STDLIB_H)
check_symbol_exists(_aligned_malloc malloc.h HAVE__ALIGNED_MALLOC)
check_symbol_exists(aligned_alloc stdlib.h HAVE_ALIGNED_ALLOC)
check_symbol_exists(posix_memalign stdlib.h HAVE_POSIX_MEMALIGN)
check_symbol_exists(_mm_malloc xmmintrin.h HAVE__MM_MALLOC)
check_symbol_exists(_mm_free xmmintrin.h HAVE__MM_FREE)
set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS_ORIG}")

check_type_size("void *" SIZEOF_VOID_P BUILTIN_TYPES_ONLY)
check_type_size("int" SIZEOF_INT BUILTIN_TYPES_ONLY)
check_type_size("uint32_t" SIZEOF_UINT32_T)

configure_file("${PROJECT_SOURCE_DIR}/config.h.in" "${PROJECT_BINARY_DIR}/config.h" @ONLY)
include_directories(${PROJECT_BINARY_DIR})

add_definitions(-DHAVE_CONFIG_H)

add_subdirectory(src)
