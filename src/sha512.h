#pragma once
#ifndef SHA512_H
#define SHA512_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
extern void sha512_compress(uint64_t state[static 8], const unsigned char block[static 128]);
#ifdef __cplusplus
}
#endif
#endif
