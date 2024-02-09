#pragma once
#ifndef SHA256_H
#define SHA256_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
extern void sha256_compress(uint32_t state[static 8], const unsigned char block[static 64]);
#ifdef __cplusplus
}
#endif
#endif
