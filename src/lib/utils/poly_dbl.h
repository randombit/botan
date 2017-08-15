/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_POLY_DBL_H__
#define BOTAN_POLY_DBL_H__

#include <botan/types.h>

namespace Botan {

void BOTAN_DLL poly_double_n(uint8_t b[], size_t n);

void poly_double_8(uint8_t b[8]);
void poly_double_16(uint8_t b[16]);
void poly_double_24(uint8_t b[24]);
void poly_double_32(uint8_t b[32]);
void poly_double_64(uint8_t b[64]);


}

#endif
