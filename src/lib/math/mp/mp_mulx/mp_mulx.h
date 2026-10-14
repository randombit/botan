/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MP_MULX_H_
#define BOTAN_MP_MULX_H_

#include <botan/types.h>

namespace Botan {

/*
* Multiplication and squaring using MULX and ADX, see gen_mp_mulx.py
*
* The output z must not overlap x or y
*/
void bigint_mulx_mul4(word z[8], const word x[4], const word y[4]);
void bigint_mulx_mul6(word z[12], const word x[6], const word y[6]);
void bigint_mulx_mul8(word z[16], const word x[8], const word y[8]);
void bigint_mulx_mul9(word z[18], const word x[9], const word y[9]);

void bigint_mulx_sqr4(word z[8], const word x[4]);
void bigint_mulx_sqr6(word z[12], const word x[6]);
void bigint_mulx_sqr8(word z[16], const word x[8]);
void bigint_mulx_sqr9(word z[18], const word x[9]);

}  // namespace Botan

#endif
