/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MONTY_EXP_AVX512_H_
#define BOTAN_MONTY_EXP_AVX512_H_

#include <botan/internal/monty_exp.h>
#include <memory>

namespace Botan {

/**
* Montgomery exponentiation using AVX-512 IFMA
*
* Returns nullptr if the CPU or the size of the modulus is not supported
*/
std::unique_ptr<Montgomery_Exponentiation_State> make_monty_exp_avx512(const Montgomery_Int& g,
                                                                       size_t window_bits,
                                                                       bool const_time);

}  // namespace Botan

#endif
