/*
* (C) 2018,2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MONTY_EXP_H_
#define BOTAN_MONTY_EXP_H_

#include <botan/internal/monty.h>
#include <memory>

namespace Botan {

class BigInt;
class Modular_Reducer;
class Montgomery_Exponentation_State;

/*
* Precompute for calculating values g^x mod p
*/
std::shared_ptr<const Montgomery_Exponentation_State> monty_precompute(
   const std::shared_ptr<const Montgomery_Params>& params_p,
   const BigInt& g,
   size_t window_bits,
   bool const_time = true);

/*
* Precompute for calculating values g^x mod p
*/
std::shared_ptr<const Montgomery_Exponentation_State> monty_precompute(const Montgomery_Int& g,
                                                                       size_t window_bits,
                                                                       bool const_time = true);

/*
* Return g^k mod p
*/
Montgomery_Int monty_execute(const Montgomery_Exponentation_State& precomputed_state,
                             const BigInt& k,
                             size_t max_k_bits);

/*
* Return g^k mod p taking variable time depending on k
* @warning only use this if k is public
*/
Montgomery_Int monty_execute_vartime(const Montgomery_Exponentation_State& precomputed_state, const BigInt& k);

inline Montgomery_Int monty_exp(const std::shared_ptr<const Montgomery_Params>& params_p,
                                const BigInt& g,
                                const BigInt& k,
                                size_t max_k_bits) {
   auto precomputed = monty_precompute(params_p, g, 4, true);
   return monty_execute(*precomputed, k, max_k_bits);
}

inline Montgomery_Int monty_exp_vartime(const std::shared_ptr<const Montgomery_Params>& params_p,
                                        const BigInt& g,
                                        const BigInt& k) {
   auto precomputed = monty_precompute(params_p, g, 4, false);
   return monty_execute_vartime(*precomputed, k);
}

/**
* Return (x^z1 * y^z2) % p
*/
Montgomery_Int monty_multi_exp(const std::shared_ptr<const Montgomery_Params>& params_p,
                               const BigInt& x,
                               const BigInt& z1,
                               const BigInt& y,
                               const BigInt& z2);

}  // namespace Botan

#endif
