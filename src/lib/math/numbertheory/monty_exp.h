/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MONTY_EXP_H_
#define BOTAN_MONTY_EXP_H_

#include <memory>

namespace Botan {

class BigInt;
class Modular_Reducer;

class Montgomery_Exponentation_State;

/*
* Precompute for calculating values g^x mod p
*/
std::shared_ptr<const Montgomery_Exponentation_State>
monty_precompute(const BigInt& g,
                 const BigInt& p,
                 const Modular_Reducer& mod_p,
                 size_t window_bits);

/*
* Return g^x mod p
*/
BigInt monty_execute(const Montgomery_Exponentation_State& precomputed_state,
                     const BigInt& k);

}

#endif
