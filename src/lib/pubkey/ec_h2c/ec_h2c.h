/*
* (C) 2019,2020,2021 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ECC_HASH_TO_CURVE_H_
#define BOTAN_ECC_HASH_TO_CURVE_H_

#include <botan/ec_point.h>
#include <botan/types.h>
#include <span>
#include <string_view>

namespace Botan {

class EC_Group;

/**
* Hash an input onto an elliptic curve point using the
* methods from RFC 9380
*
* This method requires that the ECC group have (a*b) != 0
* which excludes certain groups including secp256k1
*/
EC_Point hash_to_curve_sswu(const EC_Group& group,
                            std::string_view hash_fn,
                            std::span<const uint8_t> input,
                            std::span<const uint8_t> domain_sep,
                            bool random_oracle);

}  // namespace Botan

#endif
