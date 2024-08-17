/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PK_OPTIONS_IMPL_H_
#define BOTAN_PK_OPTIONS_IMPL_H_

#include <string_view>

namespace Botan {

class PK_Signature_Options;

namespace PK_Options_Checks {

void validate_for_hash_based_signature(const PK_Signature_Options& options,
                                       std::string_view algo_name,
                                       std::string_view hash_fn = "");

};

}  // namespace Botan

#endif
