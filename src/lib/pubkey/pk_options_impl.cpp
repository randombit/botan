/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pk_options_impl.h>

#include <botan/exceptn.h>
#include <botan/pk_options.h>
#include <botan/internal/fmt.h>

namespace Botan::PK_Options_Checks {

void validate_for_hash_based_signature(const PK_Signature_Options& options,
                                       std::string_view algo_name,
                                       std::string_view hash_fn) {
   if(!options.hash_function().empty()) {
      if(hash_fn.empty()) {
         throw Invalid_Argument(fmt("This {} key does not support explicit hash function choice", algo_name));
      } else if(options.hash_function() != hash_fn) {
         throw Invalid_Argument(
            fmt("This {} key can only be used with {}, not {}", algo_name, hash_fn, options.hash_function()));
      }
   }

   if(options.using_padding()) {
      throw Invalid_Argument(fmt("{} does not support padding modes", algo_name));
   }

   if(options.using_prehash()) {
      throw Invalid_Argument(fmt("{} does not support prehashing"));
   }
}

}  // namespace Botan::PK_Options_Checks
