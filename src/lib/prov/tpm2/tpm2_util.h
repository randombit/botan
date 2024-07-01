/*
* TPM 2 internal utilities
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TPM2_UTIL_H_
#define BOTAN_TPM2_UTIL_H_

#include <botan/tpm2.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>

namespace Botan {

inline void check_tss2_rc(std::string_view location, TSS2_RC rc) {
   if(rc != TSS2_RC_SUCCESS) {
      throw TPM2_Error(location, rc);
   }
}

inline ESYS_CONTEXT* inner(const std::shared_ptr<TPM2_Context>& ctx) {
   BOTAN_ASSERT_NOMSG(ctx != nullptr);
   auto inner = ctx->inner_context_object();
   BOTAN_ASSERT_NOMSG(inner != nullptr);
   return static_cast<ESYS_CONTEXT*>(inner);
}

}  // namespace Botan

#endif
