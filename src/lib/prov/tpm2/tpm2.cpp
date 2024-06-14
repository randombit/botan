/*
* TPM 2 interface
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tpm2.h>

#include <botan/internal/fmt.h>
#include <botan/internal/tpm2_util.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tcti.h>
#include <tss2/tss2_tctildr.h>

namespace Botan {

TPM2_Error::TPM2_Error(std::string_view location, uint32_t rc) :
      Exception(fmt("TPM2 Exception in {}: Code {} ({})", location, rc, Tss2_RC_Decode(rc))), m_rc(rc) {}

std::string TPM2_Error::error_message() const {
   return Tss2_RC_Decode(m_rc);
}

struct TPM2_Context::Impl {
      TSS2_TCTI_CONTEXT* m_tcti_ctx;
      ESYS_CONTEXT* m_ctx;
};

std::shared_ptr<TPM2_Context> TPM2_Context::create(std::optional<std::string> tcti_nameconf) {
   const auto tcti_nameconf_ptr = [&]() -> const char* {
      if(tcti_nameconf.has_value()) {
         return tcti_nameconf->c_str();
      } else {
         return nullptr;
      }
   }();
   // We cannot std::make_shared as the constructor is private
   return std::shared_ptr<TPM2_Context>(new TPM2_Context(tcti_nameconf_ptr));
}

TPM2_Context::TPM2_Context(const char* tcti_nameconf) : m_impl(std::make_unique<Impl>()) {
   check_tss2_rc("TCTI Initialization", Tss2_TctiLdr_Initialize(tcti_nameconf, &m_impl->m_tcti_ctx));
   check_tss2_rc("TPM2 Initialization", Esys_Initialize(&m_impl->m_ctx, m_impl->m_tcti_ctx, nullptr /* ABI version */));
}

void* TPM2_Context::get() {
   return m_impl->m_ctx;
}

TPM2_Context::~TPM2_Context() {
   Esys_Finalize(&m_impl->m_ctx);
   Tss2_TctiLdr_Finalize(&m_impl->m_tcti_ctx);
}

}  // namespace Botan
