/*
* TPM 2 interface
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tpm2.h>

#include <botan/internal/fmt.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

namespace Botan {

TPM2_Error::TPM2_Error(std::string_view location, TSS2_RC rc) :
      Exception(fmt("TPM2 Exception in {}: Code {} ({})", location, rc, Tss2_RC_Decode(rc))), m_rc(rc) {}

std::string TPM2_Error::error_message() const {
   return Tss2_RC_Decode(m_rc);
}

std::shared_ptr<TPM2_Context> TPM2_Context::create(std::optional<std::string> tcti_nameconf) {
   const auto tcti_nameconf_ptr = [&]() -> const char* {
      if(tcti_nameconf.has_value()) {
         return tcti_nameconf->c_str();
      } else {
         return nullptr;
      }
   }();
   return std::shared_ptr<TPM2_Context>(new TPM2_Context(tcti_nameconf_ptr));
}

TPM2_Context::TPM2_Context(const char* tcti_nameconf) {
   check_tss2_rc("TCTI Initialization", Tss2_TctiLdr_Initialize(tcti_nameconf, &m_tcti_ctx));
   check_tss2_rc("TPM2 Initialization", Esys_Initialize(&m_ctx, m_tcti_ctx, nullptr /* ABI version */));
}

TPM2_Context::TPM2_Context(TPM2_Context&& ctx) noexcept : m_ctx(ctx.m_ctx) {
   ctx.m_ctx = nullptr;
}

TPM2_Context& TPM2_Context::operator=(TPM2_Context&& ctx) noexcept {
   if(this != &ctx) {
      m_ctx = ctx.m_ctx;
      ctx.m_ctx = nullptr;
   }

   return *this;
}

TPM2_Context::~TPM2_Context() {
   Esys_Finalize(&m_ctx);
   Tss2_TctiLdr_Finalize(&m_tcti_ctx);
}

}  // namespace Botan
