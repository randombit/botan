/*
* TPM 2 interface
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TPM2_H_
#define BOTAN_TPM2_H_

#include <botan/exceptn.h>

#include <memory>
#include <optional>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tctildr.h>

namespace Botan {
class BOTAN_PUBLIC_API(3, 6) TPM2_Error final : public Exception {
   public:
      TPM2_Error(std::string_view location, TSS2_RC rc);

      ErrorType error_type() const noexcept override { return ErrorType::TPMError; }

      TSS2_RC code() const { return m_rc; }

      std::string error_message() const;

   private:
      TSS2_RC m_rc;
};

inline void check_tss2_rc(std::string_view location, TSS2_RC rc) {
   if(rc != TSS2_RC_SUCCESS) {
      throw TPM2_Error(location, rc);
   }
}

class BOTAN_PUBLIC_API(3, 6) TPM2_Context final {
   public:
      /**
       * @param tcti_nameconf  if set this is passed to Tss2_TctiLdr_Initialize verbatim
       *                       otherwise a nullptr is passed.
       */
      static std::shared_ptr<TPM2_Context> create(std::optional<std::string> tcti_nameconf = {});

      TPM2_Context(const TPM2_Context&) = delete;
      TPM2_Context(TPM2_Context&& ctx) noexcept;
      ~TPM2_Context();

      TPM2_Context& operator=(const TPM2_Context&) = delete;
      TPM2_Context& operator=(TPM2_Context&& ctx) noexcept;

      ESYS_CONTEXT* get() { return m_ctx; }

   private:
      TPM2_Context(const char* tcti_nameconf);

   private:
      TSS2_TCTI_CONTEXT* m_tcti_ctx;
      ESYS_CONTEXT* m_ctx;
};

}  // namespace Botan

#endif
