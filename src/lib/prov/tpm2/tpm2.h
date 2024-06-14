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

#include <optional>

namespace Botan {
class BOTAN_PUBLIC_API(3, 6) TPM2_Error final : public Exception {
   public:
      TPM2_Error(std::string_view location, uint32_t rc);

      ErrorType error_type() const noexcept override { return ErrorType::TPMError; }

      uint32_t code() const { return m_rc; }

      int error_code() const noexcept override {
         // RC is uint32 but the maximum value is within int32 range as per tss2_common.h
         return static_cast<int>(m_rc);
      }

      std::string error_message() const;

   private:
      uint32_t m_rc;
};

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

      // Return an ESYS_CONTEXT* for use in other TPM2 functions.
      void* get();

   private:
      TPM2_Context(const char* tcti_nameconf);

   private:
      class Impl;  // PImpl to avoid TPM2-TSS includes in this header
      std::unique_ptr<Impl> m_impl;
};

}  // namespace Botan

#endif
