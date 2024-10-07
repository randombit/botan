/*
* TPM 2 error handling
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH, financed by LANCOM Systems GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TPM2_ERROR_H_
#define BOTAN_TPM2_ERROR_H_

#include <botan/exceptn.h>

/// Forward declaration of TSS2 type for convenience
using TSS2_RC = uint32_t;

namespace Botan::TPM2 {

TSS2_RC get_raw_rc(TSS2_RC rc);

class BOTAN_PUBLIC_API(3, 6) Error final : public Exception {
   public:
      Error(std::string_view location, TSS2_RC rc);

      ErrorType error_type() const noexcept override { return ErrorType::TPMError; }

      TSS2_RC code() const { return m_rc; }

      int error_code() const noexcept override {
         // RC is uint32 but the maximum value is within int32 range as per tss2_common.h
         return static_cast<int>(m_rc);
      }

      std::string error_message() const;

   private:
      TSS2_RC m_rc;
};

}  // namespace Botan::TPM2

#endif
