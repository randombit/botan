/*
* TPM 2.0 Hash Function Wrappers
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH, financed by LANCOM Systems GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TPM2_HASH_H_
#define BOTAN_TPM2_HASH_H_

#include <botan/hash.h>
#include <botan/tpm2_context.h>
#include <botan/tpm2_object.h>
#include <botan/tpm2_session.h>

#include <botan/internal/tpm2_util.h>

#include <tss2/tss2_tpm2_types.h>

namespace Botan::TPM2 {

/**
 * Exposes the hashing capability of a TPM 2.0 device as a Botan::HashFunction.
 * Typically this is used to obtain a TPMT_TK_HASHCHECK ticket after the hash
 * operation has been completed. Otherwise, the HashFunction behaves like any
 * other Botan::HashFunction.
 */
class BOTAN_TEST_API HashFunction final : public Botan::HashFunction {
   public:
      HashFunction(std::shared_ptr<Context> ctx,
                   std::string_view algorithm,
                   TPMI_RH_HIERARCHY hierarchy = ESYS_TR_RH_NULL,
                   SessionBundle sessions = {});

      std::string name() const override;
      size_t output_length() const override;
      void clear() override;

      /// @throws Not_Implemented as copying state is not supported within the TPM
      std::unique_ptr<Botan::HashFunction> copy_state() const override;
      std::unique_ptr<Botan::HashFunction> new_object() const override;

      /// @return The hash algorithm identifier as TSS2's TPMI_ALG_HASH
      TPMI_ALG_HASH type() const { return m_hash_type; }

      /**
       * Finalize the hash operation and return the digest and the ticket
       * as TSS2 structures.
       *
       * @return A pair of TPM2B_DIGEST and TPMT_TK_HASHCHECK
       */
      std::pair<unique_esys_ptr<TPM2B_DIGEST>, unique_esys_ptr<TPMT_TK_HASHCHECK>> final_with_ticket();

   private:
      void lazy_setup();
      void add_data(std::span<const uint8_t> input) override;
      void final_result(std::span<uint8_t> output) override;

   private:
      TPMI_ALG_HASH m_hash_type;
      TPMI_RH_HIERARCHY m_hierarchy;
      Object m_handle;
      SessionBundle m_sessions;
};

}  // namespace Botan::TPM2

#endif
