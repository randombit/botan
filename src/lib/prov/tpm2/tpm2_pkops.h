/*
* TPM 2.0 Public Key Operations
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH, financed by LANCOM Systems GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TPM2_PKOPS_H_
#define BOTAN_TPM2_PKOPS_H_

#include <botan/pk_ops.h>

#include <botan/hash.h>
#include <botan/internal/tpm2_util.h>

namespace Botan::TPM2 {

struct SignatureAlgorithmSelection {
      TPMT_SIG_SCHEME signature_scheme;
      std::string hash_name;
      std::optional<std::string> padding;
};

template <typename PKOpT>
class Signature_Operation_Base : public PKOpT {
   public:
      Signature_Operation_Base(const Object& object,
                               const SessionBundle& sessions,
                               const SignatureAlgorithmSelection& algorithms,
                               std::unique_ptr<Botan::HashFunction> hash) :
            m_key_handle(object),
            m_sessions(sessions),
            m_scheme(algorithms.signature_scheme),
            m_hash(std::move(hash)),
            m_padding(algorithms.padding) {
         BOTAN_ASSERT_NONNULL(m_hash);
      }

   public:
      void update(std::span<const uint8_t> msg) override { m_hash->update(msg); }

      std::string hash_function() const override { return m_hash->name(); }

   protected:
      Botan::HashFunction* hash() { return m_hash.get(); }

      const Object& key_handle() const { return m_key_handle; }

      const SessionBundle& sessions() const { return m_sessions; }

      const TPMT_SIG_SCHEME& scheme() const { return m_scheme; }

      std::optional<std::string> padding() const { return m_padding; }

   private:
      const Object& m_key_handle;
      const SessionBundle& m_sessions;
      TPMT_SIG_SCHEME m_scheme;
      std::unique_ptr<Botan::HashFunction> m_hash;
      std::optional<std::string> m_padding;
};

/**
 * If the key is restricted, this will transparently use the TPM to hash the
 * data to obtain a validation ticket.
 *
 * TPM Library, Part 1: Architecture", Section 11.4.6.3 (4)
 *    This ticket is used to indicate that a digest of external data is safe to
 *    sign using a restricted signing key. A restricted signing key may only
 *    sign a digest that was produced by the TPM. [...] This prevents forgeries
 *    of attestation data.
 */
class Signature_Operation : public Signature_Operation_Base<PK_Ops::Signature> {
   public:
      Signature_Operation(const Object& object,
                          const SessionBundle& sessions,
                          const SignatureAlgorithmSelection& algorithms);

      std::vector<uint8_t> sign(Botan::RandomNumberGenerator& rng) override;

   protected:
      virtual std::vector<uint8_t> marshal_signature(const TPMT_SIGNATURE& signature) const = 0;
};

/**
 * Signature verification on the TPM. This does not require a validation ticket,
 * therefore the hash is always calculated in software.
 */
class Verification_Operation : public Signature_Operation_Base<PK_Ops::Verification> {
   public:
      Verification_Operation(const Object& object,
                             const SessionBundle& sessions,
                             const SignatureAlgorithmSelection& algorithms);

      bool is_valid_signature(std::span<const uint8_t> sig_data) override;

   protected:
      virtual TPMT_SIGNATURE unmarshal_signature(std::span<const uint8_t> sig_data) const = 0;
};

}  // namespace Botan::TPM2

#endif
