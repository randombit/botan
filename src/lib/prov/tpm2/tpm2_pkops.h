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
#include <botan/internal/emsa.h>
#include <botan/internal/tpm2_util.h>

namespace Botan::TPM2 {

struct SignatureAlgorithmSelection {
      TPMT_SIG_SCHEME signature_scheme;
      std::string hash_name;
      std::unique_ptr<EMSA> emsa;
};

template <typename PKOpT>
class Signature_Operation_Base : public PKOpT {
   public:
      Signature_Operation_Base(
         const Object& object,
         const SessionBundle& sessions,
         std::pair<std::unique_ptr<Botan::HashFunction>, SignatureAlgorithmSelection> algorithms) :
            m_key_handle(object),
            m_sessions(sessions),
            m_hash(std::move(algorithms.first)),
            m_scheme(algorithms.second.signature_scheme),
            m_emsa(std::move(algorithms.second.emsa)) {
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

      EMSA* emsa() const {
         BOTAN_STATE_CHECK(m_emsa);
         return m_emsa.get();
      }

   private:
      const Object& m_key_handle;
      const SessionBundle& m_sessions;
      std::unique_ptr<Botan::HashFunction> m_hash;
      TPMT_SIG_SCHEME m_scheme;

      // This EMSA object actually isn't required, we just need it to
      // conveniently parse the EMSA the user selected.
      //
      // TODO: This is a hack, and we should clean this up.
      std::unique_ptr<EMSA> m_emsa;
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
      Signature_Operation(const Object& object, const SessionBundle& sessions, SignatureAlgorithmSelection algorithms);

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
                             SignatureAlgorithmSelection algorithms);

      bool is_valid_signature(std::span<const uint8_t> sig_data) override;

   protected:
      virtual TPMT_SIGNATURE unmarshal_signature(std::span<const uint8_t> sig_data) const = 0;
};

}  // namespace Botan::TPM2

#endif
