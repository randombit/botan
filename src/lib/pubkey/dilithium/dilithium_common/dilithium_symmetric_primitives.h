/*
* Symmetric primitives for dilithium
*
* (C) 2022-2023 Jack Lloyd
* (C) 2022-2023 Michael Boric, René Meusel - Rohde & Schwarz Cybersecurity
* (C) 2022      Manuel Glaser - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_DILITHIUM_ASYM_PRIMITIVES_H_
#define BOTAN_DILITHIUM_ASYM_PRIMITIVES_H_

#include <botan/dilithium.h>

#include <botan/internal/dilithium_types.h>
#include <botan/internal/fmt.h>
#include <botan/internal/shake_xof.h>
#include <botan/internal/stl_util.h>

namespace Botan {

class RandomNumberGenerator;

/**
 * Wrapper type for the H() function calculating the message representative for
 * the Dilithium signature scheme. This wrapper may be used multiple times.
 *
 * Namely: mu = H(tr || M)
 */
class DilithiumMessageHash {
   public:
      DilithiumMessageHash(DilithiumHashedPublicKey tr) : m_tr(std::move(tr)) { clear(); }

      virtual ~DilithiumMessageHash() = default;

      std::string name() const {
         return Botan::fmt("{}({})", m_shake.name(), DilithiumConstants::MESSAGE_HASH_BYTES * 8);
      }

      virtual bool is_valid_user_context(std::span<const uint8_t> user_context) const {
         // Only ML-DSA supports user contexts, for all other modes it must be empty.
         return user_context.empty();
      }

      virtual void start(std::span<const uint8_t> user_context) {
         BOTAN_STATE_CHECK(!m_was_started);
         BOTAN_ARG_CHECK(is_valid_user_context(user_context), "Invalid user context");
         m_was_started = true;
         update(m_tr);  // see calculation of mu in FIPS 204, Algorithm 7, line 6
      }

      void update(std::span<const uint8_t> data) {
         ensure_started();
         m_shake.update(data);
      }

      DilithiumMessageRepresentative final() {
         ensure_started();
         scoped_cleanup clean([this]() { clear(); });
         return m_shake.output<DilithiumMessageRepresentative>(DilithiumConstants::MESSAGE_HASH_BYTES);
      }

   private:
      void clear() {
         m_shake.clear();
         m_was_started = false;
      }

      void ensure_started() {
         if(!m_was_started) {
            // FIPS 204, page 17, footnote 4: By default, the context is the empty string [...]
            start({});
         }
      }

   private:
      DilithiumHashedPublicKey m_tr;
      bool m_was_started;
      SHAKE_256_XOF m_shake;
};

/**
* Implemented by the derived classes to create the correct XOF instance. This is
* a customization point to enable support for the AES variant of Dilithium. This
* was not standardized in the FIPS 204; ML-DSA always uses SHAKE. Once we decide
* to remove the AES variant, this can be removed.
*/
class DilithiumXOF {
   public:
      virtual ~DilithiumXOF() = default;

      virtual Botan::XOF& XOF128(std::span<const uint8_t> seed, uint16_t nonce) const = 0;
      virtual Botan::XOF& XOF256(std::span<const uint8_t> seed, uint16_t nonce) const = 0;
};

/**
* Adapter class that uses polymorphy to distinguish
* Dilithium "common" from Dilithium "AES" modes.
*/
class Dilithium_Symmetric_Primitives_Base {
   protected:
      Dilithium_Symmetric_Primitives_Base(const DilithiumConstants& mode, std::unique_ptr<DilithiumXOF> xof_adapter) :
            m_commitment_hash_length_bytes(mode.commitment_hash_full_bytes()),
            m_public_key_hash_bytes(mode.public_key_hash_bytes()),
            m_mode(mode.mode()),
            m_xof_adapter(std::move(xof_adapter)) {}

   public:
      static std::unique_ptr<Dilithium_Symmetric_Primitives_Base> create(const DilithiumConstants& mode);

      virtual ~Dilithium_Symmetric_Primitives_Base() = default;
      Dilithium_Symmetric_Primitives_Base(const Dilithium_Symmetric_Primitives_Base&) = delete;
      Dilithium_Symmetric_Primitives_Base& operator=(const Dilithium_Symmetric_Primitives_Base&) = delete;
      Dilithium_Symmetric_Primitives_Base(Dilithium_Symmetric_Primitives_Base&&) = delete;
      Dilithium_Symmetric_Primitives_Base& operator=(Dilithium_Symmetric_Primitives_Base&&) = delete;

      virtual std::unique_ptr<DilithiumMessageHash> get_message_hash(DilithiumHashedPublicKey tr) const {
         return std::make_unique<DilithiumMessageHash>(std::move(tr));
      }

      /// Computes the private random seed rho prime used for signing
      /// if a @p rng is given, the seed is randomized
      virtual DilithiumSeedRhoPrime H_maybe_randomized(
         StrongSpan<const DilithiumSigningSeedK> k,
         StrongSpan<const DilithiumMessageRepresentative> mu,
         std::optional<std::reference_wrapper<RandomNumberGenerator>> rng) const = 0;

      DilithiumHashedPublicKey H(StrongSpan<const DilithiumSerializedPublicKey> pk) const {
         return H_256<DilithiumHashedPublicKey>(m_public_key_hash_bytes, pk);
      }

      std::tuple<DilithiumSeedRho, DilithiumSeedRhoPrime, DilithiumSigningSeedK> H(
         StrongSpan<const DilithiumSeedRandomness> seed) const {
         m_xof.update(seed);
         if(auto domsep = seed_expansion_domain_separator()) {
            m_xof.update(domsep.value());
         }

         // Note: The order of invocations in an initializer list is not
         //       guaranteed by the C++ standard. Hence, we have to store the
         //       results in variables to ensure the correct order of execution.
         auto rho = m_xof.output<DilithiumSeedRho>(DilithiumConstants::SEED_RHO_BYTES);
         auto rhoprime = m_xof.output<DilithiumSeedRhoPrime>(DilithiumConstants::SEED_RHOPRIME_BYTES);
         auto k = m_xof.output<DilithiumSigningSeedK>(DilithiumConstants::SEED_SIGNING_KEY_BYTES);
         m_xof.clear();

         return {std::move(rho), std::move(rhoprime), std::move(k)};
      }

      DilithiumCommitmentHash H(StrongSpan<const DilithiumMessageRepresentative> mu,
                                StrongSpan<const DilithiumSerializedCommitment> w1) const {
         return H_256<DilithiumCommitmentHash>(m_commitment_hash_length_bytes, mu, w1);
      }

      SHAKE_256_XOF& H(StrongSpan<const DilithiumCommitmentHash> seed) const {
         m_xof_external.clear();
         m_xof_external.update(truncate_commitment_hash(seed));
         return m_xof_external;
      }

      // Once Dilithium AES is removed, this could return a SHAKE_256_XOF and
      // avoid the virtual method call.
      Botan::XOF& H(StrongSpan<const DilithiumSeedRho> seed, uint16_t nonce) const {
         return m_xof_adapter->XOF128(seed, nonce);
      }

      // Once Dilithium AES is removed, this could return a SHAKE_128_XOF and
      // avoid the virtual method call.
      Botan::XOF& H(StrongSpan<const DilithiumSeedRhoPrime> seed, uint16_t nonce) const {
         return m_xof_adapter->XOF256(seed, nonce);
      }

   protected:
      /**
       * Implemented by the derived classes to truncate the commitment hash
       * to the correct length. This is a customization point to enable support
       * for the final ML-DSA standard.
       */
      virtual StrongSpan<const DilithiumCommitmentHash> truncate_commitment_hash(
         StrongSpan<const DilithiumCommitmentHash> seed) const = 0;

      /**
       * Creates the domain separator for the initial seed expansion.
       * The return value may be std::nullopt meaning that no domain separation
       * is required (for Dilithium).
       */
      virtual std::optional<std::array<uint8_t, 2>> seed_expansion_domain_separator() const = 0;

      template <concepts::resizable_byte_buffer OutT, ranges::spanable_range... InTs>
      OutT H_256(size_t outbytes, InTs&&... ins) const {
         scoped_cleanup clean([this]() { m_xof.clear(); });
         (m_xof.update(ins), ...);
         return m_xof.output<OutT>(outbytes);
      }

   private:
      size_t m_commitment_hash_length_bytes;
      size_t m_public_key_hash_bytes;
      DilithiumMode m_mode;

      std::unique_ptr<DilithiumXOF> m_xof_adapter;
      mutable SHAKE_256_XOF m_xof;
      mutable SHAKE_256_XOF m_xof_external;
};

}  // namespace Botan

#endif
