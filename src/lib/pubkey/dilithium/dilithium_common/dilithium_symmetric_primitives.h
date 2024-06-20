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

/**
 * Wrapper type for the H() function calculating the message representative for
 * the Dilithium signature scheme. This wrapper may be used multiple times.
 *
 * Namely: mu = H(tr || M)
 */
class DilithiumMessageHash {
   public:
      DilithiumMessageHash(DilithiumHashedPublicKey tr) : m_tr(std::move(tr)) { clear(); }

      std::string name() const {
         return Botan::fmt("{}({})", m_shake.name(), DilithiumConstants::MESSAGE_HASH_BYTES * 8);
      }

      void update(std::span<const uint8_t> data) { m_shake.update(data); }

      DilithiumMessageRepresentative final() {
         scoped_cleanup clean([this]() { clear(); });
         return m_shake.output<DilithiumMessageRepresentative>(DilithiumConstants::MESSAGE_HASH_BYTES);
      }

   private:
      void clear() {
         m_shake.clear();
         m_shake.update(m_tr);
      }

   private:
      DilithiumHashedPublicKey m_tr;
      SHAKE_256_XOF m_shake;
};

/**
* Adapter class that uses polymorphy to distinguish
* Dilithium "common" from Dilithium "AES" modes.
*/
class Dilithium_Symmetric_Primitives {
   public:
      enum class XofType { k128, k256 };

   protected:
      Dilithium_Symmetric_Primitives(size_t commitment_hash_length_bytes) :
            m_commitment_hash_length_bytes(commitment_hash_length_bytes) {}

   public:
      static std::unique_ptr<Dilithium_Symmetric_Primitives> create(const DilithiumConstants& mode);

      virtual ~Dilithium_Symmetric_Primitives() = default;
      Dilithium_Symmetric_Primitives(const Dilithium_Symmetric_Primitives&) = delete;
      Dilithium_Symmetric_Primitives& operator=(const Dilithium_Symmetric_Primitives&) = delete;
      Dilithium_Symmetric_Primitives(Dilithium_Symmetric_Primitives&&) = delete;
      Dilithium_Symmetric_Primitives& operator=(Dilithium_Symmetric_Primitives&&) = delete;

      DilithiumMessageHash get_message_hash(DilithiumHashedPublicKey tr) const {
         return DilithiumMessageHash(std::move(tr));
      }

      DilithiumHashedPublicKey H(StrongSpan<const DilithiumSerializedPublicKey> pk) const {
         return H_256<DilithiumHashedPublicKey>(DilithiumConstants::PUBLIC_KEY_HASH_BYTES, pk);
      }

      DilithiumSeedRhoPrime H(StrongSpan<const DilithiumSigningSeedK> k,
                              StrongSpan<const DilithiumMessageRepresentative> mu) const {
         return H_256<DilithiumSeedRhoPrime>(DilithiumConstants::SEED_RHOPRIME_BYTES, k, mu);
      }

      std::tuple<DilithiumSeedRho, DilithiumSeedRhoPrime, DilithiumSigningSeedK> H(
         StrongSpan<const DilithiumSeedRandomness> seed) const {
         m_xof.update(seed);

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
         m_xof_external.update(seed);
         return m_xof_external;
      }

      // Once Dilithium AES is removed, this could return a SHAKE_256_XOF and
      // avoid the virtual method call.
      Botan::XOF& H(StrongSpan<const DilithiumSeedRho> seed, uint16_t nonce) const {
         return XOF(XofType::k128, seed, nonce);
      }

      // Once Dilithium AES is removed, this could return a SHAKE_128_XOF and
      // avoid the virtual method call.
      Botan::XOF& H(StrongSpan<const DilithiumSeedRhoPrime> seed, uint16_t nonce) const {
         return XOF(XofType::k256, seed, nonce);
      }

   protected:
      /**
       * Implemented by the derived classes to create the correct XOF instance.
       * This is a customization point to enable support for the AES variant of
       * Dilithium. This won't be standardized in the FIPS 204; ML-DSA always
       * uses SHAKE. Once we decide to remove the AES variant, this virtual
       * method can be removed.
       */
      virtual Botan::XOF& XOF(XofType type, std::span<const uint8_t> seed, uint16_t nonce) const = 0;

   private:
      template <concepts::resizable_byte_buffer OutT, ranges::spanable_range... InTs>
      OutT H_256(size_t outbytes, InTs&&... ins) const {
         scoped_cleanup clean([this]() { m_xof.clear(); });
         (m_xof.update(ins), ...);
         return m_xof.output<OutT>(outbytes);
      }

   private:
      size_t m_commitment_hash_length_bytes;
      mutable SHAKE_256_XOF m_xof;
      mutable SHAKE_256_XOF m_xof_external;
};

}  // namespace Botan

#endif
