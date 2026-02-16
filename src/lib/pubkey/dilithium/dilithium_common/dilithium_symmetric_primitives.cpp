/**
 * Symmetric primitives for dilithium
 *
 * (C) 2022-2023 Jack Lloyd
 * (C) 2022-2023 Michael Boric, René Meusel - Rohde & Schwarz Cybersecurity
 * (C) 2022      Manuel Glaser - Rohde & Schwarz Cybersecurity
 * (C) 2024      Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/dilithium_symmetric_primitives.h>

#include <botan/internal/fmt.h>

#if defined(BOTAN_HAS_DILITHIUM)
   #include <botan/internal/dilithium_round3.h>
#endif

#if defined(BOTAN_HAS_DILITHIUM_AES)
   #include <botan/internal/dilithium_aes.h>
#endif

#if defined(BOTAN_HAS_ML_DSA)
   #include <botan/internal/ml_dsa_impl.h>
#endif

namespace Botan {

DilithiumMessageHash::DilithiumMessageHash(DilithiumHashedPublicKey tr) :
      m_tr(std::move(tr)), m_shake(XOF::create_or_throw("SHAKE-256")) {}

DilithiumMessageHash::~DilithiumMessageHash() = default;

std::string DilithiumMessageHash::name() const {
   return Botan::fmt("{}({})", m_shake->name(), DilithiumConstants::MESSAGE_HASH_BYTES * 8);
}

Dilithium_Symmetric_Primitives_Base::Dilithium_Symmetric_Primitives_Base(const DilithiumConstants& mode,
                                                                         std::unique_ptr<DilithiumXOF> xof_adapter) :
      m_commitment_hash_length_bytes(mode.commitment_hash_full_bytes()),
      m_public_key_hash_bytes(mode.public_key_hash_bytes()),
      m_mode(mode.mode()),
      m_xof_adapter(std::move(xof_adapter)),
      m_xof(XOF::create_or_throw("SHAKE-256")),
      m_xof_external(m_xof->new_object()) {}

std::unique_ptr<Dilithium_Symmetric_Primitives_Base> Dilithium_Symmetric_Primitives_Base::create(
   const DilithiumConstants& mode) {
#if defined(BOTAN_HAS_DILITHIUM)
   if(mode.is_modern() && !mode.is_ml_dsa()) {
      return std::make_unique<Dilithium_Symmetric_Primitives>(mode);
   }
#endif

#if defined(BOTAN_HAS_DILITHIUM_AES)
   if(mode.is_aes()) {
      return std::make_unique<Dilithium_AES_Symmetric_Primitives>(mode);
   }
#endif

#if defined(BOTAN_HAS_ML_DSA)
   if(mode.is_ml_dsa()) {
      return std::make_unique<ML_DSA_Symmetric_Primitives>(mode);
   }
#endif

   throw Not_Implemented("requested ML-DSA/Dilithium mode is not implemented in this build");
}

}  // namespace Botan
