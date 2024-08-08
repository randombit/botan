/*
 * SPHINCS+ Hash Implementation for SHA-256
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_SP_HASH_SHAKE_H_
#define BOTAN_SP_HASH_SHAKE_H_

#include <botan/internal/sp_hash.h>

#include <botan/internal/shake.h>

namespace Botan {

/**
 * Implementation of SPHINCS+ hash function abstraction for SHAKE256
 */
class Sphincs_Hash_Functions_Shake : public Sphincs_Hash_Functions {
   private:
      HashFunction& tweak_hash(const Sphincs_Address& address, size_t input_length) override {
         BOTAN_UNUSED(input_length);
         m_hash.update(m_pub_seed);
         m_hash.update(address.to_bytes());
         return m_hash;
      }

      std::vector<uint8_t> H_msg_digest(StrongSpan<const SphincsMessageRandomness> r,
                                        const SphincsTreeNode& root,
                                        std::span<const uint8_t> message) override {
         m_h_msg_hash.update(r);
         m_h_msg_hash.update(m_pub_seed);
         m_h_msg_hash.update(root);
         m_h_msg_hash.update(message);

         return m_h_msg_hash.final_stdvec();
      }

   public:
      Sphincs_Hash_Functions_Shake(const Sphincs_Parameters& sphincs_params, const SphincsPublicSeed& pub_seed) :
            Sphincs_Hash_Functions(sphincs_params, pub_seed),
            m_seeded_hash(sphincs_params.n() * 8),
            m_hash(sphincs_params.n() * 8),
            m_h_msg_hash(8 * sphincs_params.h_msg_digest_bytes()) {
         m_seeded_hash.update(m_pub_seed);
      }

      void PRF_msg(StrongSpan<SphincsMessageRandomness> out,
                   const SphincsSecretPRF& sk_prf,
                   const SphincsOptionalRandomness& opt_rand,
                   std::span<const uint8_t> in) override {
         m_hash.update(sk_prf);
         m_hash.update(opt_rand);
         m_hash.update(in);
         m_hash.final(out);
      }

      std::string msg_hash_function_name() const override { return m_h_msg_hash.name(); }

   private:
      SHAKE_256 m_seeded_hash;
      SHAKE_256 m_hash;
      SHAKE_256 m_h_msg_hash;
};

}  // namespace Botan

#endif
