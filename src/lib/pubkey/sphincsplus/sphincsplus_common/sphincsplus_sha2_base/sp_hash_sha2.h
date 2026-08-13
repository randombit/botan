/*
 * SLH-DSA Hash Implementation for SHA-256
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_SP_HASH_SHA2_H_
#define BOTAN_SP_HASH_SHA2_H_

#include <botan/internal/sp_hash.h>

#include <botan/internal/concat_util.h>
#include <botan/internal/fmt.h>
#include <botan/internal/hash_engine.h>
#include <botan/internal/hmac.h>
#include <botan/internal/mgf1.h>
#include <botan/internal/sha2_32.h>
#include <botan/internal/sha2_64.h>
#include <botan/internal/trunc_hash.h>

namespace Botan {

/**
 * Implementation of SLH-DSA hash function abstraction for SHA2
 */
class Sphincs_Hash_Functions_Sha2 : public Sphincs_Hash_Functions {
   private:
      HashFunction& tweak_hash(const Sphincs_Address& address, size_t input_length) override {
         // Depending on the input length we decide to use SHA-256 (Function F
         // in the spec) or SHA-X (Function T_l and H in the spec).
         //
         // All hashed values share a common prefix. Hence we could reuse the
         // hash state after this prefix was consumed as an optimization.
         //
         // TODO: Currently, the `copy_state()` method would force us to perform
         //       a re-allocation whenever we want to do that.
         auto& hash = (input_length > m_sphincs_params.n()) ? *m_sha_x : *m_sha_256;
         const auto& padded_pub_seed =
            (input_length > m_sphincs_params.n()) ? m_padded_pub_seed_x : m_padded_pub_seed_256;
         hash.update(padded_pub_seed);
         hash.update(address.to_bytes_compressed());
         return hash;
      }

      Hash_Engine& tweak_hash_engine(size_t input_length) override {
         auto& engine = (input_length > m_sphincs_params.n()) ? m_engine_x : m_engine_256;
         return *engine;
      }

      size_t address_encoding_len() const override { return 22; }

      void encode_address(std::span<uint8_t> out, const Sphincs_Address& address) const override {
         const auto adrs = address.to_bytes_compressed();
         copy_mem(out.data(), adrs.data(), adrs.size());
      }

      std::vector<uint8_t> H_msg_digest(StrongSpan<const SphincsMessageRandomness> r,
                                        const SphincsTreeNode& root,
                                        const SphincsMessageInternal& message) override {
         m_sha_x_full->update(r);
         m_sha_x_full->update(m_pub_seed);
         m_sha_x_full->update(root);
         m_sha_x_full->update(message.prefix);
         m_sha_x_full->update(message.message);

         auto r_pk_buffer = m_sha_x_full->final();
         std::vector<uint8_t> mgf1_input = concat<std::vector<uint8_t>>(r, m_pub_seed, r_pk_buffer);

         std::vector<uint8_t> digest(m_sphincs_params.h_msg_digest_bytes());
         mgf1_mask(*m_sha_x_full, mgf1_input, digest);

         return digest;
      }

   public:
      Sphincs_Hash_Functions_Sha2(const Sphincs_Parameters& sphincs_params, const SphincsPublicSeed& pub_seed) :
            Sphincs_Hash_Functions(sphincs_params, pub_seed), m_sphincs_params(sphincs_params) {
         m_padded_pub_seed_256 = std::vector<uint8_t>(64, '\0');
         BOTAN_ASSERT_NOMSG(pub_seed.size() <= m_padded_pub_seed_256.size());
         std::copy(pub_seed.begin(), pub_seed.end(), m_padded_pub_seed_256.begin());

         if(sphincs_params.n() == 16) {
            m_sha_x = std::make_unique<Truncated_Hash>(std::make_unique<SHA_256>(), sphincs_params.n() * 8);
            m_sha_x_full = std::make_unique<SHA_256>();
            m_padded_pub_seed_x = m_padded_pub_seed_256;
         } else {
            BOTAN_ASSERT_NOMSG(sphincs_params.n() <= 128);
            m_sha_x = std::make_unique<Truncated_Hash>(std::make_unique<SHA_512>(), sphincs_params.n() * 8);
            m_sha_x_full = std::make_unique<SHA_512>();

            m_padded_pub_seed_x = std::vector<uint8_t>(128, '\0');
            BOTAN_ASSERT_NOMSG(pub_seed.size() <= m_padded_pub_seed_x.size());
            std::copy(pub_seed.begin(), pub_seed.end(), m_padded_pub_seed_x.begin());
         }

         if(m_sphincs_params.n() < 32) {
            m_sha_256 = std::make_unique<Truncated_Hash>(std::make_unique<SHA_256>(), m_sphincs_params.n() * 8);
         } else {
            m_sha_256 = std::make_unique<SHA_256>();
         }

         // Batch engines for the same tweaked hashes. The padded pub seed
         // prefix is exactly one hash block, so the engines can precompute
         // its midstate once.
         const size_t n_bits = m_sphincs_params.n() * 8;

         const std::string hash_256 = (m_sphincs_params.n() < 32) ? fmt("Truncated(SHA-256,{})", n_bits) : "SHA-256";
         m_engine_256 = Hash_Engine::create_or_throw(hash_256, m_padded_pub_seed_256);

         const std::string hash_x =
            (m_sphincs_params.n() == 16) ? fmt("Truncated(SHA-256,{})", n_bits) : fmt("Truncated(SHA-512,{})", n_bits);
         m_engine_x = Hash_Engine::create_or_throw(hash_x, m_padded_pub_seed_x);
      }

      void PRF_msg(StrongSpan<SphincsMessageRandomness> out,
                   StrongSpan<const SphincsSecretPRF> sk_prf,
                   StrongSpan<const SphincsOptionalRandomness> opt_rand,
                   const SphincsMessageInternal& msg) override {
         HMAC hmac_sha_x(m_sha_x_full->new_object());
         hmac_sha_x.set_key(sk_prf);
         hmac_sha_x.update(opt_rand);
         hmac_sha_x.update(msg.prefix);
         hmac_sha_x.update(msg.message);

         const auto prf = hmac_sha_x.final();
         std::copy(prf.begin(), prf.begin() + out.size(), out.begin());
      }

      std::string msg_hash_function_name() const override { return m_sha_x_full->name(); }

   private:
      const Sphincs_Parameters& m_sphincs_params;
      std::unique_ptr<HashFunction> m_sha_256;
      std::unique_ptr<HashFunction> m_sha_x;
      /// Non truncated SHA-X hash
      std::unique_ptr<HashFunction> m_sha_x_full;

      std::unique_ptr<Hash_Engine> m_engine_256;
      std::unique_ptr<Hash_Engine> m_engine_x;

      std::vector<uint8_t> m_padded_pub_seed_256;
      std::vector<uint8_t> m_padded_pub_seed_x;
};

}  // namespace Botan

#endif
