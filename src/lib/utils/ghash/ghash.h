/*
* (C) 2013 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_GCM_GHASH_H_
#define BOTAN_GCM_GHASH_H_

#include <botan/sym_algo.h>

namespace Botan {

/**
* GCM's GHASH
*/
class GHASH final : public SymmetricAlgorithm {
   public:
      void set_associated_data(std::span<const uint8_t> ad);

      void nonce_hash(secure_vector<uint8_t>& y0, std::span<const uint8_t> nonce);

      void start(std::span<const uint8_t> nonce);

      /*
      * Assumes input len is multiple of 16
      */
      void update(std::span<const uint8_t> in);

      /*
      * Incremental update of associated data
      */
      void update_associated_data(std::span<const uint8_t> ad);

      void final(std::span<uint8_t> out);

      Key_Length_Specification key_spec() const override { return Key_Length_Specification(16); }

      bool has_keying_material() const override;

      void clear() override;

      void reset();

      std::string name() const override { return "GHASH"; }

      std::string provider() const;

      void ghash_update(secure_vector<uint8_t>& x, std::span<const uint8_t> input);

      void add_final_block(secure_vector<uint8_t>& x, size_t ad_len, size_t pt_len);

   private:
#if defined(BOTAN_HAS_GHASH_CLMUL_CPU)
      static void ghash_precompute_cpu(const uint8_t H[16], uint64_t H_pow[4 * 2]);

      static void ghash_multiply_cpu(uint8_t x[16], const uint64_t H_pow[4 * 2], const uint8_t input[], size_t blocks);
#endif

#if defined(BOTAN_HAS_GHASH_CLMUL_VPERM)
      static void ghash_multiply_vperm(uint8_t x[16], const uint64_t HM[256], const uint8_t input[], size_t blocks);
#endif

      void key_schedule(std::span<const uint8_t> key) override;

      void ghash_multiply(secure_vector<uint8_t>& x, std::span<const uint8_t> input, size_t blocks);

      static const size_t GCM_BS = 16;

      secure_vector<uint8_t> m_H;
      secure_vector<uint8_t> m_H_ad;
      secure_vector<uint8_t> m_ghash;
      secure_vector<uint8_t> m_nonce;
      secure_vector<uint64_t> m_HM;
      secure_vector<uint64_t> m_H_pow;
      size_t m_ad_len = 0;
      size_t m_text_len = 0;
};

}  // namespace Botan

#endif
