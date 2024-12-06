/*
* (C) 2013 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_GCM_GHASH_H_
#define BOTAN_GCM_GHASH_H_

#include <botan/sym_algo.h>
#include <botan/internal/alignment_buffer.h>

namespace Botan {

/**
* GCM's GHASH
*/
class GHASH final : public SymmetricAlgorithm {
   private:
      static constexpr size_t GCM_BS = 16;

   public:
      /// Hashing of non-default length nonce values for both GCM and GMAC use-cases
      void nonce_hash(secure_vector<uint8_t>& y0, std::span<const uint8_t> nonce);

      void start(std::span<const uint8_t> nonce);

      void update(std::span<const uint8_t> in);

      /// Monolithic setting of associated data usid in the GCM use-case
      void set_associated_data(std::span<const uint8_t> ad);

      /// Incremental update of associated data used in the GMAC use-case
      void update_associated_data(std::span<const uint8_t> ad);

      void final(std::span<uint8_t> out);

      Key_Length_Specification key_spec() const override { return Key_Length_Specification(16); }

      bool has_keying_material() const override;

      void clear() override;

      void reset();

      std::string name() const override { return "GHASH"; }

      std::string provider() const;

   private:
      void ghash_update(std::span<uint8_t, GCM_BS> x, std::span<const uint8_t> input);
      void ghash_zeropad(std::span<uint8_t, GCM_BS> x);
      void ghash_final_block(std::span<uint8_t, GCM_BS> x, uint64_t ad_len, uint64_t pt_len);

#if defined(BOTAN_HAS_GHASH_CLMUL_CPU)
      static void ghash_precompute_cpu(const uint8_t H[16], uint64_t H_pow[4 * 2]);

      static void ghash_multiply_cpu(uint8_t x[16], const uint64_t H_pow[4 * 2], const uint8_t input[], size_t blocks);
#endif

#if defined(BOTAN_HAS_GHASH_CLMUL_VPERM)
      static void ghash_multiply_vperm(uint8_t x[16], const uint64_t HM[256], const uint8_t input[], size_t blocks);
#endif

      void key_schedule(std::span<const uint8_t> key) override;

      void ghash_multiply(std::span<uint8_t, GCM_BS> x, std::span<const uint8_t> input, size_t blocks);

   private:
      AlignmentBuffer<uint8_t, GCM_BS> m_buffer;

      std::array<uint8_t, GCM_BS> m_H_ad;   /// cache of hash state after consuming the AD, reused for multiple messages
      std::array<uint8_t, GCM_BS> m_ghash;  /// hash state used for update() or update_associated_data()
      secure_vector<uint64_t> m_HM;
      secure_vector<uint64_t> m_H_pow;

      std::optional<std::array<uint8_t, GCM_BS>> m_nonce;
      size_t m_ad_len = 0;
      size_t m_text_len = 0;
};

}  // namespace Botan

#endif
