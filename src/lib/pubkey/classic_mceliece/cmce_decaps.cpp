/*
 * Classic McEliece Decapsulation
 * Based on the public domain reference implementation by the designers
 * (https://classic.mceliece.org/impl.html - released in Oct 2022 for NISTPQC-R4)
 *
 * (C) 2023 Jack Lloyd
 *     2023,2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/internal/cmce_decaps.h>

namespace Botan {

Classic_McEliece_Polynomial Classic_McEliece_Decryptor::compute_goppa_syndrome(
   const Classic_McEliece_Parameters& params,
   const Classic_McEliece_Minimal_Polynomial& goppa_poly,
   const Classic_McEliece_Field_Ordering& ordering,
   const secure_bitvector& code_word) const {
   BOTAN_ASSERT(params.n() == code_word.size(), "Correct code word size");
   std::vector<Classic_McEliece_GF> syndrome(2 * params.t(), params.gf(CmceGfElem(0)));

   auto alphas = ordering.alphas(params.n());

   for(size_t i = 0; i < params.n(); ++i) {
      auto g_alpha = goppa_poly(alphas[i]);
      auto r = (g_alpha * g_alpha).inv();

      auto c_mask = GF_Mask::expand(static_cast<bool>(code_word.at(i)));

      for(size_t j = 0; j < 2 * params.t(); ++j) {
         syndrome[j] += c_mask.if_set_return(r);
         r = r * alphas[i];
      }
   }

   return Classic_McEliece_Polynomial(syndrome);
}

Classic_McEliece_Polynomial Classic_McEliece_Decryptor::berlekamp_massey(
   const Classic_McEliece_Parameters& params, const Classic_McEliece_Polynomial& syndrome) const {
   // Represents coefficients of corresponding polynomials
   std::vector<Classic_McEliece_GF> big_c(params.t() + 1, params.gf(CmceGfElem(0)));
   std::vector<Classic_McEliece_GF> big_b(params.t() + 1, params.gf(CmceGfElem(0)));

   auto b = params.gf(CmceGfElem(1));

   // Start with x^m for m=1, see pseudocode of https://en.wikipedia.org/wiki/Berlekamp%E2%80%93Massey_algorithm
   big_b.at(1) = CmceGfElem(1);
   big_c.at(0) = CmceGfElem(1);

   for(size_t big_n = 0, big_l = 0; big_n < 2 * params.t(); ++big_n) {
      auto d = params.gf(CmceGfElem(0));
      for(size_t i = 0; i <= std::min(big_n, params.t()); ++i) {
         d += big_c.at(i) * syndrome.coef_at(big_n - i);
      }

      // Pseudocode branch if (d == 0)
      auto d_not_zero = GF_Mask::expand(d);

      // Pseudocode branch else if (2* L <= N)
      auto adjust_big_c = GF_Mask(CT::Mask<uint16_t>::is_lte(uint16_t(2 * big_l), uint16_t(big_n)));
      adjust_big_c &= d_not_zero;

      auto big_t = big_c;  // Copy
      auto f = d / b;

      for(size_t i = 0; i <= params.t(); ++i) {
         // Occurs for all other d!=0 branches in the pseudocode
         big_c.at(i) += d_not_zero.if_set_return((f * big_b.at(i)));
      }

      big_l = adjust_big_c.select(uint16_t((big_n + 1) - big_l), uint16_t(big_l));

      for(size_t i = 0; i <= params.t(); ++i) {
         big_b.at(i) = adjust_big_c.select(big_t.at(i), big_b.at(i));
      }

      b = adjust_big_c.select(d, b);

      // Rotate big_b one to the right (multiplies with x), replaces increments of m in pseudocode
      std::rotate(big_b.rbegin(), big_b.rbegin() + 1, big_b.rend());
   }

   std::reverse(big_c.begin(), big_c.end());

   return Classic_McEliece_Polynomial(big_c);
}

std::pair<CT::Mask<uint8_t>, CmceErrorVector> Classic_McEliece_Decryptor::decode(CmceCodeWord big_c) const {
   BOTAN_ASSERT(big_c.size() == m_key->params().m() * m_key->params().t(), "Correct ciphertext input size");
   big_c.resize(m_key->params().n());

   const auto syndrome =
      compute_goppa_syndrome(m_key->params(), m_key->g(), m_key->field_ordering(), big_c.as<secure_bitvector>());
   const auto locator = berlekamp_massey(m_key->params(), syndrome);

   std::vector<Classic_McEliece_GF> images;
   const auto alphas = m_key->field_ordering().alphas(m_key->params().n());
   std::transform(
      alphas.begin(), alphas.end(), std::back_inserter(images), [&](const auto& alpha) { return locator(alpha); });

   // Obtain e and check whether wt(e) = t. locator(alpha_i) = 0 <=> error at position i
   CmceErrorVector e;
   e.get().reserve(m_key->params().n());
   auto decode_success = CT::Mask<uint8_t>::set();  // Avoid bool to avoid possible compiler optimizations
   for(const auto& image : images) {
      e.push_back(GF_Mask::is_zero(image).as_bool());
   }
   decode_success &= CT::Mask<uint8_t>(CT::Mask<size_t>::is_equal(e.hamming_weight(), m_key->params().t()));

   // Check the error vector by checking H'C = H'e <=> H'(C + e) = 0; see guide for implementors Sec. 6.3
   const auto syndrome_from_e = compute_goppa_syndrome(m_key->params(), m_key->g(), m_key->field_ordering(), e.get());
   auto syndromes_are_eq = GF_Mask::set();
   for(size_t i = 0; i < syndrome.degree() - 1; ++i) {
      syndromes_are_eq &= GF_Mask::is_equal(syndrome.coef_at(i), syndrome_from_e.coef_at(i));
   }

   decode_success &= syndromes_are_eq.elem_mask();

   return {decode_success, std::move(e)};
}

void Classic_McEliece_Decryptor::raw_kem_decrypt(std::span<uint8_t> out_shared_key,
                                                 std::span<const uint8_t> encapsulated_key) {
   BOTAN_ARG_CHECK(out_shared_key.size() == m_key->params().hash_out_bytes(), "Invalid shared key output size");
   BOTAN_ARG_CHECK(encapsulated_key.size() == m_key->params().ciphertext_size(), "Invalid ciphertext size");

   auto scope = CT::scoped_poison(*m_key);

   auto [ct, c1] = [&]() -> std::pair<CmceCodeWord, std::span<const uint8_t>> {
      if(m_key->params().is_pc()) {
         BufferSlicer encaps_key_slicer(encapsulated_key);
         auto c0_ret = encaps_key_slicer.take(m_key->params().encode_out_size());
         auto c1_ret = encaps_key_slicer.take(m_key->params().hash_out_bytes());
         BOTAN_ASSERT_NOMSG(encaps_key_slicer.empty());
         return {CmceCodeWord(secure_bitvector(c0_ret, m_key->params().m() * m_key->params().t())), c1_ret};
      } else {
         return {CmceCodeWord(secure_bitvector(encapsulated_key, m_key->params().m() * m_key->params().t())), {}};
      }
   }();

   auto [decode_success_mask, maybe_e] = decode(ct);

   secure_vector<uint8_t> e_bytes(m_key->s().size());
   decode_success_mask.select_n(e_bytes.data(), maybe_e.get().to_bytes().data(), m_key->s().data(), m_key->s().size());
   uint8_t b = decode_success_mask.select(1, 0);

   auto hash_func = m_key->params().hash_func();

   if(m_key->params().is_pc()) {
      hash_func->update(0x02);
      hash_func->update(e_bytes);
      const auto c1_p = hash_func->final_stdvec();
      const CT::Mask<uint8_t> eq_mask = CT::is_equal(c1.data(), c1_p.data(), c1.size());
      eq_mask.select_n(e_bytes.data(), e_bytes.data(), m_key->s().data(), m_key->s().size());
      b = eq_mask.select(b, 0);
   }

   hash_func->update(b);
   hash_func->update(e_bytes);
   hash_func->update(encapsulated_key);
   hash_func->final(out_shared_key);
   CT::unpoison(out_shared_key);
}

}  // namespace Botan
