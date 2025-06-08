/*
 * Classic McEliece key generation with Internal Private and Public Key classes
 * (C) 2023 Jack Lloyd
 *     2023,2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/internal/cmce_keys_internal.h>

namespace Botan {

namespace {

/**
 * @brief Try to generate a Classic McEliece keypair for a given seed.
 *
 * @param[out] out_next_seed The next seed to use for key generation, if this iteration fails
 * @param params Classic McEliece parameters
 * @param seed The seed to used for this key generation iteration
 * @return a keypair on success, std::nullopt otherwise
 */
std::optional<Classic_McEliece_KeyPair_Internal> try_generate_keypair(std::span<uint8_t> out_next_seed,
                                                                      const Classic_McEliece_Parameters& params,
                                                                      CmceKeyGenSeed seed) {
   BOTAN_ASSERT_EQUAL(seed.size(), 32, "Valid seed length");
   BOTAN_ASSERT_EQUAL(out_next_seed.size(), 32, "Valid output seed length");

   auto big_e_xof = params.prg(seed);

   auto s = big_e_xof->output<CmceRejectionSeed>(params.n() / 8);
   auto ordering_bits = big_e_xof->output<CmceOrderingBits>((params.sigma2() * params.q()) / 8);
   auto irreducible_bits = big_e_xof->output<CmceIrreducibleBits>((params.sigma1() * params.t()) / 8);
   big_e_xof->output(out_next_seed);

   // Field-ordering generation - Classic McEliece ISO 8.2
   auto field_ordering = Classic_McEliece_Field_Ordering::create_field_ordering(params, ordering_bits);
   if(!field_ordering) {
      return std::nullopt;
   }

   // Irreducible-polynomial generation - Classic McEliece ISO 8.1
   auto g = params.poly_ring().compute_minimal_polynomial(irreducible_bits);
   if(!g) {
      return std::nullopt;
   }

   // Matrix generation for Goppa codes - Classic McEliece ISO 7.2
   auto pk_matrix_and_pivots =
      Classic_McEliece_Matrix::create_matrix_and_apply_pivots(params, field_ordering.value(), g.value());
   if(!pk_matrix_and_pivots) {
      return std::nullopt;
   }
   auto& [pk_matrix, pivots] = pk_matrix_and_pivots.value();

   // Key generation was successful - Create and return keys
   return Classic_McEliece_KeyPair_Internal{
      .private_key = std::make_shared<Classic_McEliece_PrivateKeyInternal>(
         params, std::move(seed), pivots, std::move(g.value()), std::move(field_ordering.value()), std::move(s)),
      .public_key = std::make_shared<Classic_McEliece_PublicKeyInternal>(params, std::move(pk_matrix))};
}

}  // namespace

Classic_McEliece_PrivateKeyInternal Classic_McEliece_PrivateKeyInternal::from_bytes(
   const Classic_McEliece_Parameters& params, std::span<const uint8_t> sk_bytes) {
   BOTAN_ASSERT(sk_bytes.size() == params.sk_size_bytes(), "Valid private key size");
   BufferSlicer sk_slicer(sk_bytes);

   auto delta = sk_slicer.copy<CmceKeyGenSeed>(params.seed_len());
   auto c = CmceColumnSelection(sk_slicer.take(params.sk_c_bytes()));
   auto g = Classic_McEliece_Minimal_Polynomial::from_bytes(sk_slicer.take(params.sk_poly_g_bytes()), params.poly_f());
   auto field_ordering = Classic_McEliece_Field_Ordering::create_from_control_bits(
      params, secure_bitvector(sk_slicer.take(params.sk_alpha_control_bytes())));
   auto s = sk_slicer.copy<CmceRejectionSeed>(params.sk_s_bytes());
   BOTAN_ASSERT_NOMSG(sk_slicer.empty());

   return Classic_McEliece_PrivateKeyInternal(
      params, std::move(delta), std::move(c), std::move(g), std::move(field_ordering), std::move(s));
}

secure_vector<uint8_t> Classic_McEliece_PrivateKeyInternal::serialize() const {
   auto control_bits = m_field_ordering.alphas_control_bits();

   /* NIST Impl. guide 6.1 Control-Bit Gen:
    *     As low-cost protection against faults in the control-bit computation, implementors are advised
    *     to check after the computation that applying the Benes network produces pi, and to
    *     restart key generation if this test fails; applying the Benes network is very fast.
    *
    * Here, we just assert that applying the Benes network produces pi.
    */
   BOTAN_ASSERT(Classic_McEliece_Field_Ordering::create_from_control_bits(m_params, control_bits)
                   .ct_is_equal(m_field_ordering)
                   .as_bool(),
                "Control Bit Computation Check");

   return concat(m_delta.get(), m_c.get().to_bytes(), m_g.serialize(), control_bits.to_bytes(), m_s);
}

bool Classic_McEliece_PrivateKeyInternal::check_key() const {
   auto prg = m_params.prg(m_delta);

   const auto s = prg->output<CmceRejectionSeed>(m_params.n() / 8);
   const auto ordering_bits = prg->output<CmceOrderingBits>((m_params.sigma2() * m_params.q()) / 8);
   const auto irreducible_bits = prg->output<CmceIrreducibleBits>((m_params.sigma1() * m_params.t()) / 8);

   // Recomputing s as hash of delta
   auto ret = CT::Mask<size_t>::expand(CT::is_equal<uint8_t>(s.data(), m_s.data(), m_params.n() / 8));

   // Checking weight of c
   ret &= CT::Mask<size_t>::is_equal(c().hamming_weight(), 32);

   if(auto g = m_params.poly_ring().compute_minimal_polynomial(irreducible_bits)) {
      for(size_t i = 0; i < g->degree() - 1; ++i) {
         ret &= CT::Mask<size_t>::expand(GF_Mask::is_equal(g->coef_at(i), m_g.coef_at(i)).elem_mask());
      }
   } else {
      ret = CT::Mask<size_t>::cleared();
   }

   // Check alpha control bits
   if(auto field_ord_from_seed = Classic_McEliece_Field_Ordering::create_field_ordering(m_params, ordering_bits)) {
      field_ord_from_seed->permute_with_pivots(m_params, c());
      ret &= CT::Mask<size_t>::expand(field_ord_from_seed->ct_is_equal(field_ordering()));
   } else {
      ret = CT::Mask<size_t>::cleared();
   }

   return ret.as_bool();
}

std::shared_ptr<Classic_McEliece_PublicKeyInternal> Classic_McEliece_PublicKeyInternal::create_from_private_key(
   const Classic_McEliece_PrivateKeyInternal& sk) {
   auto pk_matrix_and_pivot = Classic_McEliece_Matrix::create_matrix(sk.params(), sk.field_ordering(), sk.g());
   if(!pk_matrix_and_pivot.has_value()) {
      throw Decoding_Error("Cannot create public key from private key. Private key is invalid.");
   }
   auto& [pk_matrix, pivot] = pk_matrix_and_pivot.value();

   // There should not be a pivot of any other form. Otherwise the gauss
   // algorithm failed effectively.
   if(!CT::driveby_unpoison(pivot.equals(bitvector{0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00}))) {
      throw Decoding_Error("Cannot create public key from private key. Private key is invalid.");
   }

   return std::make_shared<Classic_McEliece_PublicKeyInternal>(sk.params(), std::move(pk_matrix));
}

Classic_McEliece_KeyPair_Internal Classic_McEliece_KeyPair_Internal::generate(const Classic_McEliece_Parameters& params,
                                                                              StrongSpan<const CmceInitialSeed> seed) {
   BOTAN_ASSERT_EQUAL(seed.size(), params.seed_len(), "Valid seed length");

   CmceKeyGenSeed next_seed(seed.size());
   CmceKeyGenSeed current_seed(seed.begin(), seed.end());

   while(true) {
      if(auto keypair = try_generate_keypair(next_seed, params, std::move(current_seed))) {
         return keypair.value();
      }
      current_seed = next_seed;
   }
}

}  // namespace Botan
