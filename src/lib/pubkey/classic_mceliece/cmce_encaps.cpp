/*
 * Classic McEliece Encapsulation
 * Based on the public domain reference implementation by the designers
 * (https://classic.mceliece.org/impl.html - released in Oct 2022 for NISTPQC-R4)
 *
 * (C) 2023 Jack Lloyd
 *     2023,2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/
#include <botan/internal/cmce_encaps.h>

#include <botan/rng.h>

namespace Botan {

CmceCodeWord Classic_McEliece_Encryptor::encode(const Classic_McEliece_Parameters& params,
                                                const CmceErrorVector& e,
                                                const Classic_McEliece_Matrix& mat) const {
   return mat.mul(params, e);
}

std::optional<CmceErrorVector> Classic_McEliece_Encryptor::fixed_weight_vector_gen(
   const Classic_McEliece_Parameters& params, RandomNumberGenerator& rng) const {
   const auto rand = rng.random_vec((params.sigma1() / 8) * params.tau());
   CT::poison(rand);
   uint16_t mask_m = (uint32_t(1) << params.m()) - 1;  // Only take m least significant bits
   secure_vector<uint16_t> a_values;
   a_values.reserve(params.tau());
   BufferSlicer rand_slicer(rand);

   // Steps 2 & 3: Create d_j from uniform random bits. The first t d_j entries
   //              in range {0,...,n-1} are defined as a_0,...,a_(t-1). ...
   for(size_t j = 0; j < params.tau(); ++j) {
      auto d = load_le<uint16_t>(rand_slicer.take(params.sigma1() / 8).data(), 0);
      // This is not CT, but neither is the reference implementation here.
      // This side channel only leaks which random elements are selected and which are dropped,
      // but no information about their content is leaked.
      d &= mask_m;
      bool d_in_range = d < params.n();
      CT::unpoison(d_in_range);
      if(d_in_range && a_values.size() < params.t()) {
         a_values.push_back(d);
      }
   }
   if(a_values.size() < params.t()) {
      // Step 3: ... If fewer than t of such elements exist restart
      return std::nullopt;
   }

   // Step 4: Restart if not all a_i are distinct
   for(size_t i = 1; i < params.t(); ++i) {
      for(size_t j = 0; j < i; ++j) {
         bool a_i_j_equal = a_values.at(i) == a_values.at(j);
         CT::unpoison(a_i_j_equal);
         if(a_i_j_equal) {
            return std::nullopt;
         }
      }
   }

   secure_vector<uint8_t> a_value_byte(params.t());
   secure_vector<uint8_t> e_bytes(ceil_tobytes(params.n()));

   // Step 5: Set all bits of e at the positions of a_values
   // Prepare the associated byte in e_bytes that is represented by each bit index in a_values
   // if we e is represented as a byte vector
   for(size_t j = 0; j < a_values.size(); ++j) {
      a_value_byte[j] = 1 << (a_values[j] % 8);
   }

   for(size_t i = 0; i < params.n() / 8; ++i) {
      for(size_t j = 0; j < a_values.size(); ++j) {
         // If the current byte is the one that is represented by the current bit index in a_values
         // then set the bit in e_bytes (in-byte position prepared above)
         auto mask = CT::Mask<uint16_t>::is_equal(static_cast<uint16_t>(i), static_cast<uint16_t>(a_values[j] >> 3));
         e_bytes[i] |= mask.if_set_return(a_value_byte[j]);
      }
   }

   return CmceErrorVector(secure_bitvector(e_bytes, params.n()));
}

void Classic_McEliece_Encryptor::raw_kem_encrypt(std::span<uint8_t> out_encapsulated_key,
                                                 std::span<uint8_t> out_shared_key,
                                                 RandomNumberGenerator& rng) {
   BOTAN_ARG_CHECK(out_encapsulated_key.size() == m_key->params().ciphertext_size(),
                   "Incorrect encapsulated key output length");
   BOTAN_ARG_CHECK(out_shared_key.size() == m_key->params().hash_out_bytes(), "Incorrect shared key output length");

   const auto& params = m_key->params();

   // Call fixed_weight until it is successful to
   // create a random error vector e of weight tau
   const CmceErrorVector e = [&] {
      // Emergency abort in case unexpected logical error to prevent endless loops
      //   Success probability: >24% per attempt (25% that elements are distinct * 96% enough elements are in range)
      //   => 203 attempts for 2^(-80) fail probability
      constexpr size_t MAX_ATTEMPTS = 203;
      for(size_t attempt = 0; attempt < MAX_ATTEMPTS; ++attempt) {
         if(auto maybe_e = fixed_weight_vector_gen(params, rng)) {
            return maybe_e.value();
         }
      }
      throw Internal_Error("Cannot created fixed weight vector. Is your RNG broken?");
   }();

   auto hash_func = params.hash_func();

   BufferStuffer big_c_stuf(out_encapsulated_key);
   const auto e_bytes = e.get().to_bytes();
   // Compute and store ciphertext C/C_0 from spec
   const auto big_c_0 = encode(params, e, m_key->matrix());
   big_c_0.to_bytes(big_c_stuf.next(ceil_tobytes(big_c_0.size())));
   if(params.is_pc()) {
      // Compute and store ciphertext C_1 from spec
      hash_func->update(0x02);
      hash_func->update(e_bytes);
      hash_func->final(big_c_stuf.next(hash_func->output_length()));
   }
   BOTAN_ASSERT_NOMSG(big_c_stuf.full());

   // Compute K = Hash(1,e,C) from spec
   hash_func->update(0x01);
   hash_func->update(e_bytes);
   hash_func->update(out_encapsulated_key);
   hash_func->final(out_shared_key);
   CT::unpoison_all(out_encapsulated_key, out_shared_key);
}

}  // namespace Botan
