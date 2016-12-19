/*
 * (C) Copyright Projet SECRET, INRIA, Rocquencourt
 * (C) Bhaskar Biswas and  Nicolas Sendrier
 *
 * (C) 2014 cryptosource GmbH
 * (C) 2014 Falko Strenzke fstrenzke@cryptosource.de
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 *
 */

#include <botan/internal/mce_internal.h>
#include <botan/mceliece.h>
#include <botan/internal/code_based_util.h>
#include <botan/internal/bit_ops.h>
#include <set>

namespace Botan {

namespace {

secure_vector<uint8_t> concat_vectors(const secure_vector<uint8_t>& a, const secure_vector<uint8_t>& b,
                                      uint32_t dimension, uint32_t codimension) {
  secure_vector<uint8_t> x(bit_size_to_byte_size(dimension) + bit_size_to_byte_size(codimension));

  const size_t final_bits = dimension % 8;

  if (final_bits == 0) {
    const size_t dim_bytes = bit_size_to_byte_size(dimension);
    copy_mem(&x[0], a.data(), dim_bytes);
    copy_mem(&x[dim_bytes], b.data(), bit_size_to_byte_size(codimension));
  }
  else {
    copy_mem(&x[0], a.data(), (dimension / 8));
    uint32_t l = dimension / 8;
    x[l] = static_cast<uint8_t>(a[l] & ((1 << final_bits) - 1));

    for (uint32_t k = 0; k < codimension / 8; ++k) {
      x[l] ^= static_cast<uint8_t>(b[k] << final_bits);
      ++l;
      x[l] = static_cast<uint8_t>(b[k] >>(8 - final_bits));
    }
    x[l] ^= static_cast<uint8_t>(b[codimension/8] << final_bits);
  }

  return x;
}

secure_vector<uint8_t> mult_by_pubkey(const secure_vector<uint8_t>& cleartext,
                                      std::vector<uint8_t> const& public_matrix,
                                      uint32_t code_length, uint32_t t) {
  const uint32_t ext_deg = ceil_log2(code_length);
  const uint32_t codimension = ext_deg * t;
  const uint32_t dimension = code_length - codimension;
  secure_vector<uint8_t> cR(bit_size_to_32bit_size(codimension) * sizeof(uint32_t));

  const uint8_t* pt = public_matrix.data();

  for (size_t i = 0; i < dimension / 8; ++i) {
    for (size_t j = 0; j < 8; ++j) {
      if (cleartext[i] & (1 << j)) {
        xor_buf(cR.data(), pt, cR.size());
      }
      pt += cR.size();
    }
  }

  for (size_t i = 0; i < dimension % 8 ; ++i) {
    if (cleartext[dimension/8] & (1 << i)) {
      xor_buf(cR.data(), pt, cR.size());
    }
    pt += cR.size();
  }

  secure_vector<uint8_t> ciphertext = concat_vectors(cleartext, cR, dimension, codimension);
  ciphertext.resize((code_length+7)/8);
  return ciphertext;
}

secure_vector<uint8_t> create_random_error_vector(unsigned code_length,
    unsigned error_weight,
    RandomNumberGenerator& rng) {
  secure_vector<uint8_t> result((code_length+7)/8);

  size_t bits_set = 0;

  while (bits_set < error_weight) {
    gf2m x = random_code_element(code_length, rng);

    const size_t byte_pos = x / 8, bit_pos = x % 8;

    const uint8_t mask = (1 << bit_pos);

    if (result[byte_pos] & mask) {
      continue;  // already set this bit
    }

    result[byte_pos] |= mask;
    bits_set++;
  }

  return result;
}

}

void mceliece_encrypt(secure_vector<uint8_t>& ciphertext_out,
                      secure_vector<uint8_t>& error_mask_out,
                      const secure_vector<uint8_t>& plaintext,
                      const McEliece_PublicKey& key,
                      RandomNumberGenerator& rng) {
  secure_vector<uint8_t> error_mask = create_random_error_vector(key.get_code_length(), key.get_t(), rng);

  secure_vector<uint8_t> ciphertext = mult_by_pubkey(plaintext, key.get_public_matrix(),
                                      key.get_code_length(), key.get_t());

  ciphertext ^= error_mask;

  ciphertext_out.swap(ciphertext);
  error_mask_out.swap(error_mask);
}

}
