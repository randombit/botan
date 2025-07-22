/*
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_X931_SIGNATURE_PADDING_SCHEME_H_
#define BOTAN_X931_SIGNATURE_PADDING_SCHEME_H_

#include <botan/internal/sig_padding.h>

namespace Botan {

class HashFunction;

/**
* Padding scheme from X9.31 (aka EMSA2 in IEEE 1363)
*
* Historically used for signature padding with Rabin-Williams,
* which is not implemented by Botan anymore.
*
* Sometimes used with RSA in odd protocols.
*/
class X931_SignaturePadding final : public SignaturePaddingScheme {
   public:
      /**
      * @param hash the hash function to use
      */
      explicit X931_SignaturePadding(std::unique_ptr<HashFunction> hash);

      std::string name() const override;

      std::string hash_function() const override;

   private:
      void update(const uint8_t input[], size_t length) override;
      std::vector<uint8_t> raw_data() override;

      std::vector<uint8_t> encoding_of(std::span<const uint8_t> raw,
                                       size_t key_bits,
                                       RandomNumberGenerator& rng) override;

      bool verify(std::span<const uint8_t> coded, std::span<const uint8_t> raw, size_t key_bits) override;

      std::vector<uint8_t> m_empty_hash;
      std::unique_ptr<HashFunction> m_hash;
      uint8_t m_hash_id;
};

}  // namespace Botan

#endif
