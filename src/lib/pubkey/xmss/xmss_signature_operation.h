/*
 * XMSS Signature Operation
 * (C) 2016,2017,2018 Matthias Gierlings
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_XMSS_SIGNATURE_OPERATION_H_
#define BOTAN_XMSS_SIGNATURE_OPERATION_H_

#include <botan/pk_ops.h>
#include <botan/xmss.h>
#include <botan/internal/xmss_address.h>
#include <botan/internal/xmss_hash.h>
#include <botan/internal/xmss_signature.h>
#include <botan/internal/xmss_wots.h>

namespace Botan {

/**
 * Signature generation operation for Extended Hash-Based Signatures (XMSS) as
 * defined in:
 *
 * [1] XMSS: Extended Hash-Based Signatures,
 *     Request for Comments: 8391
 *     Release: May 2018.
 *     https://datatracker.ietf.org/doc/rfc8391/
 **/
class XMSS_Signature_Operation final : public virtual PK_Ops::Signature {
   public:
      explicit XMSS_Signature_Operation(const XMSS_PrivateKey& private_key);

      /**
       * Creates an XMSS signature for the message provided through call to
       * update().
       *
       * @return serialized XMSS signature.
       **/
      std::vector<uint8_t> sign(RandomNumberGenerator& rng) override;

      void update(std::span<const uint8_t> input) override;

      size_t signature_length() const override;

      AlgorithmIdentifier algorithm_identifier() const override;

      std::string hash_function() const override { return m_hash.hash_function(); }

   private:
      void initialize();

      XMSS_PrivateKey m_priv_key;
      XMSS_Hash m_hash;
      secure_vector<uint8_t> m_randomness;
      uint32_t m_leaf_idx;
      bool m_is_initialized;
};

}  // namespace Botan

#endif
