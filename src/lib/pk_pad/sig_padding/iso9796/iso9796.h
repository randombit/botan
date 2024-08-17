/*
 * ISO-9796-2 - Digital signature schemes giving message recovery schemes 2 and 3
 * (C) 2016 Tobias Niemann, Hackmanit GmbH
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_ISO9796_H_
#define BOTAN_ISO9796_H_

#include <botan/internal/sig_padding.h>
#include <memory>
#include <string>
#include <vector>

namespace Botan {

class HashFunction;
class PK_Signature_Options;

/**
* ISO-9796-2 - Digital signature scheme 2 (probabilistic)
*/
class ISO_9796_DS2 final : public SignaturePaddingScheme {
   public:
      explicit ISO_9796_DS2(const PK_Signature_Options& options);

      std::string hash_function() const override;

      std::string name() const override;

   private:
      void update(const uint8_t input[], size_t length) override;

      std::vector<uint8_t> raw_data() override;

      std::vector<uint8_t> encoding_of(std::span<const uint8_t> msg,
                                       size_t output_bits,
                                       RandomNumberGenerator& rng) override;

      bool verify(std::span<const uint8_t> coded, std::span<const uint8_t> raw, size_t key_bits) override;

      std::unique_ptr<HashFunction> m_hash;
      bool m_implicit;
      size_t m_salt_len;
      std::vector<uint8_t> m_msg_buffer;
};

/**
* ISO-9796-2 - Digital signature scheme 3 (deterministic)
*/
class ISO_9796_DS3 final : public SignaturePaddingScheme {
   public:
      explicit ISO_9796_DS3(const PK_Signature_Options& options);

      std::string name() const override;

      std::string hash_function() const override;

   private:
      void update(const uint8_t input[], size_t length) override;

      std::vector<uint8_t> raw_data() override;

      std::vector<uint8_t> encoding_of(std::span<const uint8_t> msg,
                                       size_t output_bits,
                                       RandomNumberGenerator& rng) override;

      bool verify(std::span<const uint8_t> coded, std::span<const uint8_t> raw, size_t key_bits) override;

      std::unique_ptr<HashFunction> m_hash;
      bool m_implicit;
      std::vector<uint8_t> m_msg_buffer;
};

}  // namespace Botan

#endif
