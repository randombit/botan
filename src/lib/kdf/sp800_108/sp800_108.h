/*
* KDFs defined in NIST SP 800-108
* (C) 2016 Kai Michaelis
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SP800_108_H_
#define BOTAN_SP800_108_H_

#include <botan/kdf.h>
#include <botan/mac.h>

namespace Botan {

/**
 * NIST SP 800-108 KDF in Counter Mode (5.1)
 */
class SP800_108_Counter final : public KDF {
   public:
      std::string name() const override;

      std::unique_ptr<KDF> new_object() const override;

      /**
      * @param mac MAC algorithm to use
      * @param r  encoding bit-length of the internal counter {8, 16, 24, or 32}
      * @param L  encoding bit-length of the output length in bits {8, 16, 24, or 32}
      */
      SP800_108_Counter(std::unique_ptr<MessageAuthenticationCode> mac, size_t r, size_t L);

   private:
      /**
      * Derive a key using the SP800-108 KDF in Counter mode.
      *
      * The implementation hard codes the length of [L]_2
      * and [i]_2 (the value r) to 32 bits.
      *
      * @param key resulting keying material
      * @param secret K_I
      * @param salt Context
      * @param label Label
      *
      * @throws Invalid_Argument key_len > 2^32
      */
      void perform_kdf(std::span<uint8_t> key,
                       std::span<const uint8_t> secret,
                       std::span<const uint8_t> salt,
                       std::span<const uint8_t> label) const override;

   private:
      std::unique_ptr<MessageAuthenticationCode> m_prf;
      size_t m_counter_bits;
      size_t m_output_length_bits;
};

/**
 * NIST SP 800-108 KDF in Feedback Mode (5.2)
 */
class SP800_108_Feedback final : public KDF {
   public:
      std::string name() const override;

      std::unique_ptr<KDF> new_object() const override;

      /**
      * @param mac MAC algorithm to use
      * @param r  encoding bit-length of the internal counter {8, 16, 24, or 32}
      * @param L  encoding bit-length of the output length in bits {8, 16, 24, or 32}
      */
      SP800_108_Feedback(std::unique_ptr<MessageAuthenticationCode> mac, size_t r, size_t L);

   private:
      /**
      * Derive a key using the SP800-108 KDF in Feedback mode.
      *
      * The implementation uses the optional counter i and hard
      * codes the length of [L]_2 and [i]_2 (the value r) to 32 bits.
      *
      * @param key resulting keying material
      * @param secret K_I
      * @param salt IV || Context
      * @param label Label
      *
      * @throws Invalid_Argument key_len > 2^32
      */
      void perform_kdf(std::span<uint8_t> key,
                       std::span<const uint8_t> secret,
                       std::span<const uint8_t> salt,
                       std::span<const uint8_t> label) const override;

   private:
      std::unique_ptr<MessageAuthenticationCode> m_prf;
      size_t m_counter_bits;
      size_t m_output_length_bits;
};

/**
 * NIST SP 800-108 KDF in Double Pipeline Mode (5.3)
 */
class SP800_108_Pipeline final : public KDF {
   public:
      std::string name() const override;

      std::unique_ptr<KDF> new_object() const override;

      /**
      * @param mac MAC algorithm to use
      * @param r  encoding bit-length of the internal counter {8, 16, 24, or 32}
      * @param L  encoding bit-length of the output length in bits {8, 16, 24, or 32}
      */
      SP800_108_Pipeline(std::unique_ptr<MessageAuthenticationCode> mac, size_t r, size_t L);

   private:
      /**
      * Derive a key using the SP800-108 KDF in Double Pipeline mode.
      *
      * The implementation uses the optional counter i and hard
      * codes the length of [L]_2 and [i]_2 (the value r) to 32 bits.
      *
      * @param key resulting keying material
      * @param secret K_I
      * @param salt Context
      * @param label Label
      *
      * @throws Invalid_Argument key_len > 2^32
      */
      void perform_kdf(std::span<uint8_t> key,
                       std::span<const uint8_t> secret,
                       std::span<const uint8_t> salt,
                       std::span<const uint8_t> label) const override;

   private:
      std::unique_ptr<MessageAuthenticationCode> m_prf;
      size_t m_counter_bits;
      size_t m_output_length_bits;
};

}  // namespace Botan

#endif
