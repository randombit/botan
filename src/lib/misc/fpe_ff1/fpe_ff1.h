/*
* Format Preserving Encryption (FF1 from NIST SP 800-38G)
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_FPE_FF1_H_
#define BOTAN_FPE_FF1_H_

#include <botan/sym_algo.h>
#include <memory>
#include <span>

namespace Botan {

class BlockCipher;

/**
* Format Preserving Encryption using FF1 from NIST SP 800-38G, with AES
*
* FF1 encrypts a string of numerals, each in the range [0,radix), producing
* another string of numerals in the same radix and of the same length.
*
* The key can be 16, 24 or 32 bytes, selecting AES-128, AES-192 or AES-256.
*/
class BOTAN_PUBLIC_API(3, 15) FPE_FF1 final : public SymmetricAlgorithm {
   public:
      /**
      * Create an FF1 format preserving encryption object
      * @param radix the base of the numerals, which must be in [2,65536]
      */
      explicit FPE_FF1(size_t radix);

      ~FPE_FF1() override;

      FPE_FF1(const FPE_FF1& other) = delete;
      FPE_FF1(FPE_FF1&& other) noexcept;
      FPE_FF1& operator=(const FPE_FF1& other) = delete;
      FPE_FF1& operator=(FPE_FF1&& other) = delete;

      Key_Length_Specification key_spec() const override;

      bool has_keying_material() const override;

      std::string name() const override;

      void clear() override;

      /**
      * Return the radix
      */
      size_t radix() const { return m_radix; }

      /**
      * Return the length of the shortest numeral string that is accepted
      *
      * This is the smallest length such that there are at least one
      * million possible inputs, as required by SP 800-38G Rev 1.
      */
      size_t minimum_length() const { return m_min_length; }

      /**
      * Encrypt a numeral string in place
      * @param x the numerals to encrypt, each of which must be less than radix
      * @param tweak a (possibly empty) public value which modifies the encryption
      */
      void encrypt(std::span<uint16_t> x, std::span<const uint8_t> tweak) const;

      /**
      * Decrypt a numeral string in place
      * @param x the numerals to decrypt, each of which must be less than radix
      * @param tweak must match the value used to encrypt
      */
      void decrypt(std::span<uint16_t> x, std::span<const uint8_t> tweak) const;

   private:
      void key_schedule(std::span<const uint8_t> key) override;

      void crypt(std::span<uint16_t> x, std::span<const uint8_t> tweak, bool encrypting) const;

      std::unique_ptr<BlockCipher> m_cipher;
      size_t m_radix;
      size_t m_min_length;
};

}  // namespace Botan

#endif
