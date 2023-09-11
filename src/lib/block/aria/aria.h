/*
* ARIA
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*
* This ARIA implementation is based on the 32-bit implementation by Aaram Yun from the
* National Security Research Institute, KOREA. Aaram Yun's implementation is based on
* the 8-bit implementation by Jin Hong. The source files are available in ARIA.zip from
* the Korea Internet & Security Agency website.
* <A HREF="https://tools.ietf.org/html/rfc5794">RFC 5794, A Description of the ARIA Encryption Algorithm</A>,
* <A HREF="http://seed.kisa.or.kr/iwt/ko/bbs/EgovReferenceList.do?bbsId=BBSMSTR_000000000002">Korea
* Internet & Security Agency homepage</A>
*/

#ifndef BOTAN_ARIA_H_
#define BOTAN_ARIA_H_

#include <botan/block_cipher.h>

namespace Botan {

/**
* ARIA-128
*/
class ARIA_128 final : public Block_Cipher_Fixed_Params<16, 16> {
   public:
      void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;
      void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;

      void clear() override;

      std::string name() const override { return "ARIA-128"; }

      std::unique_ptr<BlockCipher> new_object() const override { return std::make_unique<ARIA_128>(); }

      bool has_keying_material() const override;

   private:
      void key_schedule(std::span<const uint8_t> key) override;

      // Encryption and Decryption round keys.
      secure_vector<uint32_t> m_ERK, m_DRK;
};

/**
* ARIA-192
*/
class ARIA_192 final : public Block_Cipher_Fixed_Params<16, 24> {
   public:
      void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;
      void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;

      void clear() override;

      std::string name() const override { return "ARIA-192"; }

      std::unique_ptr<BlockCipher> new_object() const override { return std::make_unique<ARIA_192>(); }

      bool has_keying_material() const override;

   private:
      void key_schedule(std::span<const uint8_t> key) override;

      // Encryption and Decryption round keys.
      secure_vector<uint32_t> m_ERK, m_DRK;
};

/**
* ARIA-256
*/
class ARIA_256 final : public Block_Cipher_Fixed_Params<16, 32> {
   public:
      void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;
      void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;

      void clear() override;

      std::string name() const override { return "ARIA-256"; }

      std::unique_ptr<BlockCipher> new_object() const override { return std::make_unique<ARIA_256>(); }

      bool has_keying_material() const override;

   private:
      void key_schedule(std::span<const uint8_t> key) override;

      // Encryption and Decryption round keys.
      secure_vector<uint32_t> m_ERK, m_DRK;
};

}  // namespace Botan

#endif
