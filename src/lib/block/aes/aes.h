/*
* AES
* (C) 1999-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_AES_H_
#define BOTAN_AES_H_

#include <botan/block_cipher.h>

namespace Botan {

/**
* AES-128
*/
class AES_128 final : public Block_Cipher_Fixed_Params<16, 16> {
   public:
      void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;
      void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;

      void clear() override;

      std::string provider() const override;

      std::string name() const override { return "AES-128"; }

      std::unique_ptr<BlockCipher> new_object() const override { return std::make_unique<AES_128>(); }

      size_t parallelism() const override;

      bool has_keying_material() const override;

   private:
      void key_schedule(std::span<const uint8_t> key) override;

#if defined(BOTAN_HAS_AES_VPERM)
      void vperm_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const;
      void vperm_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const;
      void vperm_key_schedule(const uint8_t key[], size_t length);
#endif

#if defined(BOTAN_HAS_AES_NI)
      void aesni_key_schedule(const uint8_t key[], size_t length);
#endif

#if defined(BOTAN_HAS_AES_POWER8) || defined(BOTAN_HAS_AES_ARMV8) || defined(BOTAN_HAS_AES_NI)
      void hw_aes_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const;
      void hw_aes_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const;
#endif

#if defined(BOTAN_HAS_AES_VAES)
      void x86_vaes_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const;
      void x86_vaes_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const;
#endif

      secure_vector<uint32_t> m_EK, m_DK;
};

/**
* AES-192
*/
class AES_192 final : public Block_Cipher_Fixed_Params<16, 24> {
   public:
      void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;
      void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;

      void clear() override;

      std::string provider() const override;

      std::string name() const override { return "AES-192"; }

      std::unique_ptr<BlockCipher> new_object() const override { return std::make_unique<AES_192>(); }

      size_t parallelism() const override;
      bool has_keying_material() const override;

   private:
#if defined(BOTAN_HAS_AES_VPERM)
      void vperm_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const;
      void vperm_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const;
      void vperm_key_schedule(const uint8_t key[], size_t length);
#endif

#if defined(BOTAN_HAS_AES_NI)
      void aesni_key_schedule(const uint8_t key[], size_t length);
#endif

#if defined(BOTAN_HAS_AES_POWER8) || defined(BOTAN_HAS_AES_ARMV8) || defined(BOTAN_HAS_AES_NI)
      void hw_aes_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const;
      void hw_aes_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const;
#endif

#if defined(BOTAN_HAS_AES_VAES)
      void x86_vaes_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const;
      void x86_vaes_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const;
#endif

      void key_schedule(std::span<const uint8_t> key) override;

      secure_vector<uint32_t> m_EK, m_DK;
};

/**
* AES-256
*/
class AES_256 final : public Block_Cipher_Fixed_Params<16, 32> {
   public:
      void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;
      void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;

      void clear() override;

      std::string provider() const override;

      std::string name() const override { return "AES-256"; }

      std::unique_ptr<BlockCipher> new_object() const override { return std::make_unique<AES_256>(); }

      size_t parallelism() const override;
      bool has_keying_material() const override;

   private:
#if defined(BOTAN_HAS_AES_VPERM)
      void vperm_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const;
      void vperm_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const;
      void vperm_key_schedule(const uint8_t key[], size_t length);
#endif

#if defined(BOTAN_HAS_AES_NI)
      void aesni_key_schedule(const uint8_t key[], size_t length);
#endif

#if defined(BOTAN_HAS_AES_POWER8) || defined(BOTAN_HAS_AES_ARMV8) || defined(BOTAN_HAS_AES_NI)
      void hw_aes_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const;
      void hw_aes_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const;
#endif

#if defined(BOTAN_HAS_AES_VAES)
      void x86_vaes_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const;
      void x86_vaes_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const;
#endif

      void key_schedule(std::span<const uint8_t> key) override;

      secure_vector<uint32_t> m_EK, m_DK;
};

}  // namespace Botan

#endif
