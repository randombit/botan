/*
* Camellia
* (C) 2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CAMELLIA_H_
#define BOTAN_CAMELLIA_H_

#include <botan/block_cipher.h>

namespace Botan {

/**
* Camellia-128
*/
class Camellia_128 final : public Block_Cipher_Fixed_Params<16, 16> {
   public:
      void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;
      void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;

      void clear() override;

      std::string name() const override { return "Camellia-128"; }

      std::unique_ptr<BlockCipher> new_object() const override { return std::make_unique<Camellia_128>(); }

      bool has_keying_material() const override;

   private:
      void key_schedule(std::span<const uint8_t> key) override;

      secure_vector<uint64_t> m_SK;
};

/**
* Camellia-192
*/
class Camellia_192 final : public Block_Cipher_Fixed_Params<16, 24> {
   public:
      void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;
      void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;

      void clear() override;

      std::string name() const override { return "Camellia-192"; }

      std::unique_ptr<BlockCipher> new_object() const override { return std::make_unique<Camellia_192>(); }

      bool has_keying_material() const override;

   private:
      void key_schedule(std::span<const uint8_t> key) override;

      secure_vector<uint64_t> m_SK;
};

/**
* Camellia-256
*/
class Camellia_256 final : public Block_Cipher_Fixed_Params<16, 32> {
   public:
      void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;
      void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override;

      void clear() override;

      std::string name() const override { return "Camellia-256"; }

      std::unique_ptr<BlockCipher> new_object() const override { return std::make_unique<Camellia_256>(); }

      bool has_keying_material() const override;

   private:
      void key_schedule(std::span<const uint8_t> key) override;

      secure_vector<uint64_t> m_SK;
};

}  // namespace Botan

#endif
