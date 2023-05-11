/*
* SHA-{384,512}
* (C) 1999-2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SHA_64BIT_H_
#define BOTAN_SHA_64BIT_H_

#include <botan/hash.h>
#include <botan/internal/mdx_hash.h>

namespace Botan {

/**
* SHA-512
*/
class SHA_512 final : public HashFunction
   {
   public:
      SHA_512() {}

      std::string name() const override { return "SHA-512"; }
      size_t output_length() const override { return 64; }
      size_t hash_block_size() const override { return 128; }

      std::unique_ptr<HashFunction> new_object() const override;
      std::unique_ptr<HashFunction> copy_state() const override;
      std::string provider() const override;

      void clear() override;

      /*
      * Perform a SHA-512 compression. For internal use
      */
      static void compress_digest(uint64_t digest[8],
                                  const uint8_t input[],
                                  size_t blocks);
   private:
      void add_data(const uint8_t input[], size_t length) override;
      void final_result(uint8_t output[]) override;

      static void init(uint64_t digest[8]);

      static const uint64_t K[80];

#if defined(BOTAN_HAS_SHA2_64_BMI2)
      static void compress_digest_bmi2(uint64_t digest[8],
                                       const uint8_t input[],
                                       size_t blocks);
#endif

      MD_Hash<MD_Endian::Big, uint64_t, 16,
              SHA_512::init, SHA_512::compress_digest, 128, 64, 16> m_md;
   };

/**
* SHA-384
*/
class SHA_384 final : public HashFunction
   {
   public:
      SHA_384() {}

      std::string name() const override { return "SHA-384"; }
      size_t output_length() const override { return 48; }
      size_t hash_block_size() const override { return 128; }

      std::unique_ptr<HashFunction> new_object() const override;
      std::unique_ptr<HashFunction> copy_state() const override;
      std::string provider() const override;

      void clear() override;
   private:
      void add_data(const uint8_t input[], size_t length) override;
      void final_result(uint8_t output[]) override;

      static void init(uint64_t digest[8]);

      MD_Hash<MD_Endian::Big, uint64_t, 16,
              SHA_384::init, SHA_512::compress_digest, 128, 48, 16> m_md;
   };

/**
* SHA-512/256
*/
class SHA_512_256 final : public HashFunction
   {
   public:
      SHA_512_256() {}

      std::string name() const override { return "SHA-512-256"; }
      size_t output_length() const override { return 32; }
      size_t hash_block_size() const override { return 128; }

      std::unique_ptr<HashFunction> new_object() const override;
      std::unique_ptr<HashFunction> copy_state() const override;
      std::string provider() const override;

      void clear() override;
   private:
      void add_data(const uint8_t input[], size_t length) override;
      void final_result(uint8_t output[]) override;

      static void init(uint64_t digest[8]);

      MD_Hash<MD_Endian::Big, uint64_t, 16,
              SHA_512_256::init, SHA_512::compress_digest, 128, 32, 16> m_md;
   };

}

#endif
