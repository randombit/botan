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

   private:
      void add_data(const uint8_t input[], size_t length) override;
      void final_result(uint8_t output[]) override;

   public:
      using digest_type = std::array<uint64_t, 16>;
      static constexpr MD_Endian ENDIAN = MD_Endian::Big;
      static constexpr size_t BLOCK_BYTES = 128;
      static constexpr size_t FINAL_DIGEST_BYTES = 64;
      static constexpr size_t CTR_BYTES = 16;

      /*
      * Perform a SHA-512 compression. For internal use
      */
      static void compress_n(digest_type& digest, const uint8_t input[], size_t blocks);
      static void init(digest_type& digest);

   private:
      static const uint64_t K[80];

#if defined(BOTAN_HAS_SHA2_64_BMI2)
      static void compress_digest_bmi2(uint64_t digest[8],
                                       const uint8_t input[],
                                       size_t blocks);
#endif

      MD_Hash<SHA_512> m_md;
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

   public:
      using digest_type = std::array<uint64_t, 16>;
      static constexpr MD_Endian ENDIAN = MD_Endian::Big;
      static constexpr size_t BLOCK_BYTES = 128;
      static constexpr size_t FINAL_DIGEST_BYTES = 48;
      static constexpr size_t CTR_BYTES = 16;

      /*
      * Perform a SHA-512 compression. For internal use
      */
      static void compress_n(digest_type& digest, const uint8_t input[], size_t blocks)
         { SHA_512::compress_n(digest, input, blocks); }
      static void init(digest_type& digest);

   private:
      MD_Hash<SHA_384> m_md;
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

   public:
      using digest_type = std::array<uint64_t, 16>;
      static constexpr MD_Endian ENDIAN = MD_Endian::Big;
      static constexpr size_t BLOCK_BYTES = 128;
      static constexpr size_t FINAL_DIGEST_BYTES = 32;
      static constexpr size_t CTR_BYTES = 16;

      /*
      * Perform a SHA-512 compression. For internal use
      */
      static void compress_n(digest_type& digest, const uint8_t input[], size_t blocks)
         { SHA_512::compress_n(digest, input, blocks); }
      static void init(digest_type& digest);

   private:
      MD_Hash<SHA_512_256> m_md;
   };

}

#endif
