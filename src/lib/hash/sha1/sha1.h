/*
* SHA-1
* (C) 1999-2007,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SHA1_H_
#define BOTAN_SHA1_H_

#include <botan/internal/mdx_hash.h>

namespace Botan {

/**
* NIST's SHA-1
*/
class SHA_1 final : public MDx_HashFunction {
   public:
      std::string name() const override { return "SHA-1"; }

      size_t output_length() const override { return 20; }

      std::unique_ptr<HashFunction> new_object() const override { return std::make_unique<SHA_1>(); }

      std::unique_ptr<HashFunction> copy_state() const override;

      std::string provider() const override;

      void clear() override;

      SHA_1() : MDx_HashFunction(64, true, true), m_digest(5) { clear(); }

   private:
      void compress_n(const uint8_t[], size_t blocks) override;

#if defined(BOTAN_HAS_SHA1_ARMV8)
      static void sha1_armv8_compress_n(secure_vector<uint32_t>& digest, const uint8_t blocks[], size_t block_count);
#endif

#if defined(BOTAN_HAS_SHA1_SSE2)
      static void sse2_compress_n(secure_vector<uint32_t>& digest, const uint8_t blocks[], size_t block_count);
#endif

#if defined(BOTAN_HAS_SHA1_X86_SHA_NI)
      // Using x86 SHA instructions in Intel Goldmont and Cannonlake
      static void sha1_compress_x86(secure_vector<uint32_t>& digest, const uint8_t blocks[], size_t block_count);
#endif

      void copy_out(uint8_t[]) override;

      /**
      * The digest value
      */
      secure_vector<uint32_t> m_digest;

      /**
      * The message buffer
      */
      secure_vector<uint32_t> m_W;
};

}  // namespace Botan

#endif
