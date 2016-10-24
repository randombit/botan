/*
* SHA-3
* (C) 2010,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SHA3_H__
#define BOTAN_SHA3_H__

#include <botan/hash.h>
#include <botan/secmem.h>
#include <string>

namespace Botan {

/**
* SHA-3
*/
class BOTAN_DLL SHA_3 : public HashFunction
   {
   public:

      /**
      * @param output_bits the size of the hash output; must be one of
      *                    224, 256, 384, or 512
      */
      SHA_3(size_t output_bits);

      /**
      * @param output_bits the size of the hash output; must be a
      * multiple of 8 (ie, byte-wide outputs)
      * @param capacity the capacity of the spong, normally always
      * 2*output_bits with SHA-3.
      */
      SHA_3(size_t output_bits, size_t capacity);

      size_t hash_block_size() const override { return m_bitrate / 8; }
      size_t output_length() const override { return m_output_bits / 8; }

      HashFunction* clone() const override;
      std::string name() const override;
      void clear() override;

      /**
      * The bare Keccak-1600 permutation
      */
      static void permute(u64bit A[25]);

   private:
      void add_data(const byte input[], size_t length) override;
      void final_result(byte out[]) override;

      size_t m_output_bits, m_bitrate;
      secure_vector<u64bit> m_S;
      size_t m_S_pos;
   };

/**
* SHA-3-224
*/
class BOTAN_DLL SHA_3_224 final : public SHA_3
   {
   public:
      SHA_3_224() : SHA_3(224) {}
   };

/**
* SHA-3-256
*/
class BOTAN_DLL SHA_3_256 final : public SHA_3
   {
   public:
      SHA_3_256() : SHA_3(256) {}
   };

/**
* SHA-3-384
*/
class BOTAN_DLL SHA_3_384 final : public SHA_3
   {
   public:
      SHA_3_384() : SHA_3(384) {}
   };

/**
* SHA-3-512
*/
class BOTAN_DLL SHA_3_512 final : public SHA_3
   {
   public:
      SHA_3_512() : SHA_3(512) {}
   };

}

#endif
