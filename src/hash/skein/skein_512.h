/*
* The Skein-512 hash function
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_SKEIN_512_H__
#define BOTAN_SKEIN_512_H__

#include <botan/secmem.h>
#include <botan/hash.h>
#include <string>

namespace Botan {

/**
* Skein-512, a SHA-3 candidate
*/
class BOTAN_DLL Skein_512 : public HashFunction
   {
   public:
      /**
      * @param output_bits the output size of Skein in bits
      * @param personalization is a string that will paramaterize the
      * hash output
      */
      Skein_512(size_t output_bits = 512,
                const std::string& personalization = "");

      size_t hash_block_size() const { return 64; }
      size_t output_length() const { return output_bits / 8; }

      HashFunction* clone() const;
      std::string name() const;
      void clear();
   private:
      void add_data(const byte input[], size_t length);
      void final_result(byte out[]);

      std::string personalization;
      size_t output_bits;

      SecureVector<u64bit> H;
      SecureVector<u64bit> T;
      SecureVector<byte> buffer;
      size_t buf_pos;
   };

}

#endif
