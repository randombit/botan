/*
* Blake2b
* (C) 2016 cynecx
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_BLAKE2B_H_
#define BOTAN_BLAKE2B_H_

#include <botan/hash.h>
#include <string>
#include <memory>

namespace Botan {

/**
* BLAKE2B
*/
class BOTAN_PUBLIC_API(2,0) Blake2b final : public HashFunction
   {
   public:
      /**
      * @param output_bits the output size of Blake2b in bits
      * @param key the key as hexstring
      */
      explicit Blake2b(size_t output_bits = 512, std::string key = "");

      size_t hash_block_size() const override { return 128; }
      size_t output_length() const override { return m_output_bits / 8; }

      HashFunction* clone() const override;
      std::string name() const override;
      void clear() override;

      std::unique_ptr<HashFunction> copy_state() const override;

   private:
      void add_data(const uint8_t input[], size_t length) override;
      void final_result(uint8_t out[]) override;

      void state_init(secure_vector<uint8_t> key);
      void compress(const uint8_t* data, size_t blocks, uint64_t increment);

      const size_t m_output_bits;
      const std::string m_key_hex;

      secure_vector<uint8_t> m_buffer;
      size_t m_bufpos;

      secure_vector<uint64_t> m_H;
      uint64_t m_T[2];
      uint64_t m_F[2];
   };

}

#endif
