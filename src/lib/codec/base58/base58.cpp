/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/base58.h>
#include <botan/exceptn.h>
#include <botan/bigint.h>
#include <botan/divide.h>
#include <botan/loadstor.h>
#include <botan/hash.h>

namespace Botan {

namespace {

uint32_t sha256_d_checksum(const uint8_t input[], size_t input_length)
   {
   std::unique_ptr<HashFunction> sha256 = HashFunction::create_or_throw("SHA-256");

   std::vector<uint8_t> checksum(32);

   sha256->update(input, input_length);
   sha256->final(checksum);

   sha256->update(checksum);
   sha256->final(checksum);

   return load_be<uint32_t>(checksum.data(), 0);
   }

class Character_Table
   {
   public:
      // This must be a literal constant
      Character_Table(const char* alphabet) :
         m_alphabet(alphabet)
         {
         const size_t alpha_len = std::strlen(alphabet);

         // 128 or up would flow into 0x80 invalid bit
         if(alpha_len == 0 || alpha_len >= 128)
            throw Invalid_Argument("Bad Character_Table string");

         m_alphabet_len = static_cast<uint8_t>(alpha_len);

         set_mem(m_tab, 256, 0x80);

         for(size_t i = 0; m_alphabet[i]; ++i)
            {
            const uint8_t b = static_cast<uint8_t>(m_alphabet[i]);
            BOTAN_ASSERT(m_tab[b] == 0x80, "No duplicate chars");
            m_tab[b] = static_cast<uint8_t>(i);
            }
         }

      uint8_t radix() const { return m_alphabet_len; }

      char operator[](size_t i) const
         {
         BOTAN_ASSERT(i < m_alphabet_len, "Character in range");
         return m_alphabet[i];
         }

      uint8_t code_for(char c) const
         {
         return m_tab[static_cast<uint8_t>(c)];
         }

   private:
      const char* m_alphabet;
      uint8_t m_alphabet_len;
      uint8_t m_tab[256];
   };

static const Character_Table& BASE58_ALPHA()
   {
   static const Character_Table base58_alpha("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz");
   return base58_alpha;
   }

std::string base58_encode(BigInt v, size_t leading_zeros)
   {
   const auto base58 = BASE58_ALPHA();

   std::string result;
   BigInt q;
   uint8_t r;

   while(v.is_nonzero())
      {
      ct_divide_u8(v, base58.radix(), q, r);
      result.push_back(base58[r]);
      v.swap(q);
      }

   for(size_t i = 0; i != leading_zeros; ++i)
      result.push_back(base58[0]);

   return std::string(result.rbegin(), result.rend());
   }

template<typename T, typename Z>
size_t count_leading_zeros(const T input[], size_t input_length, Z zero)
   {
   size_t leading_zeros = 0;

   while(leading_zeros < input_length && input[leading_zeros] == zero)
      leading_zeros += 1;

   return leading_zeros;
   }

}

std::string base58_encode(const uint8_t input[], size_t input_length)
   {
   BigInt v(input, input_length);
   return base58_encode(v, count_leading_zeros(input, input_length, 0));
   }

std::string base58_check_encode(const uint8_t input[], size_t input_length)
   {
   BigInt v(input, input_length);
   v <<= 32;
   v += sha256_d_checksum(input, input_length);
   return base58_encode(v, count_leading_zeros(input, input_length, 0));
   }

std::vector<uint8_t> base58_decode(const char input[], size_t input_length)
   {
   const auto base58 = BASE58_ALPHA();

   const size_t leading_zeros = count_leading_zeros(input, input_length, base58[0]);

   BigInt v;

   for(size_t i = leading_zeros; i != input_length; ++i)
      {
      const char c = input[i];

      if(c == ' ' || c == '\n')
         continue;

      const size_t idx = base58.code_for(c);

      if(idx == 0x80)
         throw Decoding_Error("Invalid base58");

      v *= base58.radix();
      v += idx;
      }

   std::vector<uint8_t> output(v.bytes() + leading_zeros);
   v.binary_encode(output.data() + leading_zeros);
   return output;
   }

std::vector<uint8_t> base58_check_decode(const char input[], size_t input_length)
   {
   std::vector<uint8_t> dec = base58_decode(input, input_length);

   if(dec.size() < 4)
      throw Decoding_Error("Invalid base58 too short for checksum");

   const uint32_t computed_checksum = sha256_d_checksum(dec.data(), dec.size() - 4);
   const uint32_t checksum = load_be<uint32_t>(&dec[dec.size()-4], 0);

   if(checksum != computed_checksum)
      throw Decoding_Error("Invalid base58 checksum");

   dec.resize(dec.size() - 4);

   return dec;
   }

}
