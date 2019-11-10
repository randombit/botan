/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include "fuzzers.h"

#include <botan/oaep.h>
#include <botan/hex.h>

namespace {

Botan::secure_vector<uint8_t>
ref_oaep_unpad(uint8_t& valid_mask,
               const uint8_t in[], size_t len,
               const Botan::secure_vector<uint8_t>& Phash)
   {
   const size_t hlen = Phash.size();

   if(len < 2*hlen + 1)
      {
      return Botan::secure_vector<uint8_t>();
      }

   for(size_t i = hlen; i != 2*hlen; ++i)
      {
      if(in[i] != Phash[i-hlen])
         {
         return Botan::secure_vector<uint8_t>();
         }
      }

   for(size_t i = 2*hlen; i != len; ++i)
      {
      if(in[i] != 0x00 && in[i] != 0x01)
         {
         return Botan::secure_vector<uint8_t>();
         }

      if(in[i] == 0x01)
         {
         valid_mask = 0xFF;
         return Botan::secure_vector<uint8_t>(in + i + 1, in + len);
         }
      }

   return Botan::secure_vector<uint8_t>();
   }

inline bool all_zeros(const Botan::secure_vector<uint8_t>& v)
   {
   for(size_t i = 0; i != v.size(); ++i)
      {
      if(v[i] != 0)
         return false;
      }
   return true;
   }

}

void fuzz(const uint8_t in[], size_t len)
   {
   static const Botan::secure_vector<uint8_t> Phash = { 1, 2, 3, 4 };

   uint8_t lib_valid_mask = 0;
   const Botan::secure_vector<uint8_t> lib_output = Botan::oaep_find_delim(lib_valid_mask, in, len, Phash);
   FUZZER_ASSERT_TRUE(lib_valid_mask == 0 || lib_valid_mask == 0xFF);

   uint8_t ref_valid_mask = 0;
   const Botan::secure_vector<uint8_t> ref_output = ref_oaep_unpad(ref_valid_mask, in, len, Phash);
   FUZZER_ASSERT_TRUE(ref_valid_mask == 0 || ref_valid_mask == 0xFF);

   if(ref_valid_mask == 0xFF && lib_valid_mask == 0x00)
      {
      FUZZER_WRITE_AND_CRASH("Ref accepted but library rejected, output " << Botan::hex_encode(ref_output) << "\n");
      }
   else if(ref_valid_mask == 0x00 && lib_valid_mask == 0xFF)
      {
      FUZZER_WRITE_AND_CRASH("Lib accepted but ref rejected, output = " << Botan::hex_encode(lib_output) << "\n");
      }

   if(ref_valid_mask == 0x00)
      {
      FUZZER_ASSERT_TRUE(all_zeros(ref_output));
      }

   if(lib_valid_mask == 0x00)
      {
      FUZZER_ASSERT_TRUE(all_zeros(lib_output));
      }

   if(ref_valid_mask && lib_valid_mask)
      {
      if(ref_output != lib_output)
         {
         FUZZER_WRITE_AND_CRASH("Ref and lib both accepted but produced different output:"
                                << " ref = " << Botan::hex_encode(ref_output)
                                << " lib = " << Botan::hex_encode(lib_output));
         }
      }
   }
