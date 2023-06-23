/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"

#include <botan/hex.h>
#include <botan/internal/eme_pkcs.h>

namespace {

std::vector<uint8_t> simple_pkcs1_unpad(const uint8_t in[], size_t len) {
   if(len < 10) {
      throw Botan::Decoding_Error("bad len");
   }

   if(in[0] != 0 || in[1] != 2) {
      throw Botan::Decoding_Error("bad header field");
   }

   for(size_t i = 2; i < len; ++i) {
      if(in[i] == 0) {
         if(i < 10) {  // at least 8 padding bytes required
            throw Botan::Decoding_Error("insufficient padding bytes");
         }
         return std::vector<uint8_t>(in + i + 1, in + len);
      }
   }

   throw Botan::Decoding_Error("delim not found");
}

}  // namespace

void fuzz(const uint8_t in[], size_t len) {
   static Botan::EME_PKCS1v15 pkcs1;

   Botan::secure_vector<uint8_t> lib_result;
   std::vector<uint8_t> ref_result;
   bool lib_rejected = false, ref_rejected = false;

   try {
      uint8_t valid_mask = 0;
      Botan::secure_vector<uint8_t> decoded = (static_cast<Botan::EME*>(&pkcs1))->unpad(valid_mask, in, len);

      if(valid_mask == 0) {
         lib_rejected = true;
      } else if(valid_mask == 0xFF) {
         lib_rejected = false;
      } else {
         FUZZER_WRITE_AND_CRASH("Invalid valid_mask from unpad");
      }
   } catch(Botan::Decoding_Error&) {
      lib_rejected = true;
   }

   try {
      ref_result = simple_pkcs1_unpad(in, len);
   } catch(Botan::Decoding_Error& e) {
      ref_rejected = true;
   }

   if(lib_rejected == true && ref_rejected == false) {
      FUZZER_WRITE_AND_CRASH("Library rejected input accepted by ref " << Botan::hex_encode(ref_result));
   } else if(ref_rejected == true && lib_rejected == false) {
      FUZZER_WRITE_AND_CRASH("Library accepted input rejected by ref " << Botan::hex_encode(lib_result));
   }
   // otherwise the two implementations agree
}
