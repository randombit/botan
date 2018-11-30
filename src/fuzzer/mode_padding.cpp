/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"
#include <botan/mode_pad.h>
#include <botan/internal/tls_cbc.h>

namespace {

size_t ref_pkcs7_unpad(const uint8_t in[], size_t len)
   {
   if(len <= 2)
      return len;

   const size_t padding_length = in[len-1];

   if(padding_length == 0 || padding_length > len)
      return len;

   const size_t padding_start = len - padding_length;

   for(size_t i = padding_start; i != len; ++i)
      {
      if(in[i] != padding_length)
         return len;
      }

   return len - padding_length;
   }

size_t ref_x923_unpad(const uint8_t in[], size_t len)
   {
   if(len <= 2)
      return len;

   const size_t padding_length = in[len-1];

   if(padding_length == 0 || padding_length > len)
      return len;
   const size_t padding_start = len - padding_length;

   for(size_t i = padding_start; i != len - 1; ++i)
      {
      if(in[i] != 0)
         {
         return len;
         }
      }

   return len - padding_length;
   }

size_t ref_oneandzero_unpad(const uint8_t in[], size_t len)
   {
   if(len <= 2)
      return len;

   size_t idx = len - 1;

   for(;;)
      {
      if(in[idx] == 0)
         {
         if(idx == 0)
            return len;
         idx -= 1;
         continue;
         }
      else if(in[idx] == 0x80)
         {
         return idx;
         }
      else
         return len;
      }

   return len;
   }

size_t ref_esp_unpad(const uint8_t in[], size_t len)
   {
   if(len <= 2)
      return len;

   const size_t padding_bytes = in[len - 1];

   if(padding_bytes == 0 || padding_bytes > len)
      {
      return len;
      }

   const size_t padding_start = len - padding_bytes;
   for(size_t i = padding_start; i != len; ++i)
      {
      if(in[i] != (i - padding_start + 1))
         {
         return len;
         }
      }

   return len - padding_bytes;
   }

uint16_t ref_tls_cbc_unpad(const uint8_t in[], size_t len)
   {
   if(len == 0)
      return 0;

   const size_t padding_length = in[(len-1)];

   if(padding_length >= len)
      return 0;

   /*
   * TLS v1.0 and up require all the padding bytes be the same value
   * and allows up to 255 bytes.
   */
   for(size_t i = 0; i != 1 + padding_length; ++i)
      {
      if(in[(len-i-1)] != padding_length)
         return 0;
      }
   return padding_length + 1;
   }

}

void fuzz(const uint8_t in[], size_t len)
   {
   static Botan::PKCS7_Padding pkcs7;
   static Botan::ANSI_X923_Padding x923;
   static Botan::OneAndZeros_Padding oneandzero;
   static Botan::ESP_Padding esp;

   if(pkcs7.valid_blocksize(len))
      {
      const size_t ct_pkcs7 = pkcs7.unpad(in, len);
      const size_t ref_pkcs7 = ref_pkcs7_unpad(in, len);
      FUZZER_ASSERT_EQUAL(ct_pkcs7, ref_pkcs7);
      }

   if(x923.valid_blocksize(len))
      {
      const size_t ct_x923 = x923.unpad(in, len);
      const size_t ref_x923 = ref_x923_unpad(in, len);
      FUZZER_ASSERT_EQUAL(ct_x923, ref_x923);
      }

   if(oneandzero.valid_blocksize(len))
      {
      const size_t ct_oneandzero = oneandzero.unpad(in, len);
      const size_t ref_oneandzero = ref_oneandzero_unpad(in, len);
      FUZZER_ASSERT_EQUAL(ct_oneandzero, ref_oneandzero);
      }

   if(esp.valid_blocksize(len))
      {
      const size_t ct_esp = esp.unpad(in, len);
      const size_t ref_esp = ref_esp_unpad(in, len);
      FUZZER_ASSERT_EQUAL(ct_esp, ref_esp);
      }

   const uint16_t ct_cbc = Botan::TLS::check_tls_cbc_padding(in, len);
   const uint16_t ref_cbc = ref_tls_cbc_unpad(in, len);
   FUZZER_ASSERT_EQUAL(ct_cbc, ref_cbc);
   }
