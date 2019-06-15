/*
* (C) 2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sodium.h>
#include <botan/salsa20.h>
#include <botan/loadstor.h>

namespace Botan {

int Sodium::crypto_core_hsalsa20(uint8_t out[], const uint8_t in[],
                                 const uint8_t key[], const uint8_t c[])
   {
   uint32_t in32[16] = { 0 };

   static const uint32_t SIGMA[] =
      { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

   if(c == nullptr)
      {
      in32[0] = SIGMA[0];
      in32[5] = SIGMA[1];
      in32[10] = SIGMA[2];
      in32[15] = SIGMA[3];
      }
   else
      {
      in32[0] = load_le<uint32_t>(c, 0);
      in32[5] = load_le<uint32_t>(c, 1);
      in32[10] = load_le<uint32_t>(c, 2);
      in32[15] = load_le<uint32_t>(c, 3);
      }

   in32[1] = load_le<uint32_t>(key, 0);
   in32[2] = load_le<uint32_t>(key, 1);
   in32[3] = load_le<uint32_t>(key, 2);
   in32[4] = load_le<uint32_t>(key, 3);

   in32[6] = load_le<uint32_t>(in, 0);
   in32[7] = load_le<uint32_t>(in, 1);
   in32[8] = load_le<uint32_t>(in, 2);
   in32[9] = load_le<uint32_t>(in, 3);

   in32[11] = load_le<uint32_t>(key, 4);
   in32[12] = load_le<uint32_t>(key, 5);
   in32[13] = load_le<uint32_t>(key, 6);
   in32[14] = load_le<uint32_t>(key, 7);

   uint32_t out32[8] = { 0 };
   Salsa20::hsalsa20(out32, in32);

   copy_out_le(out, 32, out32);
   return 0;
   }

int Sodium::crypto_stream_salsa20(uint8_t out[], size_t out_len,
                                  const uint8_t nonce[], const uint8_t key[])
   {
   Salsa20 salsa;
   salsa.set_key(key, crypto_stream_salsa20_KEYBYTES);
   salsa.set_iv(nonce, crypto_stream_salsa20_NONCEBYTES);
   salsa.write_keystream(out, out_len);
   return 0;
   }

int Sodium::crypto_stream_salsa20_xor(uint8_t out[], const uint8_t in[],
                                      size_t in_len, const uint8_t nonce[],
                                      const uint8_t key[])
   {
   return crypto_stream_salsa20_xor_ic(out, in, in_len, nonce, 0, key);
   }

int Sodium::crypto_stream_salsa20_xor_ic(uint8_t out[], const uint8_t in[],
                                         size_t in_len,
                                         const uint8_t nonce[], uint64_t ic,
                                         const uint8_t key[])
   {
   if((ic >> 6) != 0) // otherwise multiply overflows
      return -1;

   Salsa20 salsa;
   salsa.set_key(key, crypto_stream_salsa20_KEYBYTES);
   salsa.set_iv(nonce, crypto_stream_salsa20_NONCEBYTES);
   salsa.seek(ic * 64);
   salsa.cipher(in, out, in_len);
   return 0;
   }

int Sodium::crypto_stream_xsalsa20(uint8_t out[], size_t out_len,
                                   const uint8_t nonce[], const uint8_t key[])
   {
   Salsa20 salsa;
   salsa.set_key(key, crypto_stream_xsalsa20_KEYBYTES);
   salsa.set_iv(nonce, crypto_stream_xsalsa20_NONCEBYTES);
   salsa.write_keystream(out, out_len);
   return 0;
   }

int Sodium::crypto_stream_xsalsa20_xor(uint8_t out[], const uint8_t in[],
                                       size_t in_len, const uint8_t nonce[],
                                       const uint8_t key[])
   {
   return crypto_stream_xsalsa20_xor_ic(out, in, in_len, nonce, 0, key);
   }

int Sodium::crypto_stream_xsalsa20_xor_ic(uint8_t out[], const uint8_t in[],
                                          size_t in_len,
                                          const uint8_t nonce[], uint64_t ic,
                                          const uint8_t key[])
   {
   if((ic >> 6) != 0) // otherwise multiply overflows
      return -1;

   Salsa20 salsa;
   salsa.set_key(key, crypto_stream_xsalsa20_KEYBYTES);
   salsa.set_iv(nonce, crypto_stream_xsalsa20_NONCEBYTES);
   salsa.seek(ic * 64);
   salsa.cipher(in, out, in_len);
   return 0;
   }

}
