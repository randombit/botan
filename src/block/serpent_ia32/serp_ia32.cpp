/*
* IA-32 Serpent
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/serp_ia32.h>
#include <botan/loadstor.h>

namespace Botan {

extern "C" {

void botan_serpent_ia32_encrypt(const byte[16], byte[16], const u32bit[132]);
void botan_serpent_ia32_decrypt(const byte[16], byte[16], const u32bit[132]);
void botan_serpent_ia32_key_schedule(u32bit[140]);

}

/*
* Serpent Encryption
*/
void Serpent_IA32::enc(const byte in[], byte out[]) const
   {
   botan_serpent_ia32_encrypt(in, out, round_key);
   }

/*
* Serpent Decryption
*/
void Serpent_IA32::dec(const byte in[], byte out[]) const
   {
   botan_serpent_ia32_decrypt(in, out, round_key);
   }

/*
* Serpent Key Schedule
*/
void Serpent_IA32::key_schedule(const byte key[], u32bit length)
   {
   SecureBuffer<u32bit, 140> W;
   for(u32bit j = 0; j != length / 4; ++j)
      W[j] = make_u32bit(key[4*j+3], key[4*j+2], key[4*j+1], key[4*j]);
   W[length / 4] |= u32bit(1) << ((length%4)*8);

   botan_serpent_ia32_key_schedule(W);
   round_key.copy(W + 8, 132);
   }

}
