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
void Serpent_IA32::encrypt_n(const byte in[], byte out[], u32bit blocks) const
   {
   for(u32bit i = 0; i != blocks; ++i)
      {
      botan_serpent_ia32_encrypt(in, out, round_key);
      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/*
* Serpent Decryption
*/
void Serpent_IA32::decrypt_n(const byte in[], byte out[], u32bit blocks) const
   {
   for(u32bit i = 0; i != blocks; ++i)
      {
      botan_serpent_ia32_decrypt(in, out, round_key);
      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/*
* Serpent Key Schedule
*/
void Serpent_IA32::key_schedule(const byte key[], u32bit length)
   {
   SecureBuffer<u32bit, 140> W;
   for(u32bit j = 0; j != length / 4; ++j)
      W[j] = load_le<u32bit>(key, j);
   W[length / 4] |= u32bit(1) << ((length%4)*8);

   botan_serpent_ia32_key_schedule(W);
   round_key.copy(W + 8, 132);
   }

}
