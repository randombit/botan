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

/**
* Entry point for Serpent encryption in x86 asm
* @param in the input block
* @param out the output block
* @param ks the key schedule
*/
void botan_serpent_ia32_encrypt(const byte in[16],
                                byte out[16],
                                const u32bit ks[132]);

/**
* Entry point for Serpent decryption in x86 asm
* @param in the input block
* @param out the output block
* @param ks the key schedule
*/
void botan_serpent_ia32_decrypt(const byte in[16],
                                byte out[16],
                                const u32bit ks[132]);

/**
* Entry point for Serpent key schedule in x86 asm
* @param ks holds the initial working key (padded), and is set to the
            final key schedule
*/
void botan_serpent_ia32_key_schedule(u32bit ks[140]);

}

/*
* Serpent Encryption
*/
void Serpent_IA32::encrypt_n(const byte in[], byte out[], u32bit blocks) const
   {
   for(u32bit i = 0; i != blocks; ++i)
      {
      botan_serpent_ia32_encrypt(in, out, this->get_round_keys());
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
      botan_serpent_ia32_decrypt(in, out, this->get_round_keys());
      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/*
* Serpent Key Schedule
*/
void Serpent_IA32::key_schedule(const byte key[], u32bit length)
   {
   SecureVector<u32bit, 140> W;
   for(u32bit j = 0; j != length / 4; ++j)
      W[j] = load_le<u32bit>(key, j);
   W[length / 4] |= u32bit(1) << ((length%4)*8);

   botan_serpent_ia32_key_schedule(W);
   this->set_round_keys(W + 8);
   }

}
