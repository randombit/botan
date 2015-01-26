/*
* Serpent in x86-32
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/serp_x86_32.h>
#include <botan/loadstor.h>

namespace Botan {

extern "C" {

/**
* Entry point for Serpent encryption in x86 asm
* @param in the input block
* @param out the output block
* @param ks the key schedule
*/
void botan_serpent_x86_32_encrypt(const byte in[16],
                                byte out[16],
                                const u32bit ks[132]);

/**
* Entry point for Serpent decryption in x86 asm
* @param in the input block
* @param out the output block
* @param ks the key schedule
*/
void botan_serpent_x86_32_decrypt(const byte in[16],
                                byte out[16],
                                const u32bit ks[132]);

/**
* Entry point for Serpent key schedule in x86 asm
* @param ks holds the initial working key (padded), and is set to the
            final key schedule
*/
void botan_serpent_x86_32_key_schedule(u32bit ks[140]);

}

/*
* Serpent Encryption
*/
void Serpent_X86_32::encrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   auto keys = this->get_round_keys();

   for(size_t i = 0; i != blocks; ++i)
      {
      botan_serpent_x86_32_encrypt(in, out, keys.data());
      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/*
* Serpent Decryption
*/
void Serpent_X86_32::decrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   auto keys = this->get_round_keys();

   for(size_t i = 0; i != blocks; ++i)
      {
      botan_serpent_x86_32_decrypt(in, out, keys.data());
      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/*
* Serpent Key Schedule
*/
void Serpent_X86_32::key_schedule(const byte key[], size_t length)
   {
   secure_vector<u32bit> W(140);
   for(size_t i = 0; i != length / 4; ++i)
      W[i] = load_le<u32bit>(key, i);
   W[length / 4] |= u32bit(1) << ((length%4)*8);

   botan_serpent_x86_32_key_schedule(W.data());
   this->set_round_keys(&W[8]);
   }

}
