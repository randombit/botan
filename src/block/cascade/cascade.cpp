/*
* Block Cipher Cascade
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/cascade.h>

namespace Botan {

void Cascade_Cipher::encrypt_n(const byte in[], byte out[],
                               u32bit blocks) const
   {
   u32bit c1_blocks = blocks * (BLOCK_SIZE / cipher1->BLOCK_SIZE);
   u32bit c2_blocks = blocks * (BLOCK_SIZE / cipher2->BLOCK_SIZE);

   cipher1->encrypt_n(in, out, c1_blocks);
   cipher2->encrypt_n(out, out, c2_blocks);
   }

void Cascade_Cipher::decrypt_n(const byte in[], byte out[],
                               u32bit blocks) const
   {
   u32bit c1_blocks = blocks * (BLOCK_SIZE / cipher1->BLOCK_SIZE);
   u32bit c2_blocks = blocks * (BLOCK_SIZE / cipher2->BLOCK_SIZE);

   cipher2->decrypt_n(in, out, c2_blocks);
   cipher1->decrypt_n(out, out, c1_blocks);
   }

void Cascade_Cipher::key_schedule(const byte key[], u32bit)
   {
   const byte* key2 = key + cipher1->MAXIMUM_KEYLENGTH;

   cipher1->set_key(key , cipher1->MAXIMUM_KEYLENGTH);
   cipher2->set_key(key2, cipher2->MAXIMUM_KEYLENGTH);
   }

void Cascade_Cipher::clear()
   {
   cipher1->clear();
   cipher2->clear();
   }

std::string Cascade_Cipher::name() const
   {
   return "Cascade(" + cipher1->name() + "," + cipher2->name() + ")";
   }

BlockCipher* Cascade_Cipher::clone() const
   {
   return new Cascade_Cipher(cipher1->clone(),
                             cipher2->clone());
   }

namespace {

u32bit euclids_algorithm(u32bit a, u32bit b)
   {
   while(b != 0) // gcd
      {
      u32bit t = b;
      b = a % b;
      a = t;
      }

   return a;
   }

u32bit block_size_for_cascade(u32bit bs, u32bit bs2)
   {
   if(bs == bs2)
      return bs;

   u32bit gcd = euclids_algorithm(bs, bs2);

   return (bs * bs2) / gcd;
   }

}

Cascade_Cipher::Cascade_Cipher(BlockCipher* c1, BlockCipher* c2) :
   BlockCipher(block_size_for_cascade(c1->BLOCK_SIZE, c2->BLOCK_SIZE),
               c1->MAXIMUM_KEYLENGTH + c2->MAXIMUM_KEYLENGTH),
   cipher1(c1), cipher2(c2)
   {
   if(BLOCK_SIZE % c1->BLOCK_SIZE || BLOCK_SIZE % c2->BLOCK_SIZE)
      throw Internal_Error("Failure in " + name() + " constructor");
   }

Cascade_Cipher::~Cascade_Cipher()
   {
   delete cipher1;
   delete cipher2;
   }

}
