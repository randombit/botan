/*
* Block Cipher Cascade
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/cascade.h>

namespace Botan {

void Cascade_Cipher::encrypt_n(const byte in[], byte out[],
                               size_t blocks) const
   {
   size_t c1_blocks = blocks * (block_size() / cipher1->block_size());
   size_t c2_blocks = blocks * (block_size() / cipher2->block_size());

   cipher1->encrypt_n(in, out, c1_blocks);
   cipher2->encrypt_n(out, out, c2_blocks);
   }

void Cascade_Cipher::decrypt_n(const byte in[], byte out[],
                               size_t blocks) const
   {
   size_t c1_blocks = blocks * (block_size() / cipher1->block_size());
   size_t c2_blocks = blocks * (block_size() / cipher2->block_size());

   cipher2->decrypt_n(in, out, c2_blocks);
   cipher1->decrypt_n(out, out, c1_blocks);
   }

void Cascade_Cipher::key_schedule(const byte key[], size_t)
   {
   const byte* key2 = key + cipher1->maximum_keylength();

   cipher1->set_key(key , cipher1->maximum_keylength());
   cipher2->set_key(key2, cipher2->maximum_keylength());
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

size_t euclids_algorithm(size_t a, size_t b)
   {
   while(b != 0) // gcd
      {
      size_t t = b;
      b = a % b;
      a = t;
      }

   return a;
   }

size_t block_size_for_cascade(size_t bs, size_t bs2)
   {
   if(bs == bs2)
      return bs;

   size_t gcd = euclids_algorithm(bs, bs2);

   return (bs * bs2) / gcd;
   }

}

Cascade_Cipher::Cascade_Cipher(BlockCipher* c1, BlockCipher* c2) :
   cipher1(c1), cipher2(c2)
   {
   block = block_size_for_cascade(c1->block_size(), c2->block_size());

   if(block_size() % c1->block_size() || block_size() % c2->block_size())
      throw Internal_Error("Failure in " + name() + " constructor");
   }

Cascade_Cipher::~Cascade_Cipher()
   {
   delete cipher1;
   delete cipher2;
   }

}
