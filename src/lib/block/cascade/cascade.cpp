/*
* Block Cipher Cascade
* (C) 2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/cascade.h>

namespace Botan {

void Cascade_Cipher::encrypt_n(const uint8_t in[], uint8_t out[],
                               size_t blocks) const
   {
   size_t c1_blocks = blocks * (block_size() / m_cipher1->block_size());
   size_t c2_blocks = blocks * (block_size() / m_cipher2->block_size());

   m_cipher1->encrypt_n(in, out, c1_blocks);
   m_cipher2->encrypt_n(out, out, c2_blocks);
   }

void Cascade_Cipher::decrypt_n(const uint8_t in[], uint8_t out[],
                               size_t blocks) const
   {
   size_t c1_blocks = blocks * (block_size() / m_cipher1->block_size());
   size_t c2_blocks = blocks * (block_size() / m_cipher2->block_size());

   m_cipher2->decrypt_n(in, out, c2_blocks);
   m_cipher1->decrypt_n(out, out, c1_blocks);
   }

void Cascade_Cipher::key_schedule(const uint8_t key[], size_t)
   {
   const uint8_t* key2 = key + m_cipher1->maximum_keylength();

   m_cipher1->set_key(key , m_cipher1->maximum_keylength());
   m_cipher2->set_key(key2, m_cipher2->maximum_keylength());
   }

void Cascade_Cipher::clear()
   {
   m_cipher1->clear();
   m_cipher2->clear();
   }

std::string Cascade_Cipher::name() const
   {
   return "Cascade(" + m_cipher1->name() + "," + m_cipher2->name() + ")";
   }

BlockCipher* Cascade_Cipher::clone() const
   {
   return new Cascade_Cipher(m_cipher1->clone(),
                             m_cipher2->clone());
   }

namespace {

size_t euclids_algorithm(size_t a, size_t b)
   {
   while(b != 0)
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

   const size_t gcd = euclids_algorithm(bs, bs2);

   return (bs * bs2) / gcd;
   }

}

Cascade_Cipher::Cascade_Cipher(BlockCipher* c1, BlockCipher* c2) :
   m_cipher1(c1), m_cipher2(c2)
   {
   m_block = block_size_for_cascade(c1->block_size(), c2->block_size());

   BOTAN_ASSERT(m_block % c1->block_size() == 0 &&
                m_block % c2->block_size() == 0,
                "Combined block size is a multiple of each ciphers block");
   }

}
