/*
* ANSI X9.31 RNG
* (C) 1999-2009,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/x931_rng.h>
#include <algorithm>

namespace Botan {

void ANSI_X931_RNG::randomize(byte out[], size_t length)
   {
   if(!is_seeded())
      {
      rekey();

      if(!is_seeded())
         throw PRNG_Unseeded(name());
      }

   while(length)
      {
      if(m_R_pos == m_R.size())
         update_buffer();

      const size_t copied = std::min<size_t>(length, m_R.size() - m_R_pos);

      copy_mem(out, &m_R[m_R_pos], copied);
      out += copied;
      length -= copied;
      m_R_pos += copied;
      }
   }

/*
* Refill the internal state
*/
void ANSI_X931_RNG::update_buffer()
   {
   const size_t BLOCK_SIZE = m_cipher->block_size();

   secure_vector<byte> DT = m_prng->random_vec(BLOCK_SIZE);
   m_cipher->encrypt(DT);

   xor_buf(m_R.data(), m_V.data(), DT.data(), BLOCK_SIZE);
   m_cipher->encrypt(m_R);

   xor_buf(m_V.data(), m_R.data(), DT.data(), BLOCK_SIZE);
   m_cipher->encrypt(m_V);

   m_R_pos = 0;
   }

/*
* Reset V and the cipher key with new values
*/
void ANSI_X931_RNG::rekey()
   {
   const size_t BLOCK_SIZE = m_cipher->block_size();

   if(m_prng->is_seeded())
      {
      m_cipher->set_key(m_prng->random_vec(m_cipher->maximum_keylength()));

      if(m_V.size() != BLOCK_SIZE)
         m_V.resize(BLOCK_SIZE);
      m_prng->randomize(m_V.data(), m_V.size());

      update_buffer();
      }
   }

size_t ANSI_X931_RNG::reseed(Entropy_Sources& srcs,
                             size_t poll_bits,
                             std::chrono::milliseconds poll_timeout)
   {
   size_t bits = m_prng->reseed(srcs, poll_bits, poll_timeout);
   rekey();
   return bits;
   }

void ANSI_X931_RNG::add_entropy(const byte input[], size_t length)
   {
   m_prng->add_entropy(input, length);
   rekey();
   }

bool ANSI_X931_RNG::is_seeded() const
   {
   return (m_V.size() > 0);
   }

void ANSI_X931_RNG::clear()
   {
   m_cipher->clear();
   m_prng->clear();
   zeroise(m_R);
   m_V.clear();

   m_R_pos = 0;
   }

std::string ANSI_X931_RNG::name() const
   {
   return "X9.31(" + m_cipher->name() + ")";
   }

ANSI_X931_RNG::ANSI_X931_RNG(BlockCipher* cipher,
                             RandomNumberGenerator* prng) :
   m_cipher(cipher),
   m_prng(prng),
   m_R(m_cipher->block_size()),
   m_R_pos(0)
   {
   }

}
