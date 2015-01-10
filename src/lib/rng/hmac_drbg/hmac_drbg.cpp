/*
* HMAC_DRBG
* (C) 2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/hmac_drbg.h>
#include <algorithm>

namespace Botan {

HMAC_DRBG::HMAC_DRBG(MessageAuthenticationCode* mac,
                     RandomNumberGenerator* prng) :
   m_mac(mac),
   m_prng(prng),
   m_V(m_mac->output_length(), 0x01),
   m_reseed_counter(0)
   {
   m_mac->set_key(secure_vector<byte>(m_mac->output_length(), 0x00));
   }

void HMAC_DRBG::randomize(byte out[], size_t length)
   {
   if(!is_seeded() || m_reseed_counter > BOTAN_RNG_MAX_OUTPUT_BEFORE_RESEED)
      reseed(m_mac->output_length() * 8);

   if(!is_seeded())
      throw PRNG_Unseeded(name());

   while(length)
      {
      const size_t to_copy = std::min(length, m_V.size());
      m_V = m_mac->process(m_V);
      copy_mem(&out[0], &m_V[0], to_copy);

      length -= to_copy;
      out += to_copy;
      }

   m_reseed_counter += length;

   update(nullptr, 0); // additional_data is always empty
   }

/*
* Reset V and the mac key with new values
*/
void HMAC_DRBG::update(const byte input[], size_t input_len)
   {
   m_mac->update(m_V);
   m_mac->update(0x00);
   m_mac->update(input, input_len);
   m_mac->set_key(m_mac->final());

   m_V = m_mac->process(m_V);

   if(input_len)
      {
      m_mac->update(m_V);
      m_mac->update(0x01);
      m_mac->update(input, input_len);
      m_mac->set_key(m_mac->final());

      m_V = m_mac->process(m_V);
      }
   }

void HMAC_DRBG::reseed(size_t poll_bits)
   {
   if(m_prng)
      {
      m_prng->reseed(poll_bits);

      if(m_prng->is_seeded())
         {
         secure_vector<byte> input = m_prng->random_vec(m_mac->output_length());
         update(&input[0], input.size());
         m_reseed_counter = 1;
         }
      }
   }

void HMAC_DRBG::add_entropy(const byte input[], size_t length)
   {
   update(input, length);
   m_reseed_counter = 1;
   }

bool HMAC_DRBG::is_seeded() const
   {
   return m_reseed_counter > 0;
   }

void HMAC_DRBG::clear()
   {
   zeroise(m_V);

   m_mac->clear();

   if(m_prng)
      m_prng->clear();
   }

std::string HMAC_DRBG::name() const
   {
   return "HMAC_DRBG(" + m_mac->name() + ")";
   }

}
