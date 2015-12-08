/*
* HMAC_DRBG
* (C) 2014,2015 Jack Lloyd
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
   m_mac->set_key(std::vector<byte>(m_mac->output_length(), 0x00));
   }

HMAC_DRBG::HMAC_DRBG(const std::string& mac_name,
                     RandomNumberGenerator* prng) :
   m_prng(prng),
   m_reseed_counter(0)
   {
   m_mac = MessageAuthenticationCode::create(mac_name);
   if(!m_mac)
      throw Algorithm_Not_Found(mac_name);
   m_V = secure_vector<byte>(m_mac->output_length(), 0x01),
   m_mac->set_key(std::vector<byte>(m_mac->output_length(), 0x00));
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
      copy_mem(out, m_V.data(), to_copy);

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

size_t HMAC_DRBG::reseed_with_sources(Entropy_Sources& srcs,
                                      size_t poll_bits,
                                      std::chrono::milliseconds poll_timeout)
   {
   if(m_prng)
      {
      size_t bits = m_prng->reseed_with_sources(srcs, poll_bits, poll_timeout);

      if(m_prng->is_seeded())
         {
         secure_vector<byte> input = m_prng->random_vec(m_mac->output_length());
         update(input.data(), input.size());
         m_reseed_counter = 1;
         }

      return bits;
      }

   return 0;
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
   m_reseed_counter = 0;
   for(size_t i = 0; i != m_V.size(); ++i)
      m_V[i] = 0x01;

   m_mac->set_key(std::vector<byte>(m_mac->output_length(), 0x00));

   if(m_prng)
      m_prng->clear();
   }

std::string HMAC_DRBG::name() const
   {
   return "HMAC_DRBG(" + m_mac->name() + ")";
   }

}
