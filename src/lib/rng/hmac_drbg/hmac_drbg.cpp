/*
* HMAC_DRBG
* (C) 2014,2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/hmac_drbg.h>
#include <algorithm>

namespace Botan {

HMAC_DRBG::HMAC_DRBG(MessageAuthenticationCode* hmac,
                     size_t max_output_before_reseed) :
   Stateful_RNG(max_output_before_reseed),
   m_mac(hmac)
   {
   m_V.resize(m_mac->output_length());
   clear();
   }

HMAC_DRBG::HMAC_DRBG(const std::string& hmac_hash,
                     size_t max_output_before_reseed) :
   Stateful_RNG(max_output_before_reseed)
   {
   const std::string hmac = "HMAC(" + hmac_hash + ")";

   m_mac = MessageAuthenticationCode::create(hmac);
   if(!m_mac)
      {
      throw Algorithm_Not_Found(hmac);
      }

   m_V.resize(m_mac->output_length());
   clear();
   }

void HMAC_DRBG::clear()
   {
   Stateful_RNG::clear();

   for(size_t i = 0; i != m_V.size(); ++i)
      m_V[i] = 0x01;
   m_mac->set_key(std::vector<byte>(m_mac->output_length(), 0x00));
   }

std::string HMAC_DRBG::name() const
   {
   return "HMAC_DRBG(" + m_mac->name() + ")";
   }

void HMAC_DRBG::randomize(byte output[], size_t output_len)
   {
   randomize_with_input(output, output_len, nullptr, 0);
   }

/*
* HMAC_DRBG generation
* See NIST SP800-90A section 10.1.2.5
*/
void HMAC_DRBG::randomize_with_input(byte output[], size_t output_len,
                                     const byte input[], size_t input_len)
   {
   reseed_check(output_len);

   if(input_len > 0)
      {
      update(input, input_len);
      }

   while(output_len)
      {
      const size_t to_copy = std::min(output_len, m_V.size());
      m_mac->update(m_V.data(), m_V.size());
      m_mac->final(m_V.data());
      copy_mem(output, m_V.data(), to_copy);

      output += to_copy;
      output_len -= to_copy;
      }

   update(input, input_len);
   }

/*
* Reset V and the mac key with new values
* See NIST SP800-90A section 10.1.2.2
*/
void HMAC_DRBG::update(const byte input[], size_t input_len)
   {
   m_mac->update(m_V);
   m_mac->update(0x00);
   m_mac->update(input, input_len);
   m_mac->set_key(m_mac->final());

   m_mac->update(m_V.data(), m_V.size());
   m_mac->final(m_V.data());

   if(input_len > 0)
      {
      m_mac->update(m_V);
      m_mac->update(0x01);
      m_mac->update(input, input_len);
      m_mac->set_key(m_mac->final());

      m_mac->update(m_V.data(), m_V.size());
      m_mac->final(m_V.data());
      }
   }

void HMAC_DRBG::add_entropy(const byte input[], size_t input_len)
   {
   update(input, input_len);
   }

}
