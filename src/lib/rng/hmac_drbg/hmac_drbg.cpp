/*
* HMAC_DRBG
* (C) 2014,2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/hmac_drbg.h>
#include <algorithm>

namespace Botan {

HMAC_DRBG::HMAC_DRBG(std::unique_ptr<MessageAuthenticationCode> prf,
                     RandomNumberGenerator& underlying_rng,
                     size_t reseed_interval) :
   Stateful_RNG(underlying_rng, reseed_interval),
   m_mac(std::move(prf))
   {
   BOTAN_ASSERT_NONNULL(m_mac);
   clear();
   }

HMAC_DRBG::HMAC_DRBG(std::unique_ptr<MessageAuthenticationCode> prf,
                     RandomNumberGenerator& underlying_rng,
                     Entropy_Sources& entropy_sources,
                     size_t reseed_interval) :
   Stateful_RNG(underlying_rng, entropy_sources, reseed_interval),
   m_mac(std::move(prf))
   {
   BOTAN_ASSERT_NONNULL(m_mac);
   clear();
   }

HMAC_DRBG::HMAC_DRBG(std::unique_ptr<MessageAuthenticationCode> prf,
                     Entropy_Sources& entropy_sources,
                     size_t reseed_interval) :
   Stateful_RNG(entropy_sources, reseed_interval),
   m_mac(std::move(prf))
   {
   BOTAN_ASSERT_NONNULL(m_mac);
   clear();
   }

HMAC_DRBG::HMAC_DRBG(std::unique_ptr<MessageAuthenticationCode> prf) :
   Stateful_RNG(),
   m_mac(std::move(prf))
   {
   BOTAN_ASSERT_NONNULL(m_mac);
   clear();
   }

void HMAC_DRBG::clear()
   {
   Stateful_RNG::clear();

   m_V.resize(m_mac->output_length());
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
   /**
   * SP 800-90A requires we reject any request for a DRBG output
   * longer than max_number_of_bits_per_request. This is an
   * implementation-dependent value, but NIST requires for HMAC_DRBG
   * that every implementation set a value no more than 2**19 bits
   * (or 64 KiB).
   *
   * To avoid inconveniencing the caller who wants a large output for
   * whatever reason, instead treat very long output requests as
   * if multiple maximum-length requests had been made.
   */
   const size_t max_number_of_bytes_per_request = 64*1024;

   while(output_len > 0)
      {
      size_t this_req = std::min(max_number_of_bytes_per_request, output_len);
      output_len -= this_req;

      reseed_check();

      if(input_len > 0)
         {
         update(input, input_len);
         }

      while(this_req)
         {
         const size_t to_copy = std::min(this_req, m_V.size());
         m_mac->update(m_V.data(), m_V.size());
         m_mac->final(m_V.data());
         copy_mem(output, m_V.data(), to_copy);

         output += to_copy;
         this_req -= to_copy;
         }

      update(input, input_len);
      }

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

size_t HMAC_DRBG::security_level() const
   {
   // sqrt of hash size
   return m_mac->output_length() * 8 / 2;
   }

}
