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
                     size_t reseed_interval,
                     size_t max_number_of_bytes_per_request) :
   Stateful_RNG(underlying_rng, reseed_interval),
   m_mac(std::move(prf)),
   m_max_number_of_bytes_per_request(max_number_of_bytes_per_request)
   {
   BOTAN_ASSERT_NONNULL(m_mac);

   if(m_max_number_of_bytes_per_request == 0 || m_max_number_of_bytes_per_request > 64 * 1024)
      {
      throw Invalid_Argument("Invalid value for max_number_of_bytes_per_request");
      }

   clear();
   }

HMAC_DRBG::HMAC_DRBG(std::unique_ptr<MessageAuthenticationCode> prf,
                     RandomNumberGenerator& underlying_rng,
                     Entropy_Sources& entropy_sources,
                     size_t reseed_interval,
                     size_t max_number_of_bytes_per_request ) :
   Stateful_RNG(underlying_rng, entropy_sources, reseed_interval),
   m_mac(std::move(prf)),
   m_max_number_of_bytes_per_request(max_number_of_bytes_per_request)
   {
   BOTAN_ASSERT_NONNULL(m_mac);

   if(m_max_number_of_bytes_per_request == 0 || m_max_number_of_bytes_per_request > 64 * 1024)
      {
      throw Invalid_Argument("Invalid value for max_number_of_bytes_per_request");
      }

   clear();
   }

HMAC_DRBG::HMAC_DRBG(std::unique_ptr<MessageAuthenticationCode> prf,
                     Entropy_Sources& entropy_sources,
                     size_t reseed_interval,
                     size_t max_number_of_bytes_per_request) :
   Stateful_RNG(entropy_sources, reseed_interval),
   m_mac(std::move(prf)),
   m_max_number_of_bytes_per_request(max_number_of_bytes_per_request)
   {
   BOTAN_ASSERT_NONNULL(m_mac);

   if(m_max_number_of_bytes_per_request == 0 || m_max_number_of_bytes_per_request > 64 * 1024)
      {
      throw Invalid_Argument("Invalid value for max_number_of_bytes_per_request");
      }

   clear();
   }

HMAC_DRBG::HMAC_DRBG(std::unique_ptr<MessageAuthenticationCode> prf) :
   Stateful_RNG(),
   m_mac(std::move(prf)),
   m_max_number_of_bytes_per_request(64*1024)
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
   m_mac->set_key(std::vector<uint8_t>(m_mac->output_length(), 0x00));
   }

std::string HMAC_DRBG::name() const
   {
   return "HMAC_DRBG(" + m_mac->name() + ")";
   }

void HMAC_DRBG::randomize(uint8_t output[], size_t output_len)
   {
   randomize_with_input(output, output_len, nullptr, 0);
   }

/*
* HMAC_DRBG generation
* See NIST SP800-90A section 10.1.2.5
*/
void HMAC_DRBG::randomize_with_input(uint8_t output[], size_t output_len,
                                     const uint8_t input[], size_t input_len)
   {
   while(output_len > 0)
      {
      size_t this_req = std::min(m_max_number_of_bytes_per_request, output_len);
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
void HMAC_DRBG::update(const uint8_t input[], size_t input_len)
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

void HMAC_DRBG::add_entropy(const uint8_t input[], size_t input_len)
   {
   update(input, input_len);

   if(8*input_len >= security_level())
      {
      reset_reseed_counter();
      }
   }

size_t HMAC_DRBG::security_level() const
   {
   // security strength of the hash function
   // for pre-image resistance (see NIST SP 800-57)
   // SHA-160: 128 bits, SHA-224, SHA-512/224: 192 bits,
   // SHA-256, SHA-512/256, SHA-384, SHA-512: >= 256 bits
   // NIST SP 800-90A only supports up to 256 bits though
   if(m_mac->output_length() < 32)
      {
      return (m_mac->output_length() - 4) * 8;
      }
   else
      {
      return 32 * 8;
      }
   }
}
