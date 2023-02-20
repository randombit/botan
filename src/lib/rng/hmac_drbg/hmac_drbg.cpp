/*
* HMAC_DRBG
* (C) 2014,2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/hmac_drbg.h>
#include <algorithm>

namespace Botan {

namespace {

size_t hmac_drbg_security_level(size_t mac_output_length)
   {
   // security strength of the hash function
   // for pre-image resistance (see NIST SP 800-57)
   // SHA-1: 128 bits
   // SHA-224, SHA-512/224: 192 bits,
   // SHA-256, SHA-512/256, SHA-384, SHA-512: >= 256 bits
   // NIST SP 800-90A only supports up to 256 bits though

   if(mac_output_length < 32)
      {
      return (mac_output_length - 4) * 8;
      }
   else
      {
      return 32 * 8;
      }
   }

void check_limits(size_t reseed_interval,
                  size_t max_number_of_bytes_per_request)
   {
   // SP800-90A permits up to 2^48, but it is not usable on 32 bit
   // platforms, so we only allow up to 2^24, which is still reasonably high
   if(reseed_interval == 0 || reseed_interval > static_cast<size_t>(1) << 24)
      {
      throw Invalid_Argument("Invalid value for reseed_interval");
      }

   if(max_number_of_bytes_per_request == 0 || max_number_of_bytes_per_request > 64 * 1024)
      {
      throw Invalid_Argument("Invalid value for max_number_of_bytes_per_request");
      }
   }

}

HMAC_DRBG::HMAC_DRBG(std::unique_ptr<MessageAuthenticationCode> prf,
                     RandomNumberGenerator& underlying_rng,
                     size_t reseed_interval,
                     size_t max_number_of_bytes_per_request) :
   Stateful_RNG(underlying_rng, reseed_interval),
   m_mac(std::move(prf)),
   m_max_number_of_bytes_per_request(max_number_of_bytes_per_request),
   m_security_level(hmac_drbg_security_level(m_mac->output_length()))
   {
   BOTAN_ASSERT_NONNULL(m_mac);

   check_limits(reseed_interval, max_number_of_bytes_per_request);

   clear();
   }

HMAC_DRBG::HMAC_DRBG(std::unique_ptr<MessageAuthenticationCode> prf,
                     RandomNumberGenerator& underlying_rng,
                     Entropy_Sources& entropy_sources,
                     size_t reseed_interval,
                     size_t max_number_of_bytes_per_request) :
   Stateful_RNG(underlying_rng, entropy_sources, reseed_interval),
   m_mac(std::move(prf)),
   m_max_number_of_bytes_per_request(max_number_of_bytes_per_request),
   m_security_level(hmac_drbg_security_level(m_mac->output_length()))
   {
   BOTAN_ASSERT_NONNULL(m_mac);

   check_limits(reseed_interval, max_number_of_bytes_per_request);

   clear();
   }

HMAC_DRBG::HMAC_DRBG(std::unique_ptr<MessageAuthenticationCode> prf,
                     Entropy_Sources& entropy_sources,
                     size_t reseed_interval,
                     size_t max_number_of_bytes_per_request) :
   Stateful_RNG(entropy_sources, reseed_interval),
   m_mac(std::move(prf)),
   m_max_number_of_bytes_per_request(max_number_of_bytes_per_request),
   m_security_level(hmac_drbg_security_level(m_mac->output_length()))
   {
   BOTAN_ASSERT_NONNULL(m_mac);

   check_limits(reseed_interval, max_number_of_bytes_per_request);

   clear();
   }

HMAC_DRBG::HMAC_DRBG(std::unique_ptr<MessageAuthenticationCode> prf) :
   Stateful_RNG(),
   m_mac(std::move(prf)),
   m_max_number_of_bytes_per_request(64*1024),
   m_security_level(hmac_drbg_security_level(m_mac->output_length()))
   {
   BOTAN_ASSERT_NONNULL(m_mac);
   clear();
   }

HMAC_DRBG::HMAC_DRBG(const std::string& hmac_hash) :
   Stateful_RNG(),
   m_mac(MessageAuthenticationCode::create_or_throw("HMAC(" + hmac_hash + ")")),
   m_max_number_of_bytes_per_request(64 * 1024),
   m_security_level(hmac_drbg_security_level(m_mac->output_length()))
   {
   clear();
   }

void HMAC_DRBG::clear_state()
   {
   if(m_V.empty())
      {
      const size_t output_length = m_mac->output_length();
      m_V.resize(output_length);
      }

   for(size_t i = 0; i != m_V.size(); ++i)
      m_V[i] = 0x01;
   m_mac->set_key(std::vector<uint8_t>(m_V.size(), 0x00));
   }

std::string HMAC_DRBG::name() const
   {
   return "HMAC_DRBG(" + m_mac->name() + ")";
   }

/*
* HMAC_DRBG generation
* See NIST SP800-90A section 10.1.2.5
*/
void HMAC_DRBG::generate_output(std::span<uint8_t> output, std::span<const uint8_t> input)
   {
   BOTAN_ASSERT_NOMSG(!output.empty());

   if(!input.empty())
      {
      update(input);
      }

   uint8_t* output_ptr = output.data();
   size_t output_len = output.size();
   while(output_len > 0)
      {
      const size_t to_copy = std::min(output_len, m_V.size());
      m_mac->update(m_V.data(), m_V.size());
      m_mac->final(m_V.data());
      copy_mem(output_ptr, m_V.data(), to_copy);

      output_ptr += to_copy;
      output_len -= to_copy;
      }

   update(input);
   }

/*
* Reset V and the mac key with new values
* See NIST SP800-90A section 10.1.2.2
*/
void HMAC_DRBG::update(std::span<const uint8_t> input)
   {
   secure_vector<uint8_t> T(m_V.size());
   m_mac->update(m_V);
   m_mac->update(0x00);
   m_mac->update(input.data(), input.size()); // TODO: pass span after merging GH #3294
   m_mac->final(T.data());
   m_mac->set_key(T);

   m_mac->update(m_V.data(), m_V.size());
   m_mac->final(m_V.data());

   if(!input.empty())
      {
      m_mac->update(m_V);
      m_mac->update(0x01);
      m_mac->update(input.data(), input.size()); // TODO: pass span after merging GH #3294
      m_mac->final(T.data());
      m_mac->set_key(T);

      m_mac->update(m_V.data(), m_V.size());
      m_mac->final(m_V.data());
      }
   }

size_t HMAC_DRBG::security_level() const
   {
   return m_security_level;
   }
}
