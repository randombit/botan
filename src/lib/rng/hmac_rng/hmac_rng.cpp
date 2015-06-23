/*
* HMAC_RNG
* (C) 2008,2009,2013,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/hmac_rng.h>
#include <botan/get_byte.h>
#include <botan/entropy_src.h>
#include <botan/internal/xor_buf.h>
#include <algorithm>
#include <chrono>

namespace Botan {

/*
* HMAC_RNG Constructor
*/
HMAC_RNG::HMAC_RNG(MessageAuthenticationCode* extractor,
                   MessageAuthenticationCode* prf) :
   m_extractor(extractor), m_prf(prf)
   {
   if(!m_prf->valid_keylength(m_extractor->output_length()) ||
      !m_extractor->valid_keylength(m_prf->output_length()))
      {
      throw Invalid_Argument("HMAC_RNG: Bad algo combination " +
                             m_extractor->name() + " and " +
                             m_prf->name());
      }

   this->clear();
   }

void HMAC_RNG::clear()
   {
   m_collected_entropy_estimate = 0;
   m_counter = 0;

   // First PRF inputs are all zero, as specified in section 2
   m_K.resize(m_prf->output_length());
   zeroise(m_K);

   /*
   Normally we want to feedback PRF outputs to the extractor function
   to ensure a single bad poll does not reduce entropy. Thus in reseed
   we'll want to invoke the PRF before we reset the PRF key, but until
   the first reseed the PRF is unkeyed. Rather than trying to keep
   track of this, just set the initial PRF key to constant zero.
   Since all PRF inputs in the first reseed are constants, this
   amounts to suffixing the seed in the first poll with a fixed
   constant string.

   The PRF key will not be used to generate outputs until after reseed
   sets m_seeded to true.
   */
   std::vector<byte> prf_zero_key(m_extractor->output_length());
   m_prf->set_key(prf_zero_key.data(), prf_zero_key.size());

   /*
   Use PRF("Botan HMAC_RNG XTS") as the intitial XTS key.

   This will be used during the first extraction sequence; XTS values
   after this one are generated using the PRF.

   If I understand the E-t-E paper correctly (specifically Section 4),
   using this fixed initial extractor key is safe to do.
   */
   m_extractor->set_key(m_prf->process("Botan HMAC_RNG XTS"));
   }

void HMAC_RNG::new_K_value(byte label)
   {
   typedef std::chrono::high_resolution_clock clock;

   m_prf->update(m_K);
   m_prf->update_be(clock::now().time_since_epoch().count());
   m_prf->update_be(m_counter++);
   m_prf->update(label);
   m_prf->final(m_K.data());
   }

/*
* Generate a buffer of random bytes
*/
void HMAC_RNG::randomize(byte out[], size_t length)
   {
   if(!is_seeded())
      {
      reseed(256);
      if(!is_seeded())
         throw PRNG_Unseeded(name());
      }

   const size_t max_per_prf_iter = m_prf->output_length() / 2;

   m_output_since_reseed += length;

   if(m_output_since_reseed >= BOTAN_RNG_MAX_OUTPUT_BEFORE_RESEED)
      reseed_with_timeout(BOTAN_RNG_RESEED_POLL_BITS, BOTAN_RNG_AUTO_RESEED_TIMEOUT);

   /*
    HMAC KDF as described in E-t-E, using a CTXinfo of "rng"
   */
   while(length)
      {
      new_K_value(Running);

      const size_t copied = std::min<size_t>(length, max_per_prf_iter);

      copy_mem(out, m_K.data(), copied);
      out += copied;
      length -= copied;
      }
   }

/*
* Poll for entropy and reset the internal keys
*/
void HMAC_RNG::reseed(size_t poll_bits)
   {
   reseed_with_timeout(poll_bits, BOTAN_RNG_RESEED_DEFAULT_TIMEOUT);
   }

void HMAC_RNG::reseed_with_timeout(size_t poll_bits, std::chrono::milliseconds timeout)
   {
   /*
   Using the terminology of E-t-E, XTR is the MAC function (normally
   HMAC) seeded with XTS (below) and we form SKM, the key material, by
   polling as many sources as we think needed to reach our polling
   goal. We then also include feedback of the current PRK so that
   a bad poll doesn't wipe us out.
   */

   double bits_collected = 0;

   typedef std::chrono::high_resolution_clock clock;
   auto deadline = clock::now() + timeout;

   Entropy_Accumulator accum(
      [&](const byte in[], size_t in_len, double entropy_estimate)
      {
      m_extractor->update(in, in_len);
      bits_collected += entropy_estimate;
      return (bits_collected >= poll_bits || clock::now() > deadline);
      });

   EntropySource::poll_available_sources(accum);

   /*
   * It is necessary to feed forward poll data. Otherwise, a good poll
   * (collecting a large amount of conditional entropy) followed by a
   * bad one (collecting little) would be unsafe. Do this by
   * generating new PRF outputs using the previous key and feeding
   * them into the extractor function.
   */
   new_K_value(Reseed);
   m_extractor->update(m_K); // K is the CTXinfo=reseed PRF output

   /* Now derive the new PRK using everything that has been fed into
      the extractor, and set the PRF key to that */
   m_prf->set_key(m_extractor->final());

   // Now generate a new PRF output to use as the XTS extractor salt
   new_K_value(ExtractorSeed);
   m_extractor->set_key(m_K);

   // Reset state
   zeroise(m_K);
   m_counter = 0;

   m_collected_entropy_estimate =
      std::min<size_t>(m_collected_entropy_estimate + bits_collected,
                       m_extractor->output_length() * 8);

   m_output_since_reseed = 0;
   }

bool HMAC_RNG::is_seeded() const
   {
   return (m_collected_entropy_estimate >= 256);
   }

/*
* Add user-supplied entropy to the extractor input
*/
void HMAC_RNG::add_entropy(const byte input[], size_t length)
   {
   m_extractor->update(input, length);
   reseed_with_timeout(BOTAN_RNG_RESEED_POLL_BITS, BOTAN_RNG_AUTO_RESEED_TIMEOUT);
   }

/*
* Return the name of this type
*/
std::string HMAC_RNG::name() const
   {
   return "HMAC_RNG(" + m_extractor->name() + "," + m_prf->name() + ")";
   }

}
