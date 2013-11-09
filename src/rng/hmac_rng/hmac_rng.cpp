/*
* HMAC_RNG
* (C) 2008-2009,2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/hmac_rng.h>
#include <botan/libstate.h>
#include <botan/get_byte.h>
#include <botan/entropy_src.h>
#include <botan/internal/xor_buf.h>
#include <algorithm>
#include <chrono>

namespace Botan {

namespace {

void hmac_prf(MessageAuthenticationCode& prf,
              secure_vector<byte>& K,
              u32bit& counter,
              const std::string& label)
   {
   typedef std::chrono::high_resolution_clock clock;

   auto timestamp = clock::now().time_since_epoch().count();

   prf.update(K);
   prf.update(label);
   prf.update_be(timestamp);
   prf.update_be(counter);
   prf.final(&K[0]);

   ++counter;
   }

}

/*
* HMAC_RNG Constructor
*/
HMAC_RNG::HMAC_RNG(MessageAuthenticationCode* extractor,
                   MessageAuthenticationCode* prf) :
   m_extractor(extractor), m_prf(prf)
   {
   if(!m_prf->valid_keylength(m_extractor->output_length()) ||
      !m_extractor->valid_keylength(m_prf->output_length()))
      throw Invalid_Argument("HMAC_RNG: Bad algo combination " +
                             m_extractor->name() + " and " +
                             m_prf->name());

   // First PRF inputs are all zero, as specified in section 2
   m_K.resize(m_prf->output_length());

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
   secure_vector<byte> prf_key(m_extractor->output_length());
   m_prf->set_key(prf_key);

   /*
   Use PRF("Botan HMAC_RNG XTS") as the intitial XTS key.

   This will be used during the first extraction sequence; XTS values
   after this one are generated using the PRF.

   If I understand the E-t-E paper correctly (specifically Section 4),
   using this fixed extractor key is safe to do.
   */
   m_extractor->set_key(prf->process("Botan HMAC_RNG XTS"));
   }

/*
* Generate a buffer of random bytes
*/
void HMAC_RNG::randomize(byte out[], size_t length)
   {
   if(!is_seeded())
      throw PRNG_Unseeded(name());

   /*
    HMAC KDF as described in E-t-E, using a CTXinfo of "rng"
   */
   while(length)
      {
      hmac_prf(*m_prf, m_K, m_counter, "rng");

      if(m_counter % AUTOMATIC_RESEED_RATE == 0)
         reseed(AUTOMATIC_RESEED_BITS);

      const size_t copied = std::min<size_t>(m_K.size() / 2, length);

      copy_mem(out, &m_K[0], copied);
      out += copied;
      length -= copied;
      }
   }

/*
* Poll for entropy and reset the internal keys
*/
void HMAC_RNG::reseed(size_t poll_bits)
   {
   /*
   Using the terminology of E-t-E, XTR is the MAC function (normally
   HMAC) seeded with XTS (below) and we form SKM, the key material, by
   polling as many sources as we think needed to reach our polling
   goal. We then also include feedback of the current PRK so that
   a bad poll doesn't wipe us out.
   */

   Entropy_Accumulator_BufferedComputation accum(*m_extractor, poll_bits);

   global_state().poll_available_sources(accum);

   /*
   * It is necessary to feed forward poll data. Otherwise, a good poll
   * (collecting a large amount of conditional entropy) followed by a
   * bad one (collecting little) would be unsafe. Do this by
   * generating new PRF outputs using the previous key and feeding
   * them into the extractor function.
   *
   * Cycle the RNG once (CTXinfo="rng"), then generate a new PRF
   * output using the CTXinfo "reseed". Provide these values as input
   * to the extractor function.
   */
   hmac_prf(*m_prf, m_K, m_counter, "rng");
   m_extractor->update(m_K); // K is the CTXinfo=rng PRF output

   hmac_prf(*m_prf, m_K, m_counter, "reseed");
   m_extractor->update(m_K); // K is the CTXinfo=reseed PRF output

   /* Now derive the new PRK using everything that has been fed into
      the extractor, and set the PRF key to that */
   m_prf->set_key(m_extractor->final());

   // Now generate a new PRF output to use as the XTS extractor salt
   hmac_prf(*m_prf, m_K, m_counter, "xts");
   m_extractor->set_key(m_K);

   // Reset state
   zeroise(m_K);
   m_counter = 0;

   /*
   * Consider ourselves seeded once we've collected an estimated 128 bits of
   * entropy in a single poll.
   */
   if(accum.bits_collected() >= 128)
      m_seeded = true;
   }

/*
* Add user-supplied entropy to the extractor input
*/
void HMAC_RNG::add_entropy(const byte input[], size_t length)
   {
   m_extractor->update(input, length);
   reseed(AUTOMATIC_RESEED_BITS);
   }

/*
* Clear memory of sensitive data
*/
void HMAC_RNG::clear()
   {
   m_seeded = false;
   m_extractor->clear();
   m_prf->clear();
   zeroise(m_K);
   m_counter = 0;
   }

/*
* Return the name of this type
*/
std::string HMAC_RNG::name() const
   {
   return "HMAC_RNG(" + m_extractor->name() + "," + m_prf->name() + ")";
   }

}
