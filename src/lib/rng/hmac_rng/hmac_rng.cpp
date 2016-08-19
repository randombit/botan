/*
* HMAC_RNG
* (C) 2008,2009,2013,2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/hmac_rng.h>
#include <botan/entropy_src.h>
#include <botan/internal/os_utils.h>
#include <algorithm>

namespace Botan {

HMAC_RNG::HMAC_RNG(std::unique_ptr<MessageAuthenticationCode> prf,
                   RandomNumberGenerator& underlying_rng,
                   Entropy_Sources& entropy_sources,
                   size_t reseed_interval) :
   Stateful_RNG(underlying_rng, reseed_interval),
   m_prf(std::move(prf))
   {
   BOTAN_ASSERT_NONNULL(m_prf);

   if(!m_prf->valid_keylength(m_prf->output_length()))
      {
      throw Invalid_Argument("HMAC_RNG cannot use " + m_prf->name());
      }

   m_extractor.reset(m_prf->clone());
   this->clear();
   }

HMAC_RNG::HMAC_RNG(std::unique_ptr<MessageAuthenticationCode> prf,
                   RandomNumberGenerator& underlying_rng,
                   size_t reseed_interval) :
   Stateful_RNG(underlying_rng, reseed_interval),
   m_prf(std::move(prf))
   {
   BOTAN_ASSERT_NONNULL(m_prf);

   if(!m_prf->valid_keylength(m_prf->output_length()))
      {
      throw Invalid_Argument("HMAC_RNG cannot use " + m_prf->name());
      }

   m_extractor.reset(m_prf->clone());
   this->clear();
   }

HMAC_RNG::HMAC_RNG(std::unique_ptr<MessageAuthenticationCode> prf,
                   Entropy_Sources& entropy_sources,
                   size_t reseed_interval) :
   Stateful_RNG(entropy_sources, reseed_interval),
   m_prf(std::move(prf)),
   m_extractor(m_prf->clone())
   {
   BOTAN_ASSERT_NONNULL(m_prf);

   if(!m_prf->valid_keylength(m_prf->output_length()))
      {
      throw Invalid_Argument("HMAC_RNG cannot use " + m_prf->name());
      }

   m_extractor.reset(m_prf->clone());
   this->clear();
   }

HMAC_RNG::HMAC_RNG(std::unique_ptr<MessageAuthenticationCode> prf) :
   Stateful_RNG(),
   m_prf(std::move(prf))
   {
   BOTAN_ASSERT_NONNULL(m_prf);

   if(!m_prf->valid_keylength(m_prf->output_length()))
      {
      throw Invalid_Argument("HMAC_RNG cannot use " + m_prf->name());
      }

   m_extractor.reset(m_prf->clone());
   this->clear();
   }

void HMAC_RNG::clear()
   {
   Stateful_RNG::clear();
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
   m_prf->update(m_K);
   m_prf->update_be(last_pid());
   m_prf->update_be(OS::get_processor_timestamp());
   m_prf->update_be(OS::get_system_timestamp_ns());
   m_prf->update_be(m_counter++);
   m_prf->update(label);
   m_prf->final(m_K.data());
   }

/*
* Generate a buffer of random bytes
*/
void HMAC_RNG::randomize(byte out[], size_t length)
   {
   reseed_check();

   while(length)
      {
      new_K_value(Running);

      const size_t copied = std::min<size_t>(length, m_prf->output_length());

      copy_mem(out, m_K.data(), copied);
      out += copied;
      length -= copied;
      }

   new_K_value(BlockFinished);
   }

size_t HMAC_RNG::reseed(Entropy_Sources& srcs,
                        size_t poll_bits,
                        std::chrono::milliseconds timeout)
   {
   new_K_value(Reseed);
   m_extractor->update(m_K); // m_K is the PRF output

   /*
   * This ends up calling add_entropy which provides input to the extractor
   */
   size_t bits_collected = Stateful_RNG::reseed(srcs, poll_bits, timeout);

   /*
   Now derive the new PRK using everything that has been fed into
   the extractor, and set the PRF key to that
   */
   m_prf->set_key(m_extractor->final());

   // Now generate a new PRF output to use as the XTS extractor salt
   new_K_value(ExtractorSeed);
   m_extractor->set_key(m_K);

   // Reset state
   zeroise(m_K);
   m_counter = 0;

   return bits_collected;
   }

/*
* Add user-supplied entropy to the extractor input then set remaining
* output length to for a reseed on next use.
*/
void HMAC_RNG::add_entropy(const byte input[], size_t length)
   {
   m_extractor->update(input, length);
   force_reseed();
   }

/*
* Return the name of this type
*/
std::string HMAC_RNG::name() const
   {
   return "HMAC_RNG(" + m_extractor->name() + "," + m_prf->name() + ")";
   }

}
