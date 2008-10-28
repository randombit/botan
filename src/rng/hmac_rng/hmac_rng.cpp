/*************************************************
* HMAC_RNG Source File                           *
* (C) 2008 Jack Lloyd                            *
*************************************************/

#include <botan/hmac_rng.h>
#include <botan/loadstor.h>
#include <botan/xor_buf.h>
#include <botan/util.h>
#include <botan/bit_ops.h>
#include <botan/stl_util.h>
#include <algorithm>

namespace Botan {

namespace {

class Entropy_Estimator
   {
   public:
      Entropy_Estimator()
         { last = last_delta = last_delta2 = 0; estimate = 0; }

      u32bit value() const { return estimate; }

      void set_upper_bound(u32bit upper_limit)
         { estimate = std::min(estimate, upper_limit); }

      void update(const byte buffer[], u32bit length, u32bit upper_limit = 0);
   private:
      u32bit estimate;
      byte last, last_delta, last_delta2;
   };

void Entropy_Estimator::update(const byte buffer[], u32bit length,
                               u32bit upper_limit)
   {
   u32bit this_buf_estimate = 0;

   for(u32bit j = 0; j != length; ++j)
      {
      byte delta = last ^ buffer[j];
      last = buffer[j];

      byte delta2 = delta ^ last_delta;
      last_delta = delta;

      byte delta3 = delta2 ^ last_delta2;
      last_delta2 = delta2;

      byte min_delta = delta;
      if(min_delta > delta2) min_delta = delta2;
      if(min_delta > delta3) min_delta = delta3;

      this_buf_estimate += hamming_weight(min_delta);
      }

   this_buf_estimate /= 2;

   if(upper_limit)
      estimate += std::min(upper_limit, this_buf_estimate);
   else
      estimate += this_buf_estimate;
   }

}

/*************************************************
* Generate a buffer of random bytes              *
*************************************************/
void HMAC_RNG::randomize(byte out[], u32bit length)
   {
   if(!is_seeded())
      {
      reseed();

      if(!is_seeded())
         throw PRNG_Unseeded(name());
      }

   /*
    HMAC KDF as described in E-t-E, using a CTXinfo of "rng"
   */
   while(length)
      {
      prf->update(K, K.size());
      prf->update("rng");
      for(u32bit i = 0; i != 4; ++i)
         prf->update(get_byte(i, counter));
      prf->final(K);

      u32bit copied = std::min(K.size(), length);

      copy_mem(out, K.begin(), copied);

      out += copied;
      length -= copied;

      ++counter;
      }
   }

/**
* Reseed the internal state, also accepting user input to include
*/
void HMAC_RNG::reseed_with_input(const byte input[], u32bit input_length)
   {
   SecureVector<byte> buffer(128);
   Entropy_Estimator estimate;

   /*
   Use the first entropy source (which is normally a timer of some
   kind, producing an 8 byte output) as the new random key for the
   extractor.  This takes the function of XTS as described in "On
   Extract-then-Expand Key Derivation Functions and an HMAC-based KDF"
   by Hugo Krawczyk (henceforce, 'E-t-E')

   Set the extractor MAC key to this value: it's OK if the timer is
   guessable. Even if the timer remained constant for a particular
   machine, that is fine, as the only purpose is to parameterize the
   hash function. See Krawczyk's paper for details.

   If not available (no entropy sources at all), set to a constant;
   this also should be safe
   */
   if(entropy_sources.size())
      {
      u32bit got = entropy_sources[0]->fast_poll(buffer, buffer.size());
      extractor->set_key(buffer, got);
      }
   else
      {
      std::string xts = "Botan HMAC_RNG XTS";
      extractor->set_key(reinterpret_cast<const byte*>(xts.c_str()),
                         xts.length());
      }

   /*
   Using the terminology of E-t-E, XTR is the MAC function (normally
   HMAC) seeded with XTS (above) and we form SKM, the key material, by
   fast polling each source, and then slow polling as many as we think
   we need (in the following loop), and feeding all of the poll
   results, along with any optional user input, along with, finally,
   feedback of the current PRK value, into the extractor function.

   Clearly you want the old key to feed back in somehow, because
   otherwise if you have a good poll, collecting a lot of entropy,
   and then have a bad poll, collecting very little, you don't want
   to end up worse than you started (which you would if you threw
   away the entire old key).

   We don't keep the PRK value around (it is just used to seed the
   PRF), so instead we apply the PRF using a CTXinfo of the ASCII
   string "reseed" to generate an output value which is then fed back
   into the extractor function. This should mean that at least some
   bits of the newly chosen PRK will be a function of the previous
   poll data.

   Including the current PRK as an input to the extractor function
   along with the poll data seems the most conservative choice,
   because the extractor function should (assuming I understand the
   E-t-E paper) be safe to use in this way (accepting potentially
   correlated inputs), and this has the following good properties:

   If an attacker recovers a PRK value (using swap forensics,
   timing attacks, malware, etc), it seems very hard to work out
   previous PRK values.

   If an attacker recovers a PRK value, and you then do a poll
   which manages to acquire sufficient (conditional) entropy, then
   the new PRK seems hard to guess, because the old PRK is treated
   just like any other poll input, which here can be coorelated,
   etc without danger (I think) because of the use of a randomized
   extraction function, and the results from the E-t-E paper.
   */

   /*
   Fast poll all sources (except the first one, which we used to
   choose XTS, above)
   */

   for(u32bit j = 1; j < entropy_sources.size(); ++j)
      {
      u32bit got = entropy_sources[j]->fast_poll(buffer, buffer.size());

      extractor->update(buffer, got);
      estimate.update(buffer, got, 96);
      }

   /* Limit assumed entropy from fast polls (to ensure we do at
   least a few slow polls)
   */
   estimate.set_upper_bound(256);

   /* Then do a slow poll, until we think we have got enough entropy
   */
   for(u32bit j = 0; j != entropy_sources.size(); ++j)
      {
      u32bit got = entropy_sources[j]->slow_poll(buffer, buffer.size());

      extractor->update(buffer, got);
      estimate.update(buffer, got, 256);

      if(estimate.value() > 8 * extractor->OUTPUT_LENGTH)
         break;
      }

   /*
   And now add the user-provided input, if any
   */
   if(input_length)
      {
      extractor->update(input, input_length);
      estimate.update(input, input_length);
      }

   // Generate a new output using the HMAC PRF construction,
   // using a CTXinfo of "reseed" and the last K value + counter

   for(u32bit i = 0; i != prf->OUTPUT_LENGTH; ++i)
      prf->update(K);
   prf->update("reseed"); // CTXinfo
   for(u32bit i = 0; i != 4; ++i)
      prf->update(get_byte(i, counter));

   // Add PRF output K(1) with CTXinfo "reseed" to the new SKM
   extractor->update(prf->final());

   // Now derive the new PRK and set the PRF key to that
   SecureVector<byte> prk = extractor->final();
   prf->set_key(prk, prk.size());

   counter = 0;

   // Increase entropy estimate (for is_seeded)
   entropy = std::min<u32bit>(entropy + estimate.value(),
                              8 * extractor->OUTPUT_LENGTH);
   }

/**
* Reseed the internal state
*/
void HMAC_RNG::reseed()
   {
   reseed_with_input(0, 0);
   }

/**
Add user-supplied entropy by reseeding and including this
input among the poll data
*/
void HMAC_RNG::add_entropy(const byte input[], u32bit length)
   {
   reseed_with_input(input, length);
   }

/*************************************************
* Add another entropy source to the list         *
*************************************************/
void HMAC_RNG::add_entropy_source(EntropySource* src)
   {
   entropy_sources.push_back(src);
   }

/*************************************************
* Check if the the pool is seeded                *
*************************************************/
bool HMAC_RNG::is_seeded() const
   {
   return (entropy >= 8 * prf->OUTPUT_LENGTH);
   }

/*************************************************
* Clear memory of sensitive data                 *
*************************************************/
void HMAC_RNG::clear() throw()
   {
   extractor->clear();
   prf->clear();
   K.clear();
   entropy = 0;
   counter = 0;
   }

/*************************************************
* Return the name of this type                   *
*************************************************/
std::string HMAC_RNG::name() const
   {
   return "HMAC_RNG(" + extractor->name() + "," + prf->name() + ")";
   }

/*************************************************
* HMAC_RNG Constructor                           *
*************************************************/
HMAC_RNG::HMAC_RNG(MessageAuthenticationCode* extractor_mac,
                   MessageAuthenticationCode* prf_mac) :
   extractor(extractor_mac), prf(prf_mac)
   {
   entropy = 0;

   // First PRF inputs are all zero, as specified in section 2
   K.create(prf->OUTPUT_LENGTH);
   counter = 0;

   /*
   Normally we want to feedback PRF output into the input to the
   extractor function to ensure a single bad poll does not damage the
   RNG, but obviously that is meaningless to do on the first poll.

   We will want to use the PRF before we set the first key (in
   reseed_with_input), and it is a pain to keep track if it is set or
   not. Since the first time it doesn't matter anyway, just set it to
   a constant: randomize() will not produce output unless is_seeded()
   returns true, and that will only be the case if the estimated
   entropy counter is high enough. That variable is only set when a
   reseeding is performed.
   */
   std::string prf_key = "Botan HMAC_RNG PRF";
   prf->set_key(reinterpret_cast<const byte*>(prf_key.c_str()),
                prf_key.length());
   }

/*************************************************
* HMAC_RNG Destructor                            *
*************************************************/
HMAC_RNG::~HMAC_RNG()
   {
   delete extractor;
   delete prf;

   std::for_each(entropy_sources.begin(), entropy_sources.end(),
                 del_fun<EntropySource>());

   entropy = 0;
   counter = 0;
   }

}
