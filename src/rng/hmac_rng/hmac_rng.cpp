/*
* HMAC_RNG
* (C) 2008-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/hmac_rng.h>
#include <botan/loadstor.h>
#include <botan/xor_buf.h>
#include <botan/util.h>
#include <botan/stl_util.h>
#include <algorithm>

namespace Botan {

namespace {

void hmac_prf(MessageAuthenticationCode* prf,
              MemoryRegion<byte>& K,
              u32bit& counter,
              const std::string& label)
   {
   prf->update(K, K.size());
   prf->update(label);
   for(u32bit i = 0; i != 4; ++i)
      prf->update(get_byte(i, counter));
   prf->final(K);

   ++counter;
   }

}

/**
* Generate a buffer of random bytes
*/
void HMAC_RNG::randomize(byte out[], u32bit length)
   {
   if(!is_seeded())
      throw PRNG_Unseeded(name());

   /*
    HMAC KDF as described in E-t-E, using a CTXinfo of "rng"
   */
   while(length)
      {
      hmac_prf(prf, K, counter, "rng");

      const u32bit copied = std::min(K.size(), length);

      copy_mem(out, K.begin(), copied);
      out += copied;
      length -= copied;
      }
   }

/**
* Reseed the internal state, also accepting user input to include
*/
void HMAC_RNG::reseed_with_input(u32bit poll_bits,
                                 const byte input[], u32bit input_length)
   {
   /**
   Using the terminology of E-t-E, XTR is the MAC function (normally
   HMAC) seeded with XTS (below) and we form SKM, the key material, by
   fast polling each source, and then slow polling as many as we think
   we need (in the following loop), and feeding all of the poll
   results, along with any optional user input, along with, finally,
   feedback of the current PRK value, into the extractor function.
   */

   Entropy_Accumulator_BufferedComputation accum(*extractor, poll_bits);

   if(!entropy_sources.empty())
      {
      u32bit poll_attempt = 0;

      while(!accum.polling_goal_achieved() && poll_attempt < poll_bits)
         {
         entropy_sources[poll_attempt % entropy_sources.size()]->poll(accum);
         ++poll_attempt;
         }
      }

   // And now add the user-provided input, if any
   if(input_length)
      accum.add(input, input_length, 1);

   /*
   It is necessary to feed forward poll data. Otherwise, a good poll
   (collecting a large amount of conditional entropy) followed by a
   bad one (collecting little) would be unsafe. Do this by generating
   new PRF outputs using the previous key and feeding them into the
   extractor function.

   Cycle the RNG once (CTXinfo="rng"), then generate a new PRF output
   using the CTXinfo "reseed". Provide these values as input to the
   extractor function.
   */
   hmac_prf(prf, K, counter, "rng");
   extractor->update(K); // K is the CTXinfo=rng PRF output

   hmac_prf(prf, K, counter, "reseed");
   extractor->update(K); // K is the CTXinfo=reseed PRF output

   /* Now derive the new PRK using everything that has been fed into
      the extractor, and set the PRF key to that */
   prf->set_key(extractor->final());

   // Now generate a new PRF output to use as the XTS extractor salt
   hmac_prf(prf, K, counter, "xts");
   extractor->set_key(K, K.size());

   // Reset state
   K.clear();
   counter = 0;

   if(input_length || accum.bits_collected() >= poll_bits)
      seeded = true;
   }

/**
* Reseed the internal state
*/
void HMAC_RNG::reseed(u32bit poll_bits)
   {
   reseed_with_input(poll_bits, 0, 0);
   }

/**
* Add user-supplied entropy by reseeding and including this
* input among the poll data
*/
void HMAC_RNG::add_entropy(const byte input[], u32bit length)
   {
   reseed_with_input(0, input, length);
   }

/**
* Add another entropy source to the list
*/
void HMAC_RNG::add_entropy_source(EntropySource* src)
   {
   entropy_sources.push_back(src);
   }

/*
* Clear memory of sensitive data
*/
void HMAC_RNG::clear() throw()
   {
   extractor->clear();
   prf->clear();
   K.clear();
   counter = 0;
   seeded = false;
   }

/**
* Return the name of this type
*/
std::string HMAC_RNG::name() const
   {
   return "HMAC_RNG(" + extractor->name() + "," + prf->name() + ")";
   }

/**
* HMAC_RNG Constructor
*/
HMAC_RNG::HMAC_RNG(MessageAuthenticationCode* extractor_mac,
                   MessageAuthenticationCode* prf_mac) :
   extractor(extractor_mac), prf(prf_mac)
   {
   // First PRF inputs are all zero, as specified in section 2
   K.create(prf->OUTPUT_LENGTH);
   counter = 0;
   seeded = false;

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

   /*
   This will be used as the first XTS value when extracting input.
   XTS values after this one are generated using the PRF.

   If I understand the E-t-E paper correctly (specifically Section 4),
   using this fixed extractor key is safe to do.
   */
   std::string xts = "Botan HMAC_RNG XTS";
   extractor->set_key(reinterpret_cast<const byte*>(xts.c_str()),
                      xts.length());
   }

/**
* HMAC_RNG Destructor
*/
HMAC_RNG::~HMAC_RNG()
   {
   delete extractor;
   delete prf;

   std::for_each(entropy_sources.begin(), entropy_sources.end(),
                 del_fun<EntropySource>());

   counter = 0;
   }

}
