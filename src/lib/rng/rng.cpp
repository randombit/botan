/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/rng.h>
#include <botan/loadstor.h>
#include <botan/internal/os_utils.h>

#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
  #include <botan/auto_rng.h>
#endif

namespace Botan {

void RandomNumberGenerator::randomize_with_ts_input(byte output[], size_t output_len)
   {
   /*
   Form additional input which is provided to the PRNG implementation
   to paramaterize the KDF output.
   */
   byte additional_input[16] = { 0 };
   store_le(OS::get_system_timestamp_ns(), additional_input);
   store_le(OS::get_processor_timestamp(), additional_input + 8);

   randomize_with_input(output, output_len, additional_input, sizeof(additional_input));
   }

void RandomNumberGenerator::randomize_with_input(byte output[], size_t output_len,
                                                 const byte input[], size_t input_len)
   {
   this->add_entropy(input, input_len);
   this->randomize(output, output_len);
   }

size_t RandomNumberGenerator::reseed(Entropy_Sources& srcs,
                                     size_t poll_bits,
                                     std::chrono::milliseconds poll_timeout)
   {
   return srcs.poll(*this, poll_bits, poll_timeout);
   }

void RandomNumberGenerator::reseed_from_rng(RandomNumberGenerator& rng, size_t poll_bits)
   {
   secure_vector<byte> buf(poll_bits / 8);
   rng.randomize(buf.data(), buf.size());
   this->add_entropy(buf.data(), buf.size());
   }

RandomNumberGenerator* RandomNumberGenerator::make_rng()
   {
#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
   return new AutoSeeded_RNG;
#else
   throw Exception("make_rng failed, no AutoSeeded_RNG in this build");
#endif
   }

#if defined(BOTAN_TARGET_OS_HAS_THREADS)
Serialized_RNG::Serialized_RNG() : m_rng(RandomNumberGenerator::make_rng()) {}
#endif

}
