/*
* (C) 2016,2019,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_RNG_PROCESSOR_RNG_H_
#define BOTAN_RNG_PROCESSOR_RNG_H_

#include <botan/rng.h>

namespace Botan {

/**
* Directly invokes a CPU specific instruction to generate random numbers.
* On x86, the RDRAND instruction is used.
* on POWER, the DARN instruction is used.
*/
class BOTAN_PUBLIC_API(2, 15) Processor_RNG final : public Hardware_RNG {
   public:
      /**
      * Constructor will throw if CPU does not have RDRAND bit set
      */
      Processor_RNG();

      /**
      * Return true if RNG instruction is available on the current processor
      */
      static bool available();

      bool accepts_input() const override { return false; }

      bool is_seeded() const override { return true; }

      /*
      * No way to reseed processor provided generator, so reseed is ignored
      */
      size_t reseed(Entropy_Sources& src, size_t bits, std::chrono::milliseconds timeout) override;

      std::string name() const override;

   private:
      void fill_bytes_with_input(std::span<uint8_t> out, std::span<const uint8_t> in) override;
};

}  // namespace Botan

#endif
