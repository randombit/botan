// Define and use custom entropy sources

// includes needed for example Entropy_Source implementations
#include <botan/entropy_src.h>
#include <botan/rng.h>
#include <chrono>

// includes needed for main
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <iostream>

namespace {

size_t call_hardware_specific_rng(uint8_t buf[], size_t len) {
   // Hopefully your RNG works better than this one:
   std::memset(buf, 0x42, len);

   // function returns # of bytes written
   return len;
}

/**
* Example of an entropy source that invokes some external RNG,
* for example by invoking a hardware RNG on a SoC
*/
class Hardware_RNG_Entropy_Source : public Botan::Entropy_Source {
   public:
      std::string name() const override { return "hw_rng"; }

      size_t poll(Botan::RandomNumberGenerator& rng) override {
         // the amount of entropy we desire (in bits)
         const size_t poll_goal = 256;

         uint8_t buf[poll_goal / 8];
         const size_t written = call_hardware_specific_rng(buf, sizeof(buf));
         rng.add_entropy(buf, written);

         // return estimate of bits of entropy written to rng state
         return written * 8;
      }
};

uint64_t high_resolution_clock() {
   // Just using std clock as an example
   // Use a processor counter if you have access to one
   auto now = std::chrono::high_resolution_clock::now().time_since_epoch();
   return std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
}

/**
* Example of an entropy source based on timer information.
*
* Historically such entropy sources have not been very secure. However on some
* very limited embedded systems, there is no OS and no hardware RNG. In that
* case you are somewhat on your own and something like the below may be the best
* you can do.
*
* If you don't even have a clock, you have problems.
*/
class Timer_Entropy_Source : public Botan::Entropy_Source {
   public:
      std::string name() const override { return "timer_hack"; }

      size_t poll(Botan::RandomNumberGenerator& rng) override {
         // the amount of entropy we desire (in bits)
         const size_t poll_goal = 256;

         /*
         Just query the clock N times, once for each bit in our goal.

         This is not very secure, but on some embedded systems it can be tricky
         to do much more than this.

         If you have access to multiple different hardware clocks, query each of
         them within the loop. This may gain you a bit of uncertainty due to
         drift between the different clocks.
         */
         for(size_t i = 0; i != poll_goal; ++i) {
            const uint64_t clock = high_resolution_clock();

            // If the clock is fast, this loop will almost always exit immediately and
            // the counter will just be zero.
            //
            // OTOH if the clock is fast, then the clock reading itself will
            // have significant uncertainty.
            uint32_t counter = 0;
            while(high_resolution_clock() == clock) {
               ++counter;
            }

            rng.add_entropy_T(clock);
            rng.add_entropy_T(counter);

            // Examine the output of this approach on your system before trusting it!
            //printf("%016X %08X\n", clock, counter);
         }

         // return estimate of entropy written to rng state
         return poll_goal;
      }
};

}  // namespace

int main() {
   Botan::Entropy_Sources es;
   es.add_source(std::make_unique<Timer_Entropy_Source>());
   es.add_source(std::make_unique<Hardware_RNG_Entropy_Source>());
   Botan::AutoSeeded_RNG rng(es);
   std::cout << hex_encode(rng.random_vec(32)) << '\n';
}
