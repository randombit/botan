/*
* Define and use custom entropy sources
*
* This example assumes you are building for an embedded system without an
* operating system.
*
* If the system you are deploying to has an operating system, it probably has an
* RNG already. If so, it is probably already supported by System_RNG and the
* built-in entropy sources. Use that.
*
* If your OS provided RNG is not supported by System_RNG, open an issue on Github.
*/

// includes needed for example Entropy_Source implementations
#include <botan/entropy_src.h>
#include <botan/rng.h>
#include <array>
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
class Hardware_RNG_Entropy_Source final : public Botan::Entropy_Source {
   public:
      std::string name() const override { return "hw_rng"; }

      size_t poll(Botan::RandomNumberGenerator& rng) override {
         // the amount of entropy we desire (in bits)
         constexpr size_t poll_goal = 256;

         uint8_t buf[poll_goal / 8];
         const size_t written = call_hardware_specific_rng(buf, sizeof(buf));
         rng.add_entropy(buf, written);

         // return estimate of bits of entropy written to rng state
         return written * 8;
      }
};

/**
* Example of an entropy source based on timer information.
*
* Historically such entropy sources have not been very secure. However on some
* very limited embedded systems, there is no OS and no hardware RNG. In that
* case you are somewhat on your own and something like the below may be the best
* you can do.
*
* If your board somehow doesn't even have a timer, you have a problem!
*/
class Timer_Entropy_Source final : public Botan::Entropy_Source {
   public:
      std::string name() const override { return "timer_hack"; }

      size_t poll(Botan::RandomNumberGenerator& rng) override {
         // the amount of entropy we desire (in bits)
         constexpr size_t poll_goal = 256;

         /*
         * You could here also introduce additional information that varies
         * between machines or over time; for example, machine identifiers
         * (serial numbers, MAC address, IP address, etc) or any internal
         * statistical information that is available, such as the value of a
         * global counter that tracks the number of requests processed so far.
         * For example Nordic Semi's hw_id_get returns various pieces of device
         * specific information.
         *
         * These are not themselves good sources of entropy! Most are going to
         * be either public or easily guessable. They do have the function of
         * ensuring that, if the RNG seeding we're attempting to perform below
         * fails, at least multiple machines won't end up producing the _same_
         * sequence of random bits.
         */

         /*
         Query the timer N times, once for each bit in our goal. Then count how
         many times the timer, when read again in a tight loop, repeats the same
         output. Include both the timer value and the repetition count as part
         of the RNG input.

         This is not necessarily secure, depending on the characteristics of the
         timer, but on some embedded systems it can be tricky to do much better
         than this.

         If you have access to multiple different hardware timers/clocks, query
         each of them within the loop. This may gain you a bit of uncertainty
         due to drift between the different timers.
         */

         for(size_t i = 0; i != poll_goal; ++i) {
            uint64_t timer = high_resolution_timer();

            // If the timer is fast, this loop will almost always exit immediately and
            // the counter will just be zero.
            //
            // OTOH if the timer is fast, then the timer reading itself will
            // have significant uncertainty.
            uint32_t counter = 0;
            while(high_resolution_timer() == timer) {
               ++counter;
            }

            // Examine the output of this approach on your system before trusting it!
            // printf("%016lX %016X\n", timer, counter);

            rng.add_entropy_T(timer);
            rng.add_entropy_T(counter);
         }

         // return estimate of entropy written to rng state
         return poll_goal;
      }

   private:
      static uint64_t high_resolution_timer() {
         /* Insert call to your system specific timer source here
         *
         * Just using std clock here for example purposes, and intentionally
         * truncating the clock to microseconds (emulating a 1 MHz timer)
         *
         * On a SoC where this example is relevant, you would probably instead
         * have to use a BSP API such as XTime_GetTime.
         *
         * On Aarch64 you may be able to use the processor cycle counter directly:
         *
         *  uint64_t value;
         *  asm volatile("mrs %0, CNTVCT_EL0" : "=r"(value));
         *  return value;
         */
         auto now = std::chrono::high_resolution_clock::now().time_since_epoch();
         return std::chrono::duration_cast<std::chrono::microseconds>(now).count();
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
