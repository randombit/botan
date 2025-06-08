/*
* An example of creating a custom RandomNumberGenerator that wraps
* some system specific RNG. For example if you are building for an
* embedded system without an operating system, you will not have
* access to an OS provided RNG like /dev/random. In that case you may
* have to directly invoke some hardware provided by the board,
* possibly through some SDK-specific interface such as
* XTrngpsv_Generate or nrf_crypto_rng_vector_generate
*
* If you end up writing something like this feel free to post it to
* https://github.com/randombit/botan/discussions as others may find it
* useful.
*/

#include <botan/rng.h>

class MySoC_RandomNumberGenerator final : public Botan::Hardware_RNG {
   public:
      // NOLINTNEXTLINE(*-use-equals-default)
      MySoC_RandomNumberGenerator() {
         /*
         * You may need to perform some kind of initialization step here for
         * example using XTrngpsv_Instantiate or nrf_crypto_rng_init,
         * potentially also saving some state as a member variable.
         *
         * If the RNG instance is in global memory, you may need to use some
         * kind of reference counting scheme so that multiple instances of
         * MySoC_RandomNumberGenerator do not repeatedly
         * initialize/shutdown the same state, which is likely to cause
         * problems.
         */
      }

      // NOLINTNEXTLINE(*-use-equals-default)
      ~MySoC_RandomNumberGenerator() override {
         /*
         * You may need to perform some kind of shutdown step here
         */
      }

      // Generally duplicating a RNG internal state is bad:
      MySoC_RandomNumberGenerator(const MySoC_RandomNumberGenerator&) = delete;
      MySoC_RandomNumberGenerator(MySoC_RandomNumberGenerator&&) = delete;
      MySoC_RandomNumberGenerator& operator=(const MySoC_RandomNumberGenerator&) = delete;
      MySoC_RandomNumberGenerator& operator=(MySoC_RandomNumberGenerator&&) = delete;

      bool accepts_input() const override { return false; }

      std::string name() const override { return "my_soc_rng"; }

      bool is_seeded() const override { return true; }

      void fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> /*input*/) override {
         /*
         For the purpose of this example we assume the hardware RNG
         cannot accept any input, so that argument is ignored

         Some SDKs do support accepting input (for example Nordic Semi's
         SDK has a function nrf_crypto_rng_reseed)
         */
         invoke_board_specific_rng(output.data(), output.size());
      }

   private:
      void invoke_board_specific_rng(uint8_t buf[], size_t len) const {
         // Don't do this!
         memset(buf, 0, len);

         // Instead do something like this:

         /*
         if(nrf_crypto_rng_vector_generate(buf, len) != NRF_SUCCESS) {
            throw Exception("RNG failed");
         }
         */
      }

      /*
      * Possibly you need to define some member variable here, such as a XTrngpsv
      */
};

#include <stdio.h>

int main() {
   MySoC_RandomNumberGenerator my_rng;

   printf("%d\n", my_rng.next_byte());

   return 0;
}
