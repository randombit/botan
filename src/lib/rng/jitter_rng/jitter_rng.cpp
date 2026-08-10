/*
* CPU Jitter Random Number Generator
* (C) 2024 Planck Security S.A.
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/jitter_rng.h>

#include <botan/assert.h>
#include <botan/exceptn.h>
#include <botan/mutex.h>
#include <botan/internal/int_utils.h>

#include <jitterentropy.h>

/*
* BSI AIS 20/31 NTG.1 support (JENT_NTG1) was added in jitterentropy 3.7.0.
* The version encoding used by JENT_VERSION and jent_version() is
* major * 1000000 + minor * 10000 + patchlevel * 100.
*/
#define BOTAN_JITTER_RNG_NTG1_MIN_VERSION 3070000

#if defined(JENT_NTG1) && JENT_VERSION >= BOTAN_JITTER_RNG_NTG1_MIN_VERSION
   #define BOTAN_JITTER_RNG_HAS_NTG1
#endif

namespace Botan {

class Jitter_RNG_Internal final {
   public:
      Jitter_RNG_Internal(Jitter_RNG::Mode mode, size_t osr);
      ~Jitter_RNG_Internal();
      void collect_into_buffer(std::span<uint8_t> buf);

      Jitter_RNG_Internal(const Jitter_RNG_Internal& other) = delete;
      Jitter_RNG_Internal(Jitter_RNG_Internal&& other) = delete;
      Jitter_RNG_Internal& operator=(const Jitter_RNG_Internal& other) = delete;
      Jitter_RNG_Internal& operator=(Jitter_RNG_Internal&& other) = delete;

   private:
      static unsigned int flags_for_mode(Jitter_RNG::Mode mode);

      mutex_type m_mutex;
      rand_data* m_rand_data;
};

unsigned int Jitter_RNG_Internal::flags_for_mode(Jitter_RNG::Mode mode) {
   switch(mode) {
      case Jitter_RNG::Mode::Default:
         return 0;
      case Jitter_RNG::Mode::FIPS:
         // enable the SP800-90B health tests
         return JENT_FORCE_FIPS;
      case Jitter_RNG::Mode::NTG1:
#if defined(BOTAN_JITTER_RNG_HAS_NTG1)
         /*
         * An older runtime library would silently ignore the unknown flag bit
         * and hand out an entropy collector which is not NTG.1 compliant, so
         * the version the headers were taken from is not sufficient here.
         */
         if(jent_version() < BOTAN_JITTER_RNG_NTG1_MIN_VERSION) {
            throw Not_Implemented("The linked jitterentropy library is too old to support NTG.1");
         }

         /*
         * Enable BSI AIS 20/31 3.0 NTG.1 mode
         * NTG.1 implies FIPS mode within jitterentropy
         */
         return JENT_NTG1;
#else
         throw Not_Implemented("Botan was built against a jitterentropy version without NTG.1 support");
#endif
   }

   BOTAN_ASSERT_UNREACHABLE();
}

bool Jitter_RNG::ntg1_supported() {
#if defined(BOTAN_JITTER_RNG_HAS_NTG1)
   return jent_version() >= BOTAN_JITTER_RNG_NTG1_MIN_VERSION;
#else
   return false;
#endif
}

Jitter_RNG_Internal::Jitter_RNG_Internal(Jitter_RNG::Mode mode, size_t osr) {
   const auto oversampling_rate =
      checked_cast_to_or_throw<unsigned int, Invalid_Argument>(osr, "Jitter_RNG oversampling rate is too large");
   const unsigned int flags = flags_for_mode(mode);

   /*
   * This performs new health checks for the chosen osr and flags.
   * It is safe to do this multiple times, it will not alter existing
   * instances.
   *
   * If flags and osr are used, use the same values for init and alloc.
   */
   const int result = jent_entropy_init_ex(oversampling_rate, flags);

   // no further details documented regarding the return value
   if(result != 0) {
      throw Internal_Error("Jitter_RNG_Internal initialization failed");
   }

   m_rand_data = jent_entropy_collector_alloc(oversampling_rate, flags);
   if(m_rand_data == nullptr) {
      throw Internal_Error("Jitter_RNG_Internal collector allocation failed");
   }
}

Jitter_RNG_Internal::~Jitter_RNG_Internal() {
   const lock_guard_type<mutex_type> lock(m_mutex);
   if(m_rand_data != nullptr) {
      jent_entropy_collector_free(m_rand_data);
      m_rand_data = nullptr;
   }
}

void Jitter_RNG_Internal::collect_into_buffer(std::span<uint8_t> buf) {
   if(buf.empty()) {
      return;
   }

   const lock_guard_type<mutex_type> lock(m_mutex);
   BOTAN_STATE_CHECK(m_rand_data != nullptr);

   ssize_t num_bytes = jent_read_entropy_safe(&m_rand_data, reinterpret_cast<char*>(buf.data()), buf.size());
   if(num_bytes < 0) {
      const auto error_msg = [&]() -> std::string_view {
         switch(num_bytes) {
            case -1:  // should never happen because of the check above
               return "JitterRNG: Uninitialized";
            case -2:
               return "JitterRNG: SP800-90B repetition count online health test failed";
            case -3:
               return "JitterRNG: SP800-90B adaptive proportion online health test failed";
            case -4:
               return "JitterRNG: Internal timer generator could not be initialized";
            case -5:
               return "JitterRNG: LAG predictor health test failed";
            case -6:
               return "JitterRNG: Repetition count test (RCT) failed permanently";
            case -7:
               return "JitterRNG: Adaptive proportion test (APT) failed permanently";
            case -8:
               return "JitterRNG: LAG prediction test failed permanently";
            // the following are only returned by jitterentropy 3.7.0 and newer
            case -9:
               return "JitterRNG: Repetition count test with memory failed";
            case -10:
               return "JitterRNG: Repetition count test with memory failed permanently";
            default:
               return "JitterRNG: Error reading entropy";
         }
      }();
      throw Internal_Error(error_msg);
   }

   // According to the docs, `jent_read_entropy_safe` itself runs its logic as often
   // as necessary to gather the requested number of bytes,
   // so this should actually never happen.
   BOTAN_ASSERT(static_cast<size_t>(num_bytes) == buf.size(), "JitterRNG produced the expected number of bytes");
}

Jitter_RNG::Jitter_RNG(Mode mode, size_t osr) : m_jitter{std::make_unique<Jitter_RNG_Internal>(mode, osr)} {}

Jitter_RNG::~Jitter_RNG() = default;

void Jitter_RNG::clear() {
   /* ignored - jitterentropy library does not support this */
}

void Jitter_RNG::fill_bytes_with_input(std::span<uint8_t> out, std::span<const uint8_t> in) {
   BOTAN_UNUSED(in);

   m_jitter->collect_into_buffer(out);
}

}  // namespace Botan
