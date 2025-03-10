/*
* Entropy Source Polling
* (C) 2008-2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/entropy_src.h>

#include <botan/assert.h>
#include <botan/rng.h>
#include <botan/internal/target_info.h>

#if defined(BOTAN_HAS_SYSTEM_RNG)
   #include <botan/system_rng.h>
#endif

#if defined(BOTAN_HAS_PROCESSOR_RNG)
   #include <botan/processor_rng.h>
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_RDSEED)
   #include <botan/internal/rdseed.h>
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_WIN32)
   #include <botan/internal/es_win32.h>
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_GETENTROPY)
   #include <botan/internal/getentropy.h>
#endif

#if defined(BOTAN_HAS_JITTER_RNG)
   #include <botan/jitter_rng.h>
#endif

namespace Botan {

namespace {

#if defined(BOTAN_HAS_SYSTEM_RNG)

class System_RNG_EntropySource final : public Entropy_Source {
   public:
      size_t poll(RandomNumberGenerator& rng) override {
         const size_t poll_bits = RandomNumberGenerator::DefaultPollBits;
         rng.reseed_from_rng(system_rng(), poll_bits);
         return poll_bits;
      }

      std::string name() const override { return "system_rng"; }
};

#endif

#if defined(BOTAN_HAS_PROCESSOR_RNG)

class Processor_RNG_EntropySource final : public Entropy_Source {
   public:
      size_t poll(RandomNumberGenerator& rng) override {
         /*
         * Intel's documentation for RDRAND at
         * https://software.intel.com/en-us/articles/intel-digital-random-number-generator-drng-software-implementation-guide
         * claims that software can guarantee a reseed event by polling enough data:
         * "There is an upper bound of 511 samples per seed in the implementation
         * where samples are 128 bits in size and can provide two 64-bit random
         * numbers each."
         *
         * By requesting 65536 bits we are asking for 512 samples and thus are assured
         * that at some point in producing the output, at least one reseed of the
         * internal state will occur.
         *
         * The reseeding conditions of the POWER and ARM processor RNGs are not known
         * but probably work in a somewhat similar manner. The exact amount requested
         * may be tweaked if and when such conditions become publically known.
         */
         const size_t poll_bits = 65536;
         rng.reseed_from_rng(m_hwrng, poll_bits);
         // Avoid trusting a black box, don't count this as contributing entropy:
         return 0;
      }

      std::string name() const override { return m_hwrng.name(); }

   private:
      Processor_RNG m_hwrng;
};

#endif

#if defined(BOTAN_HAS_JITTER_RNG)

class Jitter_RNG_EntropySource final : public Entropy_Source {
   public:
      size_t poll(RandomNumberGenerator& rng) override {
         rng.reseed_from_rng(m_rng);
         return RandomNumberGenerator::DefaultPollBits;
      }

      std::string name() const override { return m_rng.name(); }

   private:
      Jitter_RNG m_rng;
};

#endif

}  // namespace

std::unique_ptr<Entropy_Source> Entropy_Source::create(std::string_view name) {
#if defined(BOTAN_HAS_SYSTEM_RNG)
   if(name == "system_rng") {
      return std::make_unique<System_RNG_EntropySource>();
   }
#endif

#if defined(BOTAN_HAS_PROCESSOR_RNG)
   if(name == "hwrng") {
      if(Processor_RNG::available()) {
         return std::make_unique<Processor_RNG_EntropySource>();
      }
   }
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_RDSEED)
   if(name == "rdseed") {
      return std::make_unique<Intel_Rdseed>();
   }
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_GETENTROPY)
   if(name == "getentropy") {
      return std::make_unique<Getentropy>();
   }
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_WIN32)
   if(name == "system_stats") {
      return std::make_unique<Win32_EntropySource>();
   }
#endif

#if defined(BOTAN_HAS_JITTER_RNG)
   if(name == "jitter_rng") {
      return std::make_unique<Jitter_RNG_EntropySource>();
   }
#endif

   BOTAN_UNUSED(name);
   return nullptr;
}

void Entropy_Sources::add_source(std::unique_ptr<Entropy_Source> src) {
   if(src) {
      m_srcs.push_back(std::move(src));
   }
}

std::vector<std::string> Entropy_Sources::enabled_sources() const {
   std::vector<std::string> sources;
   sources.reserve(m_srcs.size());
   for(const auto& src : m_srcs) {
      sources.push_back(src->name());
   }
   return sources;
}

size_t Entropy_Sources::poll(RandomNumberGenerator& rng, size_t poll_bits, std::chrono::milliseconds timeout) {
#if defined(BOTAN_TARGET_OS_HAS_SYSTEM_CLOCK)
   typedef std::chrono::system_clock clock;
   auto timeout_expired = [to = clock::now() + timeout] { return clock::now() > to; };
#else
   auto timeout_expired = [] { return false; };
#endif

   size_t bits_collected = 0;

   for(auto& src : m_srcs) {
      bits_collected += src->poll(rng);

      if(bits_collected >= poll_bits || timeout_expired()) {
         break;
      }
   }

   return bits_collected;
}

size_t Entropy_Sources::poll_just(RandomNumberGenerator& rng, std::string_view the_src) {
   for(auto& src : m_srcs) {
      if(src->name() == the_src) {
         return src->poll(rng);
      }
   }

   return 0;
}

Entropy_Sources::Entropy_Sources(const std::vector<std::string>& sources) {
   for(auto&& src_name : sources) {
      add_source(Entropy_Source::create(src_name));
   }
}

Entropy_Sources& Entropy_Sources::global_sources() {
   static Entropy_Sources global_entropy_sources({"rdseed", "hwrng", "getentropy", "system_rng", "system_stats"});

   return global_entropy_sources;
}

}  // namespace Botan
