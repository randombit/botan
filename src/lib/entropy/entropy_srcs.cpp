/*
* Entropy Source Polling
* (C) 2008-2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/entropy_src.h>

#include <botan/assert.h>
#include <botan/exceptn.h>
#include <botan/rng.h>
#include <botan/internal/fmt.h>
#include <botan/internal/target_info.h>
#include <algorithm>

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

/*
* Stand-in RNG handed to sources which implement the legacy
* Entropy_Source::poll interface. It forwards any input to the accumulator
* and refuses to produce output, so the source cannot affect the RNG which
* is actually being seeded.
*
* TODO(Botan4) this can be removed when Entropy_Source::poll is
*/
class Legacy_Poll_RNG final : public RandomNumberGenerator {
   public:
      explicit Legacy_Poll_RNG(Entropy_Accumulator& acc) : m_acc(acc) {}

      bool accepts_input() const override { return true; }

      bool is_seeded() const override { return false; }

      void clear() override {}

      std::string name() const override { return "Legacy_Poll_RNG"; }

   private:
      void fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> input) override {
         if(!output.empty()) {
            throw Invalid_State("An entropy source cannot draw output from the RNG being seeded");
         }
         // Credit is assigned from the return value of poll once it completes
         m_acc.add(input, 0);
      }

      Entropy_Accumulator& m_acc;
};

Entropy_Accumulator::Sink additional_input_sink(RandomNumberGenerator& rng) {
   return [&rng](std::span<const uint8_t> in) { rng.randomize_with_input({}, in); };
}

#if defined(BOTAN_HAS_SYSTEM_RNG)

class System_RNG_EntropySource final : public Entropy_Source {
   public:
      void gather(Entropy_Accumulator& acc) override {
         const size_t poll_bits = RandomNumberGenerator::DefaultPollBits;
         acc.add(system_rng().random_vec(poll_bits / 8), poll_bits);
      }

      std::string name() const override { return "system_rng"; }
};

#endif

#if defined(BOTAN_HAS_PROCESSOR_RNG)

class Processor_RNG_EntropySource final : public Entropy_Source {
   public:
      void gather(Entropy_Accumulator& acc) override {
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
         * may be tweaked if and when such conditions become publicly known.
         */
         const size_t poll_bits = 65536;
         // Avoid trusting a black box, don't count this as contributing entropy:
         acc.add(m_hwrng.random_vec(poll_bits / 8), 0);
      }

      std::string name() const override { return m_hwrng.name(); }

   private:
      Processor_RNG m_hwrng;
};

#endif

#if defined(BOTAN_HAS_JITTER_RNG)

class Jitter_RNG_EntropySource final : public Entropy_Source {
   public:
      Jitter_RNG_EntropySource(Jitter_RNG::Mode mode) : m_rng(mode) {}

      void gather(Entropy_Accumulator& acc) override {
         const size_t poll_bits = RandomNumberGenerator::DefaultPollBits;
         acc.add(m_rng.random_vec(poll_bits / 8), poll_bits);
      }

      std::string name() const override { return m_rng.name(); }

   private:
      Jitter_RNG m_rng;
};

#endif

}  // namespace

Entropy_Accumulator::Entropy_Accumulator(size_t goal_bits, Sink sink) :
      m_sink(std::move(sink)), m_goal_bits(goal_bits) {
   BOTAN_ARG_CHECK(m_sink != nullptr, "Entropy_Accumulator requires a sink");
}

void Entropy_Accumulator::add(std::span<const uint8_t> data, size_t estimated_entropy_bits) {
   if(data.empty()) {
      return;
   }

   m_sink(data);
   m_bytes_contributed += data.size();
   credit(estimated_entropy_bits, data.size());
}

void Entropy_Accumulator::credit(size_t estimated_entropy_bits, size_t data_bytes) {
   // Never credit more entropy than the data could possibly contain
   m_bits_collected += std::min(estimated_entropy_bits, 8 * data_bytes);
}

void Entropy_Source::gather(Entropy_Accumulator& acc) {
   Legacy_Poll_RNG rng(acc);
   const size_t bytes_before = acc.bytes_contributed();
   const size_t bits = this->poll(rng);
   // Only the data provided during this poll can back the reported estimate
   acc.credit(bits, acc.bytes_contributed() - bytes_before);
}

size_t Entropy_Source::poll(RandomNumberGenerator& rng) {
   // A source implementing neither interface would otherwise recurse forever
   if(dynamic_cast<Legacy_Poll_RNG*>(&rng) != nullptr) {
      throw Not_Implemented(fmt("Entropy source {} does not implement gather", name()));
   }

   Entropy_Accumulator acc(RandomNumberGenerator::DefaultPollBits, additional_input_sink(rng));
   this->gather(acc);
   return acc.bits_collected();
}

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
      return std::make_unique<Jitter_RNG_EntropySource>(Jitter_RNG::Mode::Default);
   }
   if(name == "jitter_rng_fips") {
      return std::make_unique<Jitter_RNG_EntropySource>(Jitter_RNG::Mode::FIPS);
   }
   if(name == "jitter_rng_ntg1") {
      return std::make_unique<Jitter_RNG_EntropySource>(Jitter_RNG::Mode::NTG1);
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

size_t Entropy_Sources::_gather(Entropy_Accumulator& acc) {
   const size_t bits_before = acc.bits_collected();

   for(auto& src : m_srcs) {
      if(acc.goal_reached()) {
         break;
      }

      src->gather(acc);
   }

   return acc.bits_collected() - bits_before;
}

size_t Entropy_Sources::_gather_just(Entropy_Accumulator& acc, std::string_view the_src) {
   for(auto& src : m_srcs) {
      if(src->name() == the_src) {
         const size_t bits_before = acc.bits_collected();
         src->gather(acc);
         return acc.bits_collected() - bits_before;
      }
   }

   return 0;
}

size_t Entropy_Sources::poll(RandomNumberGenerator& rng, size_t poll_bits, std::chrono::milliseconds timeout) {
#if defined(BOTAN_TARGET_OS_HAS_SYSTEM_CLOCK)
   typedef std::chrono::system_clock clock;
   auto timeout_expired = [to = clock::now() + timeout] { return clock::now() > to; };
#else
   auto timeout_expired = [] { return false; };
#endif

   Entropy_Accumulator acc(poll_bits, additional_input_sink(rng));

   for(auto& src : m_srcs) {
      src->gather(acc);

      if(acc.goal_reached() || timeout_expired()) {
         break;
      }
   }

   return acc.bits_collected();
}

size_t Entropy_Sources::poll(RandomNumberGenerator& rng, size_t poll_bits) {
   Entropy_Accumulator acc(poll_bits, additional_input_sink(rng));
   return this->_gather(acc);
}

size_t Entropy_Sources::poll_just(RandomNumberGenerator& rng, std::string_view the_src) {
   Entropy_Accumulator acc(RandomNumberGenerator::DefaultPollBits, additional_input_sink(rng));
   return this->_gather_just(acc, the_src);
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
