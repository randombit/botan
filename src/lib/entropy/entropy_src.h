/*
* EntropySource
* (C) 2008,2009,2014,2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ENTROPY_H_
#define BOTAN_ENTROPY_H_

#include <botan/api.h>
#include <chrono>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace Botan {

class RandomNumberGenerator;

/**
* Collects entropy on behalf of an RNG which is being seeded
*
* An Entropy_Source is handed an accumulator rather than the RNG itself. A
* source can only contribute data plus a conservative estimate of how much
* entropy that data contains. The RNG later decides, from the accumulated
* estimate, whether the seeding succeeded.
*/
class BOTAN_PUBLIC_API(3, 14) Entropy_Accumulator final {
   public:
      using Sink = std::function<void(std::span<const uint8_t>)>;

      /**
      * @param goal_bits how many bits of entropy the caller hopes to collect
      * @param sink receives all data contributed to the accumulator
      */
      Entropy_Accumulator(size_t goal_bits, Sink sink);

      Entropy_Accumulator(const Entropy_Accumulator& other) = delete;
      Entropy_Accumulator(Entropy_Accumulator&& other) = delete;
      Entropy_Accumulator& operator=(const Entropy_Accumulator& other) = delete;
      Entropy_Accumulator& operator=(Entropy_Accumulator&& other) = delete;
      ~Entropy_Accumulator() = default;

      /**
      * Contribute data along with a conservative estimate of the entropy it
      * contains. Data of unknown or untrusted quality should be contributed
      * with an estimate of zero; it is still mixed into the RNG but not
      * credited. The estimate is capped at the bit length of the data.
      */
      void add(std::span<const uint8_t> data, size_t estimated_entropy_bits);

      /**
      * Contribute the representation of a trivial object, see add
      */
      template <typename T>
         requires std::is_standard_layout_v<T> && std::is_trivial_v<T>
      void add_T(const T& t, size_t estimated_entropy_bits) {
         this->add(std::span(reinterpret_cast<const uint8_t*>(&t), sizeof(T)), estimated_entropy_bits);
      }

      /**
      * @return the entropy estimate accumulated so far, in bits
      */
      size_t bits_collected() const { return m_bits_collected; }

      /**
      * @return the number of bits the caller hopes to collect
      */
      size_t goal_bits() const { return m_goal_bits; }

      /**
      * @return true once the goal has been reached; a source may stop polling early
      */
      bool goal_reached() const { return m_bits_collected >= m_goal_bits; }

   private:
      friend class Entropy_Source;

      size_t bytes_contributed() const { return m_bytes_contributed; }

      /*
      * Credit entropy for data already contributed, capped at the bit length
      * of @p data_bytes. Used only to support the legacy Entropy_Source::poll
      * interface, which reports its estimate after the fact.
      */
      void credit(size_t estimated_entropy_bits, size_t data_bytes);

      Sink m_sink;
      size_t m_goal_bits;
      size_t m_bytes_contributed = 0;
      size_t m_bits_collected = 0;
};

/**
* Abstract interface to a source of entropy
*/
class BOTAN_PUBLIC_API(2, 0) Entropy_Source {
   public:
      /**
      * Return a new entropy source of a particular type, or null
      * Each entropy source may require substantial resources (eg, a file handle
      * or socket instance), so try to share them among multiple RNGs, or just
      * use the preconfigured global list accessed by Entropy_Sources::global_sources()
      */
      static std::unique_ptr<Entropy_Source> create(std::string_view type);

      /**
      * Return a free-form string identifying this entropy source
      */
      virtual std::string name() const = 0;

      /**
      * Perform an entropy gathering poll
      *
      * Contribute data to @p acc, each contribution along with a conservative
      * estimate of the entropy it contains. Data which should be mixed in but
      * not trusted is contributed with an estimate of zero. A source may stop
      * early once acc.goal_reached() returns true.
      *
      * Any implementation of this function should be thread safe; it may be
      * called concurrently in multiple threads if multiple stateful RNGs reseed
      * across different threads.
      *
      * The default implementation exists only to support subclasses which
      * implement the legacy poll interface, and forwards to poll.
      *
      * Note that applications should not directly invoke this function to
      * perform reseeding; use `RandomNumberGenerator::reseed_from` with an
      * instance of `Entropy_Sources` which contains this source.
      *
      * TODO(Botan4) make this a pure virtual
      */
      virtual void gather(Entropy_Accumulator& acc);

      /**
      * Perform an entropy gathering poll (legacy interface)
      * @param rng will be provided with entropy via calls to add_entropy
      * @return conservative estimate of actual entropy added to rng during poll
      *
      * New sources should implement gather instead. The default implementation
      * of this function forwards to gather.
      *
      * TODO(Botan4) remove this function
      */
      virtual size_t poll(RandomNumberGenerator& rng);

      /**
      * Default constructor
      */
      Entropy_Source() = default;
      Entropy_Source(const Entropy_Source& other) = delete;
      Entropy_Source(Entropy_Source&& other) = delete;
      Entropy_Source& operator=(const Entropy_Source& other) = delete;
      Entropy_Source& operator=(Entropy_Source&& other) = delete;

      virtual ~Entropy_Source() = default;
};

/**
* A collection of entropy sources which can be polled together
*/
class BOTAN_PUBLIC_API(2, 0) Entropy_Sources final {
   public:
      /**
      * Access the process-wide set of entropy sources used by default
      * @warning This object is not synchronized. For general usage (eg polling)
      * this is fine. However if you use global_sources().add_source() concurrently
      * with a poll, likely a race leading to memory corruption will occur; only
      * add a new entropy source at the start of main before RNG objects are created.
      */
      static Entropy_Sources& global_sources();

      /**
      * Add an entropy source to this collection
      * @param src the source to add
      */
      void add_source(std::unique_ptr<Entropy_Source> src);

      /**
      * List the entropy sources in this collection
      * @return the names of the enabled sources
      */
      std::vector<std::string> enabled_sources() const;

      /**
      * Poll all sources to collect @p bits of entropy with a @p timeout.
      * Entropy collection is aborted as soon as either the requested number of
      * bits are obtained or the timeout runs out. If the target system does not
      * provide a clock, the timeout is ignored.
      *
      * Note that the timeout is cooperative. If the poll() method of an entropy
      * source blocks forever, this invocation will potentially also block.
      *
      * @returns the number of bits collected from the entropy sources
      *
      * TODO(Botan4) remove this variant, and the <chrono> include above
      */
      BOTAN_DEPRECATED("Use version without a timeout argument")
      size_t poll(RandomNumberGenerator& rng, size_t bits, std::chrono::milliseconds timeout);

      /**
      * Poll all sources into @p acc until its goal is reached
      *
      * This should not be called by applications and is not covered by SemVer
      *
      * @returns the number of bits collected during this call
      */
      size_t _gather(Entropy_Accumulator& acc);

      /**
      * Poll just a single named source into @p acc. Ordinally only used for testing
      *
      * This should not be called by applications and is not covered by SemVer
      *
      * @returns the number of bits collected during this call, or zero if no
      * source with this name exists
      */
      size_t _gather_just(Entropy_Accumulator& acc, std::string_view src);

      /**
      * Poll all sources to collect @p bits of entropy. Entropy collection is
      * aborted as soon as the requested number of bits are obtained.
      *
      * The data is mixed into @p rng without affecting its seeded state. To
      * seed an RNG from entropy sources use RandomNumberGenerator::reseed_from
      *
      * @returns the number of bits collected from the entropy sources
      */
      size_t poll(RandomNumberGenerator& rng, size_t bits);

      /**
      * Poll just a single named source. Ordinally only used for testing
      *
      * The data is mixed into @p rng without affecting its seeded state.
      */
      size_t poll_just(RandomNumberGenerator& rng, std::string_view src);

      /**
      * Create an empty collection of entropy sources
      */
      Entropy_Sources() = default;

      /**
      * Create a collection containing the named entropy sources
      * @param sources the names of the sources to enable
      */
      explicit Entropy_Sources(const std::vector<std::string>& sources);

      Entropy_Sources(const Entropy_Sources& other) = delete;
      Entropy_Sources(Entropy_Sources&& other) = delete;
      Entropy_Sources& operator=(const Entropy_Sources& other) = delete;
      Entropy_Sources& operator=(Entropy_Sources&& other) = delete;
      ~Entropy_Sources() = default;

   private:
      std::vector<std::unique_ptr<Entropy_Source>> m_srcs;
};

}  // namespace Botan

#endif
