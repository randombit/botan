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
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace Botan {

class RandomNumberGenerator;

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
      * @return name identifying this entropy source
      */
      virtual std::string name() const = 0;

      /**
      * Perform an entropy gathering poll
      * @param rng will be provided with entropy via calls to add_entropy
      * @return conservative estimate of actual entropy added to rng during poll
      */
      virtual size_t poll(RandomNumberGenerator& rng) = 0;

      Entropy_Source() = default;
      Entropy_Source(const Entropy_Source& other) = delete;
      Entropy_Source(Entropy_Source&& other) = delete;
      Entropy_Source& operator=(const Entropy_Source& other) = delete;

      virtual ~Entropy_Source() = default;
};

class BOTAN_PUBLIC_API(2, 0) Entropy_Sources final {
   public:
      static Entropy_Sources& global_sources();

      void add_source(std::unique_ptr<Entropy_Source> src);

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
      */
      size_t poll(RandomNumberGenerator& rng, size_t bits, std::chrono::milliseconds timeout);

      /**
      * Poll just a single named source. Ordinally only used for testing
      */
      size_t poll_just(RandomNumberGenerator& rng, std::string_view src);

      Entropy_Sources() = default;
      explicit Entropy_Sources(const std::vector<std::string>& sources);

      Entropy_Sources(const Entropy_Sources& other) = delete;
      Entropy_Sources(Entropy_Sources&& other) = delete;
      Entropy_Sources& operator=(const Entropy_Sources& other) = delete;

   private:
      std::vector<std::unique_ptr<Entropy_Source>> m_srcs;
};

}  // namespace Botan

#endif
