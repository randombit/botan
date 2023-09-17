/*
 * SHAKE-128 and SHAKE-256 as XOFs
 *
 * (C) 2016-2023 Jack Lloyd
 *     2022-2023 Fabian Albert, Michael Boric, René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_SHAKE_XOF_H_
#define BOTAN_SHAKE_XOF_H_

#include <botan/xof.h>
#include <botan/internal/keccak_perm.h>

#include <vector>

namespace Botan {

/**
 * Base class for SHAKE-based XOFs
 */
class SHAKE_XOF : public XOF {
   protected:
      /**
       * Defines a concrete instance of a SHAKE XOF.
       *
       * @param capacity  either 256 or 512
       */
      SHAKE_XOF(size_t capacity);

   public:
      std::string provider() const final { return m_keccak.provider(); }

      size_t block_size() const final { return m_keccak.byte_rate(); }

      bool accepts_input() const final { return !m_output_generated; }

   private:
      void add_data(std::span<const uint8_t> input) final;
      void generate_bytes(std::span<uint8_t> output) final;
      void reset() final;

   private:
      Keccak_Permutation m_keccak;
      bool m_output_generated;
};

/**
 * SHAKE-128 as defined in FIPS Pub.202 Section 6.2
 */
class SHAKE_128_XOF final : public SHAKE_XOF {
   public:
      SHAKE_128_XOF() : SHAKE_XOF(256) {}

      std::string name() const final { return "SHAKE-128"; }

      std::unique_ptr<XOF> copy_state() const final { return std::make_unique<SHAKE_128_XOF>(*this); }

      std::unique_ptr<XOF> new_object() const final { return std::make_unique<SHAKE_128_XOF>(); }
};

/**
 * SHAKE-256 as defined in FIPS Pub.202 Section 6.2
 */
class SHAKE_256_XOF final : public SHAKE_XOF {
   public:
      SHAKE_256_XOF() : SHAKE_XOF(512) {}

      std::string name() const final { return "SHAKE-256"; }

      std::unique_ptr<XOF> copy_state() const final { return std::make_unique<SHAKE_256_XOF>(*this); }

      std::unique_ptr<XOF> new_object() const final { return std::make_unique<SHAKE_256_XOF>(); }
};

}  // namespace Botan

#endif
