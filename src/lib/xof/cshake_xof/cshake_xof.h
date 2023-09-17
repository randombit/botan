/*
 * cSHAKE-128 and cSHAKE-256 as XOFs
 *
 * (C) 2016-2023 Jack Lloyd
 *     2022-2023 René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_CSHAKE_XOF_H_
#define BOTAN_CSHAKE_XOF_H_

#include <botan/xof.h>
#include <botan/internal/keccak_perm.h>

#include <vector>

namespace Botan {

/**
 * Base class for cSHAKE-based XOFs
 */
class BOTAN_TEST_API cSHAKE_XOF : public XOF {
   protected:
      /**
       * Defines a concrete instance of a cSHAKE XOF.
       *
       * @param capacity      either 256 or 512
       * @param function_name a domain separator for Keccak-based functions
       *                      derived from cSHAKE
       */
      cSHAKE_XOF(size_t capacity, std::vector<uint8_t> function_name);
      cSHAKE_XOF(size_t capacity, std::span<const uint8_t> function_name);
      cSHAKE_XOF(size_t capacity, std::string_view function_name);

   public:
      std::string provider() const final;

      bool valid_salt_length(size_t salt_length) const final;

      size_t block_size() const final;

      bool accepts_input() const final { return !m_output_generated; }

   protected:
      const std::vector<uint8_t>& function_name() const { return m_function_name; }

   private:
      /**
       * @param salt  the S value for cSHAKE (see NIST SP.800-185)
       * @param key   not supported, must be an empty buffer
       */
      void start_msg(std::span<const uint8_t> salt, std::span<const uint8_t> key) final;
      void add_data(std::span<const uint8_t> input) final;
      void generate_bytes(std::span<uint8_t> output) final;
      void reset() final;

   private:
      Keccak_Permutation m_keccak;
      std::vector<uint8_t> m_function_name;
      bool m_output_generated;
};

/**
 * customizable SHAKE-128 as defined in NIST SP.800-185
 * This class is meant for internal use only and is not exposed via XOF::create().
 */
class BOTAN_TEST_API cSHAKE_128_XOF final : public cSHAKE_XOF {
   public:
      cSHAKE_128_XOF(std::vector<uint8_t> function_name) : cSHAKE_XOF(256, std::move(function_name)) {}

      cSHAKE_128_XOF(std::span<const uint8_t> function_name) : cSHAKE_XOF(256, function_name) {}

      cSHAKE_128_XOF(std::string_view function_name) : cSHAKE_XOF(256, function_name) {}

      std::string name() const final { return "cSHAKE-128"; }

      std::unique_ptr<XOF> copy_state() const final { return std::make_unique<cSHAKE_128_XOF>(*this); }

      std::unique_ptr<XOF> new_object() const final { return std::make_unique<cSHAKE_128_XOF>(function_name()); }
};

/**
 * customizable SHAKE-256 as defined in NIST SP.800-185
 * This class is meant for internal use only and is not exposed via XOF::create().
 */
class BOTAN_TEST_API cSHAKE_256_XOF final : public cSHAKE_XOF {
   public:
      cSHAKE_256_XOF(std::vector<uint8_t> function_name) : cSHAKE_XOF(512, std::move(function_name)) {}

      cSHAKE_256_XOF(std::span<const uint8_t> function_name) : cSHAKE_XOF(512, function_name) {}

      cSHAKE_256_XOF(std::string_view function_name) : cSHAKE_XOF(512, function_name) {}

      std::string name() const final { return "cSHAKE-256"; }

      std::unique_ptr<XOF> copy_state() const final { return std::make_unique<cSHAKE_256_XOF>(*this); }

      std::unique_ptr<XOF> new_object() const final { return std::make_unique<cSHAKE_256_XOF>(function_name()); }
};

}  // namespace Botan

#endif
