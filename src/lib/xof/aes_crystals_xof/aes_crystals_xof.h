/*
 * XOF based on AES-256/CTR for CRYSTALS Kyber/Dilithium 90s-modes
 * (C) 2023 Jack Lloyd
 *     2023 René Meusel - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#ifndef BOTAN_AES_CRYSTALS_XOF_H_
#define BOTAN_AES_CRYSTALS_XOF_H_

#include <botan/secmem.h>
#include <botan/xof.h>

namespace Botan {

class StreamCipher;

/**
 * XOF implementation for Kyber/Dilithium 90s-modes based on
 * AES-256 in counter mode.
 *
 * This is an internal class that is not meant for consumption
 * by library users. It is therefore not registered in XOF::create().
 */
class BOTAN_TEST_API AES_256_CTR_XOF final : public XOF {
   public:
      AES_256_CTR_XOF();
      ~AES_256_CTR_XOF() override;

      void reset() override;

      std::string name() const override { return "CTR-BE(AES-256)"; }

      /**
       * Checks that the given @p iv_length is compatible with this XOF
       */
      bool valid_salt_length(size_t iv_length) const override;
      Key_Length_Specification key_spec() const override;

      size_t block_size() const override { return 16; }

      std::unique_ptr<XOF> copy_state() const override;

      std::unique_ptr<XOF> new_object() const override { return std::make_unique<AES_256_CTR_XOF>(); }

      bool accepts_input() const override { return false; }

   private:
      /**
       * Sets the @p IV and @p key of the underlying AES-256/CTR object.
       * Do not call AES_256_CTR_XOF::update(), on this object!
       */
      void start_msg(std::span<const uint8_t> iv = {}, std::span<const uint8_t> key = {}) override;

      /**
       * @throws Not_Implemented, use XOF::start() instead of XOF::update()
       */
      void add_data(std::span<const uint8_t>) override;

      void generate_bytes(std::span<uint8_t> output) override;

   private:
      std::unique_ptr<StreamCipher> m_stream_cipher;
};

}  // namespace Botan

#endif
