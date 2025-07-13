/*
* CBC Padding Methods
* (C) 1999-2008,2013 Jack Lloyd
* (C) 2016 René Korthaus, Rohde & Schwarz Cybersecurity
* (C) 2025 René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MODE_PADDING_H_
#define BOTAN_MODE_PADDING_H_

#include <botan/assert.h>
#include <botan/secmem.h>
#include <memory>
#include <span>
#include <string>

namespace Botan {

/**
* Block Cipher Mode Padding Method
* This class is pretty limited, it cannot deal well with
* randomized padding methods, or any padding method that
* wants to add more than one block. For instance, it should
* be possible to define cipher text stealing mode as simply
* a padding mode for CBC, which happens to consume the last
* two block (and requires use of the block cipher).
*/
class BOTAN_TEST_API BlockCipherModePaddingMethod /* NOLINT(*-special-member-functions) */ {
   public:
      /**
      * Get a block cipher padding mode by name (eg "NoPadding" or "PKCS7")
      * @param algo_spec block cipher padding mode name
      */
      static std::unique_ptr<BlockCipherModePaddingMethod> create(std::string_view algo_spec);

      /**
      * Add padding bytes to buffer.
      * @param buffer data to pad, span must be large enough to hold the padding
      *               behind the final (partial) block
      * @param final_block_bytes size of the final block in bytes
      * @param block_size size of each block in bytes
      */
      virtual void add_padding(std::span<uint8_t> buffer, size_t final_block_bytes, size_t block_size) const;

      /**
      * Remove padding bytes from block
      * @param last_block the last block containing the padding
      * @return number of data bytes, or if the padding is invalid returns the
      *         byte length of @p last_block (i.e. the block size)
      */
      size_t unpad(std::span<const uint8_t> last_block) const;

      /**
      * @param block_size of the cipher
      * @return valid block size for this padding mode
      */
      virtual bool valid_blocksize(size_t block_size) const = 0;

      /**
      * @param input_length number of bytes to be padded
      * @param block_size   size of each block in bytes
      * @return the total number of output bytes (including the padding)
      */
      virtual size_t output_length(size_t input_length, size_t block_size) const {
         return ((input_length + block_size) / block_size) * block_size;
      }

      /**
      * @return name of the mode
      */
      virtual std::string name() const = 0;

      /**
      * virtual destructor
      */
      virtual ~BlockCipherModePaddingMethod() = default;

   protected:
      /**
      * Applies the concrete padding to the @p last_block assuming the padding
      * bytes should start at @p padding_start_pos within the last block.
      *
      * Concrete implementations of this function must ensure not to leak
      * @p padding_start_pos via side channels. Both the bytes of @p last_block
      * and @p padding_start_pos are passed in with CT::poison applied.
      */
      virtual void apply_padding(std::span<uint8_t> last_block, size_t padding_start_pos) const = 0;

      /**
      * Removes the padding from @p last_block and returns the number of data
      * bytes. If the padding is invalid, this returns the byte length of
      * @p last_block.
      *
      * Concrete implementations of this function must ensure not to leak
      * the size or validity of the padding via side channels. The bytes of
      * @p last_block are passed in with CT::poison applied to them.
      */
      virtual size_t remove_padding(std::span<const uint8_t> last_block) const = 0;
};

/**
* PKCS#7 Padding
*/
class BOTAN_FUZZER_API PKCS7_Padding final : public BlockCipherModePaddingMethod {
   public:
      void apply_padding(std::span<uint8_t> last_block, size_t final_block_bytes) const override;

      size_t remove_padding(std::span<const uint8_t> last_block) const override;

      bool valid_blocksize(size_t bs) const override { return (bs > 2 && bs < 256); }

      std::string name() const override { return "PKCS7"; }
};

/**
* ANSI X9.23 Padding
*/
class BOTAN_FUZZER_API ANSI_X923_Padding final : public BlockCipherModePaddingMethod {
   public:
      void apply_padding(std::span<uint8_t> last_block, size_t final_block_bytes) const override;

      size_t remove_padding(std::span<const uint8_t> last_block) const override;

      bool valid_blocksize(size_t bs) const override { return (bs > 2 && bs < 256); }

      std::string name() const override { return "X9.23"; }
};

/**
* One And Zeros Padding (ISO/IEC 9797-1, padding method 2)
*/
class BOTAN_FUZZER_API OneAndZeros_Padding final : public BlockCipherModePaddingMethod {
   public:
      void apply_padding(std::span<uint8_t> last_block, size_t final_block_bytes) const override;

      size_t remove_padding(std::span<const uint8_t> last_block) const override;

      bool valid_blocksize(size_t bs) const override { return (bs > 2); }

      std::string name() const override { return "OneAndZeros"; }
};

/**
* ESP Padding (RFC 4303)
*/
class BOTAN_FUZZER_API ESP_Padding final : public BlockCipherModePaddingMethod {
   public:
      void apply_padding(std::span<uint8_t> last_block, size_t final_block_bytes) const override;

      size_t remove_padding(std::span<const uint8_t> last_block) const override;

      bool valid_blocksize(size_t bs) const override { return (bs > 2 && bs < 256); }

      std::string name() const override { return "ESP"; }
};

/**
* Null Padding
*/
class Null_Padding final : public BlockCipherModePaddingMethod {
   public:
      void add_padding(std::span<uint8_t> /*buffer*/,
                       size_t /*final_block_bytes*/,
                       size_t /*block_size*/) const override {
         // no padding
      }

      size_t remove_padding(std::span<const uint8_t> last_block) const override { return last_block.size(); }

      bool valid_blocksize(size_t /*block_size*/) const override { return true; }

      size_t output_length(size_t input_length, size_t /*block_size*/) const override { return input_length; }

      std::string name() const override { return "NoPadding"; }

   private:
      void apply_padding(std::span<uint8_t> /*last_block*/, size_t /*padding_start_pos*/) const override {
         // This class overrides add_padding() as a NOOP, so this customization
         // point can never be called by anyone.
         BOTAN_ASSERT_UNREACHABLE();
      }
};

}  // namespace Botan

#endif
