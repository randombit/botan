/*
* Block Cipher Base Class
* (C) 1999-2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_BLOCK_CIPHER_H_
#define BOTAN_BLOCK_CIPHER_H_

#include <botan/sym_algo.h>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace Botan {

/**
* This class represents a block cipher object.
*/
class BOTAN_PUBLIC_API(2, 0) BlockCipher : public SymmetricAlgorithm {
   public:
      /**
      * Create an instance based on a name
      * If provider is empty then best available is chosen.
      * @param algo_spec algorithm name
      * @param provider provider implementation to choose
      * @return a null pointer if the algo/provider combination cannot be found
      */
      static std::unique_ptr<BlockCipher> create(std::string_view algo_spec, std::string_view provider = "");

      /**
      * Create an instance based on a name, or throw if the
      * algo/provider combination cannot be found. If provider is
      * empty then best available is chosen.
      */
      static std::unique_ptr<BlockCipher> create_or_throw(std::string_view algo_spec, std::string_view provider = "");

      /**
      * @return list of available providers for this algorithm, empty if not available
      * @param algo_spec algorithm name
      */
      static std::vector<std::string> providers(std::string_view algo_spec);

      /**
      * Multiplier on a block cipher's native parallelism
      *
      * Usually notable performance gains come from further loop blocking,
      * at least for 2 or 4x
      */
      static constexpr size_t ParallelismMult = 4;

      /**
      * @return block size of this algorithm
      */
      virtual size_t block_size() const = 0;

      /**
      * @return native parallelism of this cipher in blocks
      */
      virtual size_t parallelism() const { return 1; }

      /**
      * @return preferred parallelism of this cipher in bytes
      */
      size_t parallel_bytes() const { return parallelism() * block_size() * BlockCipher::ParallelismMult; }

      /**
      * @return provider information about this implementation. Default is "base",
      * might also return "sse2", "avx2", "openssl", or some other arbitrary string.
      */
      virtual std::string provider() const { return "base"; }

      /**
      * Encrypt a block.
      * @param in The plaintext block to be encrypted as a byte array.
      * Must be of length block_size().
      * @param out The byte array designated to hold the encrypted block.
      * Must be of length block_size().
      */
      void encrypt(const uint8_t in[], uint8_t out[]) const { encrypt_n(in, out, 1); }

      /**
      * Decrypt a block.
      * @param in The ciphertext block to be decrypted as a byte array.
      * Must be of length block_size().
      * @param out The byte array designated to hold the decrypted block.
      * Must be of length block_size().
      */
      void decrypt(const uint8_t in[], uint8_t out[]) const { decrypt_n(in, out, 1); }

      /**
      * Encrypt a block.
      * @param block the plaintext block to be encrypted
      * Must be of length block_size(). Will hold the result when the function
      * has finished.
      */
      void encrypt(uint8_t block[]) const { encrypt_n(block, block, 1); }

      /**
      * Decrypt a block.
      * @param block the ciphertext block to be decrypted
      * Must be of length block_size(). Will hold the result when the function
      * has finished.
      */
      void decrypt(uint8_t block[]) const { decrypt_n(block, block, 1); }

      /**
      * Encrypt one or more blocks
      * @param block the input/output buffer (multiple of block_size())
      */
      void encrypt(std::span<uint8_t> block) const {
         return encrypt_n(block.data(), block.data(), block.size() / block_size());
      }

      /**
      * Decrypt one or more blocks
      * @param block the input/output buffer (multiple of block_size())
      */
      void decrypt(std::span<uint8_t> block) const {
         return decrypt_n(block.data(), block.data(), block.size() / block_size());
      }

      /**
      * Encrypt one or more blocks
      * @param in the input buffer (multiple of block_size())
      * @param out the output buffer (same size as in)
      */
      void encrypt(std::span<const uint8_t> in, std::span<uint8_t> out) const {
         return encrypt_n(in.data(), out.data(), in.size() / block_size());
      }

      /**
      * Decrypt one or more blocks
      * @param in the input buffer (multiple of block_size())
      * @param out the output buffer (same size as in)
      */
      void decrypt(std::span<const uint8_t> in, std::span<uint8_t> out) const {
         return decrypt_n(in.data(), out.data(), in.size() / block_size());
      }

      /**
      * Encrypt one or more blocks
      * @param in the input buffer (multiple of block_size())
      * @param out the output buffer (same size as in)
      * @param blocks the number of blocks to process
      */
      virtual void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const = 0;

      /**
      * Decrypt one or more blocks
      * @param in the input buffer (multiple of block_size())
      * @param out the output buffer (same size as in)
      * @param blocks the number of blocks to process
      */
      virtual void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const = 0;

      BOTAN_DEPRECATED("Deprecated no replacement")
      void encrypt_n_xex(uint8_t data[], const uint8_t mask[], size_t blocks) const {
         const size_t BS = block_size();
         for(size_t i = 0; i != blocks * BS; ++i) {
            data[i] ^= mask[i];
         }
         encrypt_n(data, data, blocks);
         for(size_t i = 0; i != blocks * BS; ++i) {
            data[i] ^= mask[i];
         }
      }

      BOTAN_DEPRECATED("Deprecated no replacement")
      void decrypt_n_xex(uint8_t data[], const uint8_t mask[], size_t blocks) const {
         const size_t BS = block_size();
         for(size_t i = 0; i != blocks * BS; ++i) {
            data[i] ^= mask[i];
         }
         decrypt_n(data, data, blocks);
         for(size_t i = 0; i != blocks * BS; ++i) {
            data[i] ^= mask[i];
         }
      }

      /**
      * @return new object representing the same algorithm as *this
      */
      virtual std::unique_ptr<BlockCipher> new_object() const = 0;

      BlockCipher* clone() const { return this->new_object().release(); }
};

/**
* Tweakable block ciphers allow setting a tweak which is a non-keyed
* value which affects the encryption/decryption operation.
*/
class BOTAN_PUBLIC_API(2, 8) Tweakable_Block_Cipher : public BlockCipher {
   public:
      /**
      * Set the tweak value. This must be called after setting a key. The value
      * persists until either set_tweak, set_key, or clear is called.
      * Different algorithms support different tweak length(s). If called with
      * an unsupported length, Invalid_Argument will be thrown.
      */
      virtual void set_tweak(const uint8_t tweak[], size_t len) = 0;
};

/**
* Represents a block cipher with a single fixed block size
*/
template <size_t BS, size_t KMIN, size_t KMAX = 0, size_t KMOD = 1, typename BaseClass = BlockCipher>
class Block_Cipher_Fixed_Params : public BaseClass {
   public:
      enum { BLOCK_SIZE = BS }; /* NOLINT(*-enum-size,*-use-enum-class) */

      size_t block_size() const final { return BS; }

      Key_Length_Specification key_spec() const final { return Key_Length_Specification(KMIN, KMAX, KMOD); }
};

}  // namespace Botan

#endif
