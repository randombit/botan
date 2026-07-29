/*
* RTSS (threshold secret sharing)
* (C) 2009,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_RTSS_H_
#define BOTAN_RTSS_H_

#include <botan/secmem.h>
#include <string>
#include <vector>

namespace Botan {

class RandomNumberGenerator;

/**
* A split secret, using the format from draft-mcgrew-tss-03
*/
class BOTAN_PUBLIC_API(2, 0) RTSS_Share final {
   public:
      /**
      * Split a secret into shares
      * @param M the number of shares needed to reconstruct
      * @param N the number of shares generated
      * @param secret the secret to split
      * @param secret_len the length of the secret
      * @param identifier the 16 byte share identifier
      * @param rng the random number generator to use
      */
      static std::vector<RTSS_Share> split(uint8_t M,
                                           uint8_t N,
                                           const uint8_t secret[],
                                           uint16_t secret_len,
                                           const uint8_t identifier[16],
                                           RandomNumberGenerator& rng);

      /**
      * Split a secret into shares
      * @param M the number of shares needed to reconstruct
      * @param N the number of shares generated
      * @param secret the secret to split
      * @param secret_len the length of the secret
      * @param identifier the share identifier
      * @param hash_fn the hash function to use for a checksum ("None", "SHA-1", "SHA-256")
      * @param rng the random number generator to use
      */
      static std::vector<RTSS_Share> split(uint8_t M,
                                           uint8_t N,
                                           const uint8_t secret[],
                                           uint16_t secret_len,
                                           const std::vector<uint8_t>& identifier,
                                           std::string_view hash_fn,
                                           RandomNumberGenerator& rng);

      /**
      * Reconstruct a secret from a set of shares
      * @param shares the list of shares
      */
      static secure_vector<uint8_t> reconstruct(const std::vector<RTSS_Share>& shares);

      /**
      * Create an uninitialized share
      */
      RTSS_Share() = default;

      /**
      * Decode a share from its hex representation
      * @param hex_input the share encoded in hexadecimal
      */
      explicit RTSS_Share(std::string_view hex_input);

      /**
      * Create a share from its binary representation
      * @param data the shared data
      * @param len the length of data
      */
      RTSS_Share(const uint8_t data[], size_t len);

      /**
      * Access the binary representation of this share
      * @return binary representation
      */
      const secure_vector<uint8_t>& data() const { return m_contents; }

      /**
      * Format this share as a hex string
      * @return hex representation
      */
      std::string to_string() const;

      /**
      * Return the identifier of this share
      * @return share identifier
      */
      uint8_t share_id() const;

      /**
      * Return the size of this share
      * @return size of this share in bytes
      */
      size_t size() const { return m_contents.size(); }

      /**
      * Test whether this share was initialized
      * @return if this TSS share was initialized or not
      */
      bool initialized() const { return (!m_contents.empty()); }

   private:
      secure_vector<uint8_t> m_contents;
};

}  // namespace Botan

#endif
