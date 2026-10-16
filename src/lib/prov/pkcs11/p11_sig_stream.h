/*
* PKCS#11 Signature Streaming
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_P11_SIG_STREAM_H_
#define BOTAN_P11_SIG_STREAM_H_

#include <botan/p11_mechanism.h>
#include <botan/p11_object.h>
#include <span>
#include <vector>

namespace Botan::PKCS11 {

/**
* Maps the streaming update() interface of a signature or verification
* operation onto the PKCS #11 single and multiple part functions.
*
* Input is buffered until a second nonempty update() call so that the common case
* of a single update() uses C_Sign/C_Verify. Mechanisms which only support
* single part operations (such as CKM_ECDSA) always buffer the entire input.
*
* The token operation is only initialized once it is actually needed, and an
* abandoned multiple part operation is terminated on destruction so the
* session remains usable.
*/
class Signature_Stream final {
   public:
      enum class Direction : uint8_t { Sign, Verify };

      /**
      * @param direction whether signatures are created or verified
      * @param key the key object; must outlive this object
      * @param mechanism the mechanism; must outlive this object
      */
      Signature_Stream(Direction direction, const Object& key, const MechanismWrapper& mechanism);

      ~Signature_Stream() noexcept;

      Signature_Stream(const Signature_Stream&) = delete;
      Signature_Stream& operator=(const Signature_Stream&) = delete;
      Signature_Stream(Signature_Stream&&) = delete;
      Signature_Stream& operator=(Signature_Stream&&) = delete;

      void update(std::span<const uint8_t> input);

      /// Only valid for Direction::Sign
      std::vector<uint8_t> sign();

      /// Only valid for Direction::Verify
      bool verify(std::span<const uint8_t> signature);

   private:
      void init();
      void update_token(std::span<const uint8_t> input);

      const Direction m_direction;
      const Object& m_key;
      const MechanismWrapper& m_mechanism;
      const bool m_single_part_only;
      secure_vector<uint8_t> m_buffer;
      bool m_multipart_active = false;
};

}  // namespace Botan::PKCS11

#endif
