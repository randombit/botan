/*
* PKCS#11 Signature Streaming
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/p11_sig_stream.h>

#include <botan/assert.h>
#include <botan/p11_types.h>
#include <utility>

namespace Botan::PKCS11 {

namespace {

/*
* Mechanisms which take a digest or an already encoded message and which the
* PKCS #11 mechanism tables list as single part only for sign/verify
*/
bool is_single_part_only(MechanismType type) {
   switch(type) {
      case MechanismType::Ecdsa:
      case MechanismType::RsaX509:
      case MechanismType::RsaPkcs:
      case MechanismType::RsaPkcsPss:
      case MechanismType::RsaX931:
      case MechanismType::Rsa9796:
         return true;
      default:
         return false;
   }
}

}  // namespace

Signature_Stream::Signature_Stream(Direction direction, const Object& key, const MechanismWrapper& mechanism) :
      m_direction(direction),
      m_key(key),
      m_mechanism(mechanism),
      m_single_part_only(is_single_part_only(mechanism.mechanism_type())) {}

Signature_Stream::~Signature_Stream() noexcept {
   if(!m_multipart_active) {
      return;
   }

   /*
   * Terminate the abandoned operation; otherwise every later operation of the
   * same kind on this session fails with CKR_OPERATION_ACTIVE. Only a final
   * call which is not a length query is guaranteed to end the operation.
   */
   try {
      if(m_direction == Direction::Sign) {
         std::vector<uint8_t> discarded;
         m_key.module()->C_SignFinal(m_key.session().handle(), discarded, nullptr);
      } else {
         const uint8_t dummy_signature = 0;
         m_key.module()->C_VerifyFinal(m_key.session().handle(), &dummy_signature, 1, nullptr);
      }
   } catch(...) {  // NOLINT(*-empty-catch)
   }
}

void Signature_Stream::init() {
   if(m_direction == Direction::Sign) {
      m_key.module()->C_SignInit(m_key.session().handle(), m_mechanism.data(), m_key.handle());
   } else {
      m_key.module()->C_VerifyInit(m_key.session().handle(), m_mechanism.data(), m_key.handle());
   }
}

void Signature_Stream::update_token(std::span<const uint8_t> input) {
   try {
      if(m_direction == Direction::Sign) {
         m_key.module()->C_SignUpdate(m_key.session().handle(), input.data(), checked_ulong_cast(input.size()));
      } else {
         m_key.module()->C_VerifyUpdate(m_key.session().handle(), input.data(), checked_ulong_cast(input.size()));
      }
   } catch(...) {
      // A failed update terminates the operation on the token
      m_multipart_active = false;
      throw;
   }
}

void Signature_Stream::update(std::span<const uint8_t> input) {
   if(input.empty()) {
      return;
   }

   if(m_multipart_active) {
      update_token(input);
      return;
   }

   if(m_single_part_only || m_buffer.empty()) {
      m_buffer.insert(m_buffer.end(), input.begin(), input.end());
      return;
   }

   // Second nonempty update: switch to a multiple part operation
   const auto buffered = std::exchange(m_buffer, {});

   init();
   m_multipart_active = true;
   update_token(buffered);
   update_token(input);
}

std::vector<uint8_t> Signature_Stream::sign() {
   BOTAN_STATE_CHECK(m_direction == Direction::Sign);

   std::vector<uint8_t> signature;

   if(m_multipart_active) {
      // Any outcome of C_SignFinal other than a length query ends the operation
      m_multipart_active = false;
      m_key.module()->C_SignFinal(m_key.session().handle(), signature);
   } else {
      const auto message = std::exchange(m_buffer, {});

      init();
      m_key.module()->C_Sign(m_key.session().handle(), message, signature);
   }

   return signature;
}

bool Signature_Stream::verify(std::span<const uint8_t> signature) {
   BOTAN_STATE_CHECK(m_direction == Direction::Verify);

   // Avoid passing a null pointer, which some modules reject
   const uint8_t empty_signature = 0;
   const uint8_t* sig_ptr = signature.empty() ? &empty_signature : signature.data();
   const Ulong sig_len = checked_ulong_cast(signature.size());

   ReturnValue return_value = ReturnValue::SignatureInvalid;

   if(m_multipart_active) {
      // C_VerifyFinal always ends the operation
      m_multipart_active = false;
      m_key.module()->C_VerifyFinal(m_key.session().handle(), sig_ptr, sig_len, &return_value);
   } else {
      const auto message = std::exchange(m_buffer, {});

      init();
      m_key.module()->C_Verify(
         m_key.session().handle(), message.data(), checked_ulong_cast(message.size()), sig_ptr, sig_len, &return_value);
   }

   if(return_value == ReturnValue::SignatureInvalid || return_value == ReturnValue::SignatureLenRange) {
      return false;
   } else if(return_value == ReturnValue::OK) {
      return true;
   } else {
      throw PKCS11_ReturnError(return_value);
   }
}

}  // namespace Botan::PKCS11
