/*
* Key Derivation Function interfaces
* (C) 1999-2007 Jack Lloyd
* (C) 2024      René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_KDF_BASE_H_
#define BOTAN_KDF_BASE_H_

#include <botan/concepts.h>
#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/secmem.h>
#include <span>
#include <string>
#include <string_view>

namespace Botan {

/**
* Key Derivation Function
*/
class BOTAN_PUBLIC_API(2, 0) KDF {
   public:
      virtual ~KDF() = default;

      /**
      * Create an instance based on a name
      * If provider is empty then best available is chosen.
      * @param algo_spec algorithm name
      * @param provider provider implementation to choose
      * @return a null pointer if the algo/provider combination cannot be found
      */
      static std::unique_ptr<KDF> create(std::string_view algo_spec, std::string_view provider = "");

      /**
      * Create an instance based on a name, or throw if the
      * algo/provider combination cannot be found. If provider is
      * empty then best available is chosen.
      */
      static std::unique_ptr<KDF> create_or_throw(std::string_view algo_spec, std::string_view provider = "");

      /**
      * @return list of available providers for this algorithm, empty if not available
      */
      static std::vector<std::string> providers(std::string_view algo_spec);

      /**
      * @return KDF name
      */
      virtual std::string name() const = 0;

      /**
      * Derive a key
      * @param key buffer holding the derived key, must be of length key_len
      * @param key_len the desired output length in bytes
      * @param secret the secret input
      * @param secret_len size of secret in bytes
      * @param salt a diversifier
      * @param salt_len size of salt in bytes
      * @param label purpose for the derived keying material
      * @param label_len size of label in bytes
      */
      BOTAN_DEPRECATED("Use KDF::derive_key")
      void kdf(uint8_t key[],
               size_t key_len,
               const uint8_t secret[],
               size_t secret_len,
               const uint8_t salt[],
               size_t salt_len,
               const uint8_t label[],
               size_t label_len) const {
         derive_key({key, key_len}, {secret, secret_len}, {salt, salt_len}, {label, label_len});
      }

      /**
      * Derive a key
      * @param key_len the desired output length in bytes
      * @param secret the secret input
      * @param secret_len size of secret in bytes
      * @param salt a diversifier
      * @param salt_len size of salt in bytes
      * @param label purpose for the derived keying material
      * @param label_len size of label in bytes
      * @return the derived key
      */
      template <concepts::resizable_byte_buffer T = secure_vector<uint8_t>>
      BOTAN_DEPRECATED("Use std::span or std::string_view overloads")
      T derive_key(size_t key_len,
                   const uint8_t secret[],
                   size_t secret_len,
                   const uint8_t salt[],
                   size_t salt_len,
                   const uint8_t label[] = nullptr,
                   size_t label_len = 0) const {
         return derive_key<T>(key_len, {secret, secret_len}, {salt, salt_len}, {label, label_len});
      }

      /**
      * Derive a key
      * @param key_len the desired output length in bytes
      * @param secret the secret input
      * @param salt a diversifier
      * @param label purpose for the derived keying material
      * @return the derived key
      */
      template <concepts::resizable_byte_buffer T = secure_vector<uint8_t>>
      T derive_key(size_t key_len,
                   std::span<const uint8_t> secret,
                   std::string_view salt = "",
                   std::string_view label = "") const {
         return derive_key<T>(key_len,
                              secret,
                              {cast_char_ptr_to_uint8(salt.data()), salt.length()},
                              {cast_char_ptr_to_uint8(label.data()), label.length()});
      }

      /**
      * Derive a key
      * @param key the output buffer for the to-be-derived key
      * @param secret the secret input
      * @param salt a diversifier
      * @param label purpose for the derived keying material
      */
      void derive_key(std::span<uint8_t> key,
                      std::span<const uint8_t> secret,
                      std::span<const uint8_t> salt,
                      std::span<const uint8_t> label) const {
         perform_kdf(key, secret, salt, label);
      }

      /**
      * Derive a key
      * @param key_len the desired output length in bytes
      * @param secret the secret input
      * @param salt a diversifier
      * @param label purpose for the derived keying material
      * @return the derived key
      */
      template <concepts::resizable_byte_buffer T = secure_vector<uint8_t>>
      T derive_key(size_t key_len,
                   std::span<const uint8_t> secret,
                   std::span<const uint8_t> salt,
                   std::span<const uint8_t> label) const {
         T key(key_len);
         perform_kdf(key, secret, salt, label);
         return key;
      }

      /**
      * Derive a key
      * @param key_len the desired output length in bytes
      * @param secret the secret input
      * @param salt a diversifier
      * @param salt_len size of salt in bytes
      * @param label purpose for the derived keying material
      * @return the derived key
      */
      template <concepts::resizable_byte_buffer T = secure_vector<uint8_t>>
      BOTAN_DEPRECATED("Use std::span or std::string_view overloads")
      T derive_key(size_t key_len,
                   std::span<const uint8_t> secret,
                   const uint8_t salt[],
                   size_t salt_len,
                   std::string_view label = "") const {
         return derive_key<T>(key_len, secret, {salt, salt_len}, {cast_char_ptr_to_uint8(label.data()), label.size()});
      }

      /**
      * Derive a key
      * @param key_len the desired output length in bytes
      * @param secret the secret input
      * @param secret_len size of secret in bytes
      * @param salt a diversifier
      * @param label purpose for the derived keying material
      * @return the derived key
      */
      template <concepts::resizable_byte_buffer T = secure_vector<uint8_t>>
      BOTAN_DEPRECATED("Use std::span or std::string_view overloads")
      T derive_key(size_t key_len,
                   const uint8_t secret[],
                   size_t secret_len,
                   std::string_view salt = "",
                   std::string_view label = "") const {
         return derive_key<T>(key_len,
                              {secret, secret_len},
                              {cast_char_ptr_to_uint8(salt.data()), salt.length()},
                              {cast_char_ptr_to_uint8(label.data()), label.length()});
      }

      /**
      * Derive a key
      * @tparam key_len the desired output length in bytes
      * @param secret the secret input
      * @param salt a diversifier
      * @param label purpose for the derived keying material
      * @return the derived key
      */
      template <size_t key_len>
      std::array<uint8_t, key_len> derive_key(std::span<const uint8_t> secret,
                                              std::span<const uint8_t> salt = {},
                                              std::span<const uint8_t> label = {}) {
         std::array<uint8_t, key_len> key;
         perform_kdf(key, secret, salt, label);
         return key;
      }

      /**
      * Derive a key
      * @tparam key_len the desired output length in bytes
      * @param secret the secret input
      * @param salt a diversifier
      * @param label purpose for the derived keying material
      * @return the derived key
      */
      template <size_t key_len>
      std::array<uint8_t, key_len> derive_key(std::span<const uint8_t> secret,
                                              std::span<const uint8_t> salt = {},
                                              std::string_view label = "") {
         return derive_key<key_len>(secret, salt, {cast_char_ptr_to_uint8(label.data()), label.size()});
      }

      /**
      * Derive a key
      * @tparam key_len the desired output length in bytes
      * @param secret the secret input
      * @param salt a diversifier
      * @param label purpose for the derived keying material
      * @return the derived key
      */
      template <size_t key_len>
      std::array<uint8_t, key_len> derive_key(std::span<const uint8_t> secret,
                                              std::string_view salt = "",
                                              std::string_view label = "") {
         return derive_key<key_len>(secret,
                                    {cast_char_ptr_to_uint8(salt.data()), salt.size()},
                                    {cast_char_ptr_to_uint8(label.data()), label.size()});
      }

      /**
      * @return new object representing the same algorithm as *this
      */
      virtual std::unique_ptr<KDF> new_object() const = 0;

      /**
      * @return new object representing the same algorithm as *this
      */
      KDF* clone() const { return this->new_object().release(); }

   protected:
      /**
      * Internal customization point for subclasses
      *
      * The byte size of the @p key span is the number of bytes to be produced
      * by the concrete key derivation function.
      *
      * @param key the output buffer for the to-be-derived key
      * @param secret the secret input
      * @param salt a diversifier
      * @param label purpose for the derived keying material
      */
      virtual void perform_kdf(std::span<uint8_t> key,
                               std::span<const uint8_t> secret,
                               std::span<const uint8_t> salt,
                               std::span<const uint8_t> label) const = 0;
};

/**
* Factory method for KDF (key derivation function)
* @param algo_spec the name of the KDF to create
* @return pointer to newly allocated object of that type
*
* Prefer KDF::create
*/
BOTAN_DEPRECATED("Use KDF::create")

inline KDF* get_kdf(std::string_view algo_spec) {
   auto kdf = KDF::create(algo_spec);
   if(kdf) {
      return kdf.release();
   }

   if(algo_spec == "Raw") {
      return nullptr;
   }

   throw Algorithm_Not_Found(algo_spec);
}

}  // namespace Botan

#endif
