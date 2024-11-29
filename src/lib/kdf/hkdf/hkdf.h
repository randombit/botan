/*
* HKDF
* (C) 2013,2015 Jack Lloyd
* (C) 2016 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_HKDF_H_
#define BOTAN_HKDF_H_

#include <botan/kdf.h>
#include <botan/mac.h>

namespace Botan {

/**
* HKDF from RFC 5869.
*/
class HKDF final : public KDF {
   public:
      /**
      * @param prf MAC algorithm to use
      */
      explicit HKDF(std::unique_ptr<MessageAuthenticationCode> prf) : m_prf(std::move(prf)) {}

      std::unique_ptr<KDF> new_object() const override;

      std::string name() const override;

   private:
      void perform_kdf(std::span<uint8_t> key,
                       std::span<const uint8_t> secret,
                       std::span<const uint8_t> salt,
                       std::span<const uint8_t> label) const override;

   private:
      std::unique_ptr<MessageAuthenticationCode> m_prf;
};

/**
* HKDF Extraction Step from RFC 5869.
*/
class HKDF_Extract final : public KDF {
   public:
      /**
      * @param prf MAC algorithm to use
      */
      explicit HKDF_Extract(std::unique_ptr<MessageAuthenticationCode> prf) : m_prf(std::move(prf)) {}

      std::unique_ptr<KDF> new_object() const override;

      std::string name() const override;

   private:
      void perform_kdf(std::span<uint8_t> key,
                       std::span<const uint8_t> secret,
                       std::span<const uint8_t> salt,
                       std::span<const uint8_t> label) const override;

   private:
      std::unique_ptr<MessageAuthenticationCode> m_prf;
};

/**
* HKDF Expansion Step from RFC 5869.
*/
class HKDF_Expand final : public KDF {
   public:
      /**
      * @param prf MAC algorithm to use
      */
      explicit HKDF_Expand(std::unique_ptr<MessageAuthenticationCode> prf) : m_prf(std::move(prf)) {}

      std::unique_ptr<KDF> new_object() const override;

      std::string name() const override;

   private:
      void perform_kdf(std::span<uint8_t> key,
                       std::span<const uint8_t> secret,
                       std::span<const uint8_t> salt,
                       std::span<const uint8_t> label) const override;

   private:
      std::unique_ptr<MessageAuthenticationCode> m_prf;
};

/**
* HKDF-Expand-Label from TLS 1.3/QUIC
* @param hash_fn the hash to use
* @param secret the secret bits
* @param label the full label (no "TLS 1.3, " or "tls13 " prefix
*  is applied)
* @param hash_val the previous hash value (used for chaining, may be empty)
* @param length the desired output length
*/
secure_vector<uint8_t> BOTAN_TEST_API hkdf_expand_label(std::string_view hash_fn,
                                                        std::span<const uint8_t> secret,
                                                        std::string_view label,
                                                        std::span<const uint8_t> hash_val,
                                                        size_t length);

}  // namespace Botan

#endif
