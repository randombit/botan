/*
* ECIES
* (C) 2016 Philipp Weber
*     2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*     2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ecies.h>

#include <botan/cipher_mode.h>
#include <botan/ecdh.h>
#include <botan/kdf.h>
#include <botan/mac.h>
#include <botan/mem_ops.h>
#include <botan/pk_options.h>
#include <botan/internal/concat_util.h>
#include <botan/internal/ct_utils.h>

namespace Botan {

ECIES_KA_Operation::ECIES_KA_Operation(const PK_Key_Agreement_Key& private_key,
                                       const ECIES_KA_Params& ecies_params,
                                       RandomNumberGenerator& rng) :
      m_ka(private_key, rng, PK_Key_Agreement_Options().with_raw_shared_key()), m_params(ecies_params) {}

/**
* ECIES secret derivation according to ISO 18033-2
*/
SymmetricKey ECIES_KA_Operation::derive_secret(std::span<const uint8_t> eph_public_key_bin,
                                               const EC_AffinePoint& other_public_key_point) const {
   BOTAN_ARG_CHECK(!other_public_key_point.is_identity(), "ECIES: peer public key point is the identity element");

   auto kdf = KDF::create_or_throw(m_params.kdf());

   secure_vector<uint8_t> derivation_input;

   // ISO 18033: encryption step e / decryption step g
   if(!m_params.single_hash_mode()) {
      derivation_input.assign(eph_public_key_bin.begin(), eph_public_key_bin.end());
   }

   // ISO 18033: encryption step f / decryption step h
   std::vector<uint8_t> other_public_key_bin = other_public_key_point.serialize(m_params.point_format());
   // Note: the argument `m_params.secret_length()` passed for `key_len` will only be used by providers because
   // "Raw" is passed to the `PK_Key_Agreement` if the implementation of botan is used.
   const SymmetricKey peh =
      m_ka.derive_key(m_params.group().get_order_bytes(), other_public_key_bin.data(), other_public_key_bin.size());
   derivation_input.insert(derivation_input.end(), peh.begin(), peh.end());

   // ISO 18033: encryption step g / decryption step i
   return SymmetricKey(kdf->derive_key(m_params.secret_length(), derivation_input));
}

ECIES_KA_Params::ECIES_KA_Params(
   const EC_Group& group, std::string_view kdf, size_t length, EC_Point_Format point_format, bool single_hash_mode) :
      m_group(group),
      m_kdf(kdf),
      m_length(length),
      m_point_format(point_format),
      m_single_hash_mode(single_hash_mode) {}

ECIES_System_Params::ECIES_System_Params(const EC_Group& group,
                                         std::string_view kdf,
                                         std::string_view dem_algo_spec,
                                         size_t dem_key_len,
                                         std::string_view mac_spec,
                                         size_t mac_key_len,
                                         EC_Point_Format point_format,
                                         bool single_hash_mode) :
      ECIES_KA_Params(group, kdf, dem_key_len + mac_key_len, point_format, single_hash_mode),
      m_dem_spec(dem_algo_spec),
      m_dem_keylen(dem_key_len),
      m_mac_spec(mac_spec),
      m_mac_keylen(mac_key_len) {}

std::unique_ptr<MessageAuthenticationCode> ECIES_System_Params::create_mac() const {
   return MessageAuthenticationCode::create_or_throw(m_mac_spec);
}

std::unique_ptr<Cipher_Mode> ECIES_System_Params::create_cipher(Cipher_Dir direction) const {
   return Cipher_Mode::create_or_throw(m_dem_spec, direction);
}

/*
* ECIES_Encryptor Constructor
*/
ECIES_Encryptor::ECIES_Encryptor(const PK_Key_Agreement_Key& private_key,
                                 const ECIES_System_Params& ecies_params,
                                 RandomNumberGenerator& rng) :
      m_ka(private_key, ecies_params, rng), m_params(ecies_params), m_eph_public_key_bin(private_key.public_value()) {
   if(ecies_params.point_format() != EC_Point_Format::Uncompressed) {
      // ISO 18033: step d
      // convert only if necessary; m_eph_public_key_bin has been initialized with the uncompressed format
      m_eph_public_key_bin =
         EC_AffinePoint(m_params.group(), m_eph_public_key_bin).serialize(ecies_params.point_format());
   }
   m_mac = m_params.create_mac();
   m_cipher = m_params.create_cipher(Cipher_Dir::Encryption);
}

/*
* ECIES_Encryptor Constructor
*/
ECIES_Encryptor::ECIES_Encryptor(RandomNumberGenerator& rng, const ECIES_System_Params& ecies_params) :
      ECIES_Encryptor(ECDH_PrivateKey(rng, ecies_params.group()), ecies_params, rng) {}

size_t ECIES_Encryptor::maximum_input_size() const {
   /*
   ECIES should just be used for key transport so this (arbitrary) limit
   seems sufficient
   */
   return 64;
}

size_t ECIES_Encryptor::ciphertext_length(size_t ptext_len) const {
   return m_eph_public_key_bin.size() + m_mac->output_length() + m_cipher->output_length(ptext_len);
}

/*
* ECIES Encryption according to ISO 18033-2
*/
std::vector<uint8_t> ECIES_Encryptor::enc(const uint8_t data[],
                                          size_t length,
                                          RandomNumberGenerator& /*unused*/) const {
   if(!m_other_point.has_value()) {
      throw Invalid_State("ECIES_Encryptor: peer key invalid or not set");
   }
   if(!m_iv.has_value()) {
      throw Invalid_State("ECIES requires a fresh IV be provided for each message");
   }
   if(m_iv->empty() && !m_cipher->valid_nonce_length(m_iv->size())) {
      throw Invalid_Argument("ECIES with " + m_cipher->name() + " requires an IV be set");
   }

   const SymmetricKey secret_key = m_ka.derive_secret(m_eph_public_key_bin, m_other_point.value());

   BOTAN_ASSERT_NOMSG(secret_key.size() == m_params.dem_keylen() + m_params.mac_keylen());

   // encryption

   m_cipher->set_key(SymmetricKey(secret_key.begin(), m_params.dem_keylen()));

   m_cipher->start(m_iv->bits_of());
   m_iv.reset();

   secure_vector<uint8_t> encrypted_data(data, data + length);
   m_cipher->finish(encrypted_data);

   // compute the MAC
   m_mac->set_key(secret_key.begin() + m_params.dem_keylen(), m_params.mac_keylen());
   m_mac->update(encrypted_data);
   if(!m_label.empty()) {
      m_mac->update(m_label);
   }
   const auto mac = m_mac->final();

   // concat elements
   return concat(m_eph_public_key_bin, encrypted_data, mac);
}

ECIES_Decryptor::ECIES_Decryptor(const PK_Key_Agreement_Key& key,
                                 const ECIES_System_Params& ecies_params,
                                 RandomNumberGenerator& rng) :
      m_ka(key, ecies_params, rng), m_params(ecies_params) {
   m_mac = m_params.create_mac();
   m_cipher = m_params.create_cipher(Cipher_Dir::Decryption);
}

namespace {

size_t compute_point_size(const EC_Group& group, EC_Point_Format format) {
   const size_t fe_bytes = group.get_p_bytes();
   if(format == EC_Point_Format::Compressed) {
      return 1 + fe_bytes;
   } else {
      return 1 + 2 * fe_bytes;
   }
}

}  // namespace

size_t ECIES_Decryptor::plaintext_length(size_t ctext_len) const {
   const size_t point_size = compute_point_size(m_params.group(), m_params.point_format());
   const size_t overhead = point_size + m_mac->output_length();

   if(ctext_len < overhead) {
      return 0;
   }

   return m_cipher->output_length(ctext_len - overhead);
}

size_t ECIES_Decryptor::ciphertext_length(size_t ptext_len) const {
   // We need the encryption direction to estimate the ciphertext length given
   // an expected plaintext length.
   auto cipher = m_params.create_cipher(Cipher_Dir::Encryption);

   const size_t point_size = compute_point_size(m_params.group(), m_params.point_format());
   const size_t mac_size = m_mac->output_length();
   const size_t ct_size_bound = cipher->output_length(ptext_len);
   return point_size + mac_size + ct_size_bound;
}

/**
* ECIES Decryption according to ISO 18033-2
*/
size_t ECIES_Decryptor::do_decrypt(uint8_t& valid_mask,
                                   std::span<uint8_t> ptext,
                                   std::span<const uint8_t> ctext) const {
   const uint8_t* in = ctext.data();
   const size_t in_len = ctext.size();
   const size_t point_size = compute_point_size(m_params.group(), m_params.point_format());

   if(in_len < point_size + m_mac->output_length()) {
      throw Decoding_Error("ECIES decryption: ciphertext is too short");
   }

   if(!m_iv.has_value()) {
      throw Invalid_State("ECIES requires a fresh IV be provided for each message");
   }
   if(m_iv->empty() && !m_cipher->valid_nonce_length(m_iv->size())) {
      throw Invalid_Argument("ECIES with " + m_cipher->name() + " requires an IV be set");
   }

   // extract data
   const std::vector<uint8_t> other_public_key_bin(in, in + point_size);  // the received (ephemeral) public key
   const std::vector<uint8_t> encrypted_data(in + point_size, in + in_len - m_mac->output_length());
   const std::vector<uint8_t> mac_data(in + in_len - m_mac->output_length(), in + in_len);

   // ISO 18033: step a
   auto other_public_key =
      [](const EC_Group& group, EC_Point_Format format, std::span<const uint8_t> key) -> std::optional<EC_AffinePoint> {
      if(format == EC_Point_Format::Compressed) {
         return EC_AffinePoint::deserialize_compressed(group, key);
      } else if(format == EC_Point_Format::Uncompressed) {
         return EC_AffinePoint::deserialize_uncompressed(group, key);
      } else {
         return {};
      }
   }(m_params.group(), m_params.point_format(), other_public_key_bin);

   if(!other_public_key) {
      throw Decoding_Error("Invalid ECIES public point");
   }

   // ISO 18033: step e (and step f, since the identity element cannot be decoded above)
   const SymmetricKey secret_key = m_ka.derive_secret(other_public_key_bin, *other_public_key);

   BOTAN_ASSERT_NOMSG(secret_key.size() == m_params.dem_keylen() + m_params.mac_keylen());

   // validate mac
   m_mac->set_key(secret_key.begin() + m_params.dem_keylen(), m_params.mac_keylen());
   m_mac->update(encrypted_data);
   if(!m_label.empty()) {
      m_mac->update(m_label);
   }
   const secure_vector<uint8_t> calculated_mac = m_mac->final();
   valid_mask = CT::is_equal<uint8_t>(mac_data, calculated_mac).value();

   // Consume the IV state even if the message is invalid
   auto iv = m_iv->bits_of();
   m_iv.reset();

   if(valid_mask == 0xFF) {
      // decrypt data

      m_cipher->set_key(SymmetricKey(secret_key.begin(), m_params.dem_keylen()));
      m_cipher->start(iv);

      try {
         // the decryption can fail:
         // e.g. Invalid_Authentication_Tag is thrown if GCM is used and the message does not have a valid tag
         secure_vector<uint8_t> decrypted_data(encrypted_data.begin(), encrypted_data.end());
         m_cipher->finish(decrypted_data);
         BOTAN_ARG_CHECK(ptext.size() >= decrypted_data.size(), "Output buffer too small for decryption");
         copy_mem(ptext.first(decrypted_data.size()), decrypted_data);
         return decrypted_data.size();
      } catch(...) {
         valid_mask = 0;
      }
   }
   return 0;
}

}  // namespace Botan
