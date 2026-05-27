/*
* PKCS#12
* (C) 2026 Damiano Mazzella
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pkcs12.h>

#include <botan/asn1_obj.h>
#include <botan/ber_dec.h>
#include <botan/data_src.h>
#include <botan/der_enc.h>
#include <botan/exceptn.h>
#include <botan/hash.h>
#include <botan/mac.h>
#include <botan/mem_ops.h>
#include <botan/pkcs8.h>
#include <botan/rng.h>
#include <botan/internal/charset.h>
#include <botan/internal/fmt.h>
#include <botan/internal/pkcs12_kdf.h>
#include <botan/internal/pkcs12_pbe.h>
#include <algorithm>
#include <array>
#include <memory>

namespace Botan {

namespace {

// Associates a parsed certificate with its bag attributes
struct ParsedCert {
      X509_Certificate cert;
      std::vector<uint8_t> local_key_id;
      std::string friendly_name;
};

/*
* Encode a friendly name as a BMPString (UTF-16BE)
* ASN1_String doesn't support encoding BMPStrings, so we do it manually
*/
void encode_bmpstring(DER_Encoder& enc, std::string_view str) {
   const std::vector<uint8_t> utf16be = utf8_to_ucs2(str);
   enc.add_object(ASN1_Type::BmpString, ASN1_Class::Universal, utf16be);
}

/*
* Resolve a MAC digest OID to a hash name, throwing on unsupported algorithms.
*/
std::string resolve_mac_hash(const OID& oid) {
   if(oid == OID::from_string("SHA-1")) {
      return "SHA-1";
   }
   if(oid == OID::from_string("SHA-224")) {
      return "SHA-224";
   }
   if(oid == OID::from_string("SHA-256")) {
      return "SHA-256";
   }
   if(oid == OID::from_string("SHA-384")) {
      return "SHA-384";
   }
   if(oid == OID::from_string("SHA-512")) {
      return "SHA-512";
   }
   if(oid == OID::from_string("SHA-512-256")) {
      return "SHA-512-256";
   }
   throw Decoding_Error(fmt("Unsupported PKCS#12 MAC digest: {}", oid.to_formatted_string()));
}

/*
* Validate PKCS12_Export_Options before starting export.
*/
void validate_options(const PKCS12_Export_Options& opts) {
   if(opts.iterations() == 0 || opts.iterations() > PKCS12_MAX_ITERATIONS) {
      throw Invalid_Argument(fmt("PKCS#12: iteration count must be between 1 and {}", PKCS12_MAX_ITERATIONS));
   }
   static const std::array<std::string_view, 4> supported_key_algos = {
      "PBE-SHA1-3DES",
      "PBE-SHA1-2DES",
      "PBES2-SHA256-AES256",
      "PBES2-SHA256-AES128",
   };
   if(std::find(supported_key_algos.begin(), supported_key_algos.end(), opts.key_encryption_algo()) ==
      supported_key_algos.end()) {
      throw Invalid_Argument(fmt("PKCS#12: unsupported key encryption algorithm '{}'", opts.key_encryption_algo()));
   }
   if(!opts.cert_encryption_algo().empty()) {
      if(std::find(supported_key_algos.begin(), supported_key_algos.end(), opts.cert_encryption_algo()) ==
         supported_key_algos.end()) {
         throw Invalid_Argument(
            fmt("PKCS#12: unsupported cert encryption algorithm '{}'", opts.cert_encryption_algo()));
      }
      if(opts.password().empty()) {
         throw Invalid_Argument("PKCS#12: cert_encryption_algo requires a non-empty password");
      }
   }
   if(opts.include_mac()) {
      if(opts.password().empty()) {
         throw Invalid_Argument("PKCS#12: include_mac requires a non-empty password");
      }
      static const std::array<std::string_view, 6> supported_mac_digests = {
         "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA-512-256"};
      if(std::find(supported_mac_digests.begin(), supported_mac_digests.end(), opts.mac_digest()) ==
         supported_mac_digests.end()) {
         throw Invalid_Argument(fmt("PKCS#12: unsupported MAC digest '{}'", opts.mac_digest()));
      }
      if(!HashFunction::create(opts.mac_digest())) {
         throw Invalid_Argument(fmt("PKCS#12: MAC digest '{}' is not available in this build", opts.mac_digest()));
      }
   }
}

/*
* Verify PKCS#12 MAC.
*
* When @p openssl_empty_pwd_compat is @c true and @p password is empty, the
* KDF is fed an empty byte string (OpenSSL non-conforming behavior) instead
* of the RFC 7292 form (a two-byte {0x00,0x00} terminator).
*/
void verify_mac(std::span<const uint8_t> auth_safe_data,
                std::span<const uint8_t> mac_value,
                std::span<const uint8_t> mac_salt,
                size_t iterations,
                const std::string& hash_name,
                std::string_view password,
                bool openssl_empty_pwd_compat) {
   auto hmac = MessageAuthenticationCode::create_or_throw(fmt("HMAC({})", hash_name));
   const size_t mac_key_len = hmac->output_length();

   secure_vector<uint8_t> mac_key(mac_key_len);
   if(openssl_empty_pwd_compat && password.empty()) {
      const auto hash = HashFunction::create_or_throw(hash_name);
      pkcs12_kdf({mac_key.data(), mac_key_len}, {}, {mac_salt.data(), mac_salt.size()}, iterations, 3, *hash);
   } else {
      const PKCS12_KDF kdf(HashFunction::create_or_throw(hash_name), 3, iterations);
      kdf.derive_key(mac_key.data(), mac_key_len, password.data(), password.size(), mac_salt.data(), mac_salt.size());
   }

   hmac->set_key(mac_key);
   hmac->update(auth_safe_data);
   if(!constant_time_compare(hmac->final(), mac_value)) {
      throw Invalid_Authentication_Tag("PKCS#12 MAC verification failed");
   }
}

/*
* Parse attributes from a SafeBag. Only FriendlyName and LocalKeyId are
* handled; other attributes are silently skipped (RFC 7292 sec.4.2).
*/
void parse_bag_attributes(BER_Decoder& decoder, std::string& friendly_name, std::vector<uint8_t>& local_key_id) {
   if(!decoder.more_items()) {
      return;
   }

   const OID friendly_name_oid = OID::from_string("PKCS9.FriendlyName");
   const OID local_key_id_oid = OID::from_string("PKCS9.LocalKeyId");

   BER_Decoder attrs = decoder.start_set();
   while(attrs.more_items()) {
      OID attr_oid;
      BER_Decoder attr_seq = attrs.start_sequence();
      attr_seq.decode(attr_oid);

      BER_Decoder values = attr_seq.start_set();
      if(attr_oid == friendly_name_oid) {
         ASN1_String str;
         values.decode(str);
         friendly_name = str.value();
      } else if(attr_oid == local_key_id_oid) {
         values.decode(local_key_id, ASN1_Type::OctetString);
      }
      values.discard_remaining();
      values.end_cons();
      attr_seq.discard_remaining();
      attr_seq.end_cons();
   }
   attrs.end_cons();
}

// Helper bag carrying a parsed private key with its attributes.
struct ParsedKey {
      std::shared_ptr<Private_Key> key;
      std::vector<uint8_t> local_key_id;
      std::string friendly_name;
};

/*
* Parse SafeContents (sequence of SafeBag)
*/
void parse_safe_contents(BER_Decoder& decoder,
                         std::string_view password,
                         std::vector<ParsedCert>& cert_entries,
                         std::vector<ParsedKey>& key_entries,
                         std::vector<OID>& unknown_bag_types,
                         bool openssl_empty_pwd_compat,
                         size_t depth = 0) {
   if(depth >= PKCS12_MAX_NESTING) {
      throw Decoding_Error("PKCS#12: SafeContentsBag nesting too deep");
   }
   const OID cert_bag_oid = OID::from_string("PKCS12.CertBag");
   const OID shrouded_key_bag_oid = OID::from_string("PKCS12.PKCS8ShroudedKeyBag");
   const OID key_bag_oid = OID::from_string("PKCS12.KeyBag");
   const OID safe_contents_bag_oid = OID::from_string("PKCS12.SafeContentsBag");
   const OID x509_cert_oid = OID::from_string("PKCS9.X509Certificate");

   while(decoder.more_items()) {
      OID bag_type;
      std::string bag_friendly_name;
      std::vector<uint8_t> bag_key_id;

      BER_Decoder bag_seq = decoder.start_sequence();
      bag_seq.decode(bag_type);

      BER_Decoder bag_value = bag_seq.start_context_specific(0);

      bool pushed_cert = false;
      bool pushed_key = false;

      if(bag_type == cert_bag_oid) {
         OID cert_type;
         BER_Decoder cert_bag = bag_value.start_sequence();
         cert_bag.decode(cert_type);

         if(cert_type == x509_cert_oid) {
            std::vector<uint8_t> cert_data;
            BER_Decoder cert_value = cert_bag.start_context_specific(0);
            cert_value.decode(cert_data, ASN1_Type::OctetString);
            cert_value.verify_end();

            cert_entries.push_back({X509_Certificate(cert_data), {}, {}});
            pushed_cert = true;
         } else {
            cert_bag.discard_remaining();
         }
         cert_bag.end_cons();
         bag_value.verify_end();
      } else if(bag_type == shrouded_key_bag_oid) {
         AlgorithmIdentifier pbe_algo;
         std::vector<uint8_t> encrypted_key;

         BER_Decoder shrouded = bag_value.start_sequence();
         shrouded.decode(pbe_algo);
         shrouded.decode(encrypted_key, ASN1_Type::OctetString);
         shrouded.verify_end();

         auto decrypted = pkcs12_pbe_decrypt(encrypted_key, password, pbe_algo, openssl_empty_pwd_compat);
         DataSource_Memory src(decrypted);
         key_entries.push_back({std::shared_ptr<Private_Key>(PKCS8::load_key(src)), {}, {}});
         pushed_key = true;
      } else if(bag_type == key_bag_oid) {
         secure_vector<uint8_t> key_data;
         bag_value.raw_bytes(key_data);
         bag_value.verify_end();
         DataSource_Memory src(key_data);
         key_entries.push_back({std::shared_ptr<Private_Key>(PKCS8::load_key(src)), {}, {}});
         pushed_key = true;
      } else if(bag_type == safe_contents_bag_oid) {
         BER_Decoder nested_sc = bag_value.start_sequence();
         parse_safe_contents(
            nested_sc, password, cert_entries, key_entries, unknown_bag_types, openssl_empty_pwd_compat, depth + 1);
         nested_sc.verify_end();
         bag_value.verify_end();
      } else {
         unknown_bag_types.push_back(bag_type);
         bag_value.discard_remaining();
      }

      bag_value.end_cons();

      parse_bag_attributes(bag_seq, bag_friendly_name, bag_key_id);

      if(pushed_cert && !cert_entries.empty()) {
         if(!bag_key_id.empty()) {
            cert_entries.back().local_key_id = bag_key_id;
         }
         if(!bag_friendly_name.empty()) {
            cert_entries.back().friendly_name = bag_friendly_name;
         }
      } else if(pushed_key && !key_entries.empty()) {
         if(!bag_key_id.empty()) {
            key_entries.back().local_key_id = bag_key_id;
         }
         if(!bag_friendly_name.empty()) {
            key_entries.back().friendly_name = bag_friendly_name;
         }
      }

      bag_seq.verify_end();
   }
}

/*
* Parse AuthenticatedSafe (sequence of ContentInfo)
*/
void parse_authenticated_safe(std::span<const uint8_t> data,
                              std::string_view password,
                              std::vector<ParsedCert>& cert_entries,
                              std::vector<ParsedKey>& key_entries,
                              std::vector<OID>& unknown_bag_types,
                              bool openssl_empty_pwd_compat) {
   const OID pkcs7_data_oid = OID::from_string("PKCS7.Data");
   const OID pkcs7_enc_data_oid = OID::from_string("PKCS7.EncryptedData");

   BER_Decoder auth_safe(data);
   BER_Decoder seq = auth_safe.start_sequence();

   while(seq.more_items()) {
      OID content_type;
      BER_Decoder content_info = seq.start_sequence();
      content_info.decode(content_type);

      if(content_type == pkcs7_data_oid) {
         std::vector<uint8_t> safe_contents_data;
         BER_Decoder content = content_info.start_context_specific(0);
         content.decode(safe_contents_data, ASN1_Type::OctetString);
         content.verify_end();

         BER_Decoder safe_contents(safe_contents_data);
         BER_Decoder sc_seq = safe_contents.start_sequence();
         parse_safe_contents(sc_seq, password, cert_entries, key_entries, unknown_bag_types, openssl_empty_pwd_compat);
         sc_seq.verify_end();
         safe_contents.verify_end();
         content_info.verify_end();
      } else if(content_type == pkcs7_enc_data_oid) {
         BER_Decoder content = content_info.start_context_specific(0);
         BER_Decoder enc_data = content.start_sequence();

         size_t version = 0;
         enc_data.decode(version);

         if(version != 0) {
            throw Decoding_Error(fmt("PKCS#12: unsupported EncryptedData version: {}", version));
         }

         BER_Decoder enc_content_info = enc_data.start_sequence();
         OID enc_content_type;
         AlgorithmIdentifier enc_algo;
         enc_content_info.decode(enc_content_type);
         enc_content_info.decode(enc_algo);

         if(enc_content_type != pkcs7_data_oid) {
            throw Decoding_Error(
               fmt("PKCS#12: EncryptedData contentType must be Data, got {}", enc_content_type.to_formatted_string()));
         }

         std::vector<uint8_t> encrypted_content;
         const BER_Object enc_content_obj = enc_content_info.get_next_object();

         if(enc_content_obj.is_a(0, ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
            const std::span<const uint8_t> raw(enc_content_obj.bits(), enc_content_obj.length());
            encrypted_content.reserve(raw.size());
            BER_Decoder chunks(raw);
            while(chunks.more_items()) {
               std::vector<uint8_t> chunk;
               chunks.decode(chunk, ASN1_Type::OctetString);
               encrypted_content.insert(encrypted_content.end(), chunk.begin(), chunk.end());
            }
            chunks.verify_end();
         } else if(enc_content_obj.is_a(0, ASN1_Class::ContextSpecific)) {
            encrypted_content.assign(enc_content_obj.bits(), enc_content_obj.bits() + enc_content_obj.length());
         } else {
            throw Decoding_Error("PKCS#12: Expected [0] context-specific for encrypted content");
         }

         enc_content_info.verify_end();
         enc_data.verify_end();

         const secure_vector<uint8_t> decrypted =
            pkcs12_pbe_decrypt(encrypted_content, password, enc_algo, openssl_empty_pwd_compat);

         BER_Decoder safe_contents(decrypted);
         BER_Decoder sc_seq = safe_contents.start_sequence();
         parse_safe_contents(sc_seq, password, cert_entries, key_entries, unknown_bag_types, openssl_empty_pwd_compat);
         sc_seq.verify_end();
         safe_contents.verify_end();
         content.verify_end();
         content_info.verify_end();
      } else {
         throw Decoding_Error(
            fmt("PKCS#12: unsupported AuthenticatedSafe content type {}", content_type.to_formatted_string()));
      }
   }

   seq.verify_end();
   auth_safe.verify_end();
}

}  // namespace

//
// PKCS12_Export_Options
//

PKCS12_Export_Options::PKCS12_Export_Options(std::string_view password, std::optional<std::string> friendly_name) :
      m_password(password), m_friendly_name(std::move(friendly_name)) {}

PKCS12_Export_Options PKCS12_Export_Options::modern(std::string_view password,
                                                    std::optional<std::string> friendly_name) {
   return PKCS12_Export_Options(password, std::move(friendly_name));
}

PKCS12_Export_Options PKCS12_Export_Options::legacy_compat(std::string_view password,
                                                           std::optional<std::string> friendly_name) {
   PKCS12_Export_Options opts(password, std::move(friendly_name));
   opts.m_iterations = 2048;
   opts.m_key_encryption_algo = "PBE-SHA1-3DES";
   opts.m_mac_digest = "SHA-1";
   return opts;
}

PKCS12_Export_Options& PKCS12_Export_Options::with_friendly_name(std::string name) {
   m_friendly_name = std::move(name);
   return *this;
}

PKCS12_Export_Options& PKCS12_Export_Options::with_iterations(size_t n) {
   m_iterations = n;
   return *this;
}

PKCS12_Export_Options& PKCS12_Export_Options::with_key_encryption_algo(std::string algo) {
   m_key_encryption_algo = std::move(algo);
   return *this;
}

PKCS12_Export_Options& PKCS12_Export_Options::with_cert_encryption_algo(std::string algo) {
   m_cert_encryption_algo = std::move(algo);
   return *this;
}

PKCS12_Export_Options& PKCS12_Export_Options::with_mac_digest(std::string algo) {
   m_mac_digest = std::move(algo);
   return *this;
}

PKCS12_Export_Options& PKCS12_Export_Options::without_mac() {
   m_include_mac = false;
   return *this;
}

//
// PKCS12
//

PKCS12::PKCS12(std::span<const uint8_t> data, std::string_view password) {
   std::vector<ParsedCert> cert_entries;
   std::vector<ParsedKey> key_entries;

   BER_Decoder pfx(data);
   BER_Decoder pfx_seq = pfx.start_sequence();

   size_t version = 0;
   pfx_seq.decode(version);
   if(version != 3) {
      throw Decoding_Error(fmt("Unsupported PKCS#12 version: {}", version));
   }

   OID auth_safe_type;
   std::vector<uint8_t> auth_safe_content;

   BER_Decoder auth_safe_info = pfx_seq.start_sequence();
   auth_safe_info.decode(auth_safe_type);

   const OID pkcs7_data_oid = OID::from_string("PKCS7.Data");
   if(auth_safe_type != pkcs7_data_oid) {
      throw Decoding_Error("PKCS#12 authSafe must be of type Data");
   }

   BER_Decoder auth_safe_content_wrapper = auth_safe_info.start_context_specific(0);
   auth_safe_content_wrapper.decode(auth_safe_content, ASN1_Type::OctetString);
   auth_safe_content_wrapper.verify_end();
   auth_safe_info.verify_end();

   // Tracks whether MAC verification succeeded with OpenSSL's non-conforming
   // empty-password encoding; if so, the same convention is used for any
   // subsequent EncryptedData / PKCS8ShroudedKeyBag decryption.
   bool openssl_empty_pwd_compat = false;

   if(pfx_seq.more_items()) {
      BER_Decoder mac_data = pfx_seq.start_sequence();

      BER_Decoder digest_info = mac_data.start_sequence();
      AlgorithmIdentifier digest_algo;
      std::vector<uint8_t> mac_value;
      digest_info.decode(digest_algo);
      digest_info.decode(mac_value, ASN1_Type::OctetString);
      digest_info.verify_end();

      std::vector<uint8_t> mac_salt;
      size_t iterations = 1;
      mac_data.decode(mac_salt, ASN1_Type::OctetString);
      if(mac_data.more_items()) {
         mac_data.decode(iterations);
      }
      mac_data.verify_end();
      if(iterations == 0 || iterations > PKCS12_MAX_ITERATIONS) {
         throw Decoding_Error(fmt("PKCS#12 MAC has invalid iteration count: {}", iterations));
      }

      const std::string hash_name = resolve_mac_hash(digest_algo.oid());
      // Try RFC 7292 password encoding first. If MAC verification fails and
      // the password is empty, retry with OpenSSL's non-conforming empty
      // encoding (some OpenSSL releases pass an empty byte string to the KDF
      // instead of the RFC {0x00,0x00} form when the password is empty).
      // Propagate the chosen convention to any subsequent PBE decryption.
      try {
         verify_mac(auth_safe_content, mac_value, mac_salt, iterations, hash_name, password, false);
      } catch(const Invalid_Authentication_Tag&) {
         if(!password.empty()) {
            throw;
         }
         verify_mac(auth_safe_content, mac_value, mac_salt, iterations, hash_name, password, true);
         openssl_empty_pwd_compat = true;
      }
   }

   parse_authenticated_safe(
      auth_safe_content, password, cert_entries, key_entries, m_unknown_bag_types, openssl_empty_pwd_compat);

   // Move all parsed keys into storage.
   m_private_keys.reserve(key_entries.size());
   for(auto& ke : key_entries) {
      m_private_keys.push_back(std::move(ke.key));
   }

   // Capture bundle-level attributes from the first key (if any), or from
   // the end-entity certificate (if found below).
   if(!key_entries.empty()) {
      if(!key_entries.front().friendly_name.empty()) {
         m_friendly_name = key_entries.front().friendly_name;
      }
      if(!key_entries.front().local_key_id.empty()) {
         m_local_key_id = key_entries.front().local_key_id;
      }
   }

   // Reorder certificates so the end-entity (cert matching the first key)
   // comes first; rest follow in original order. Match prefers localKeyId,
   // falls back to subjectPublicKeyInfo comparison.
   std::optional<size_t> end_entity_idx;
   if(!cert_entries.empty() && !m_private_keys.empty()) {
      const auto& first_key = m_private_keys.front();
      const auto& first_key_id = key_entries.empty() ? std::vector<uint8_t>{} : key_entries.front().local_key_id;

      if(!first_key_id.empty()) {
         for(size_t i = 0; i < cert_entries.size(); ++i) {
            if(cert_entries[i].local_key_id == first_key_id) {
               end_entity_idx = i;
               break;
            }
         }
      }
      if(!end_entity_idx) {
         const auto key_spki = first_key->subject_public_key();
         for(size_t i = 0; i < cert_entries.size(); ++i) {
            try {
               if(cert_entries[i].cert.subject_public_key_info() == key_spki) {
                  end_entity_idx = i;
                  break;
               }
            } catch(const Decoding_Error&) {
               // Certificate with unsupported key algorithm - skip
            }
         }
      }
   }

   m_certificates.reserve(cert_entries.size());
   if(end_entity_idx) {
      m_certificates.push_back(std::move(cert_entries[*end_entity_idx].cert));
      if(!m_friendly_name && !cert_entries[*end_entity_idx].friendly_name.empty()) {
         m_friendly_name = cert_entries[*end_entity_idx].friendly_name;
      }
      if(!m_local_key_id && !cert_entries[*end_entity_idx].local_key_id.empty()) {
         m_local_key_id = cert_entries[*end_entity_idx].local_key_id;
      }
      for(size_t i = 0; i < cert_entries.size(); ++i) {
         if(i != *end_entity_idx) {
            // Still surface any friendly name found on non-end-entity certs
            // when the bundle doesn't have one yet (some producers attach the
            // attribute to the CA bag instead of the end-entity bag).
            if(!m_friendly_name && !cert_entries[i].friendly_name.empty()) {
               m_friendly_name = cert_entries[i].friendly_name;
            }
            m_certificates.push_back(std::move(cert_entries[i].cert));
         }
      }
   } else {
      for(auto& ce : cert_entries) {
         if(!m_friendly_name && !ce.friendly_name.empty()) {
            m_friendly_name = ce.friendly_name;
         }
         m_certificates.push_back(std::move(ce.cert));
      }
   }

   pfx_seq.verify_end();
   pfx_seq.end_cons();
   pfx.verify_end("PKCS#12: trailing data after PFX");
}

std::vector<X509_Certificate> PKCS12::ca_certificates() const {
   if(m_certificates.size() < 2) {
      return {};
   }
   const auto ee = end_entity_certificate();
   std::vector<X509_Certificate> result;
   result.reserve(m_certificates.size() - 1);
   if(ee) {
      // Skip the first certificate matching the end-entity (only one, in case
      // the bundle contains multiple certs signed for the same key, e.g. an
      // old leaf still kept alongside a renewed one).
      const auto ee_spki = ee->subject_public_key_info();
      bool skipped = false;
      for(const auto& c : m_certificates) {
         if(!skipped && c.subject_public_key_info() == ee_spki) {
            skipped = true;
            continue;
         }
         result.push_back(c);
      }
   } else {
      // No end-entity (e.g. key-less bundle): treat the first stored cert as
      // the "primary" and surface the rest as CA / chain certs. This matches
      // the storage order used by parsing.
      for(size_t i = 1; i < m_certificates.size(); ++i) {
         result.push_back(m_certificates[i]);
      }
   }
   return result;
}

std::optional<X509_Certificate> PKCS12::end_entity_certificate() const {
   if(m_certificates.empty() || m_private_keys.empty()) {
      return std::nullopt;
   }
   const auto& first_key = m_private_keys.front();
   const auto key_spki = first_key->subject_public_key();
   for(const auto& c : m_certificates) {
      try {
         if(c.subject_public_key_info() == key_spki) {
            return c;
         }
      } catch(const Decoding_Error&) {
         // Skip certificates with unsupported algorithms
      }
   }
   return std::nullopt;
}

void PKCS12::add_key(std::shared_ptr<Private_Key> key) {
   if(!key) {
      throw Invalid_Argument("PKCS12::add_key: key must not be null");
   }
   m_private_keys.push_back(std::move(key));
}

void PKCS12::add_certificate(X509_Certificate cert) {
   m_certificates.push_back(std::move(cert));
}

void PKCS12::set_friendly_name(std::string name) {
   m_friendly_name = std::move(name);
}

void PKCS12::clear_friendly_name() {
   m_friendly_name.reset();
}

void PKCS12::set_local_key_id(std::vector<uint8_t> id) {
   m_local_key_id = std::move(id);
}

void PKCS12::clear_local_key_id() {
   m_local_key_id.reset();
}

std::vector<uint8_t> PKCS12::export_to(const PKCS12_Export_Options& options, RandomNumberGenerator& rng) const {
   if(m_private_keys.empty() && m_certificates.empty()) {
      throw Invalid_Argument("PKCS#12::export_to requires at least a key or certificate");
   }

   validate_options(options);

   // Determine end-entity certificate(s). With a single key we pair it
   // against a cert matching its SPKI; that pair gets the
   // friendly_name/localKeyId from options or the bundle.
   std::optional<size_t> end_entity_idx;
   if(!m_private_keys.empty() && !m_certificates.empty()) {
      const auto& first_key = m_private_keys.front();
      const auto key_spki = first_key->subject_public_key();
      for(size_t i = 0; i < m_certificates.size(); ++i) {
         try {
            if(m_certificates[i].subject_public_key_info() == key_spki) {
               end_entity_idx = i;
               break;
            }
         } catch(const Decoding_Error&) {
            // skip
         }
      }
      if(!end_entity_idx) {
         throw Invalid_Argument("PKCS#12::export_to: private key does not match any certificate");
      }
   }

   const OID cert_bag_oid = OID::from_string("PKCS12.CertBag");
   const OID shrouded_key_oid = OID::from_string("PKCS12.PKCS8ShroudedKeyBag");
   const OID x509_cert_oid = OID::from_string("PKCS9.X509Certificate");
   const OID friendly_name_oid = OID::from_string("PKCS9.FriendlyName");
   const OID local_key_id_oid = OID::from_string("PKCS9.LocalKeyId");
   const OID pkcs7_data_oid = OID::from_string("PKCS7.Data");
   const OID pkcs7_enc_data_oid = OID::from_string("PKCS7.EncryptedData");

   // Pick the friendly-name and local-key-id used by attribute encoding.
   // Options take precedence over the bundle-level fields.
   const std::optional<std::string>& friendly_name =
      options.friendly_name().has_value() ? options.friendly_name() : m_friendly_name;

   std::vector<uint8_t> local_key_id;
   if(m_local_key_id) {
      local_key_id = *m_local_key_id;
   } else if(end_entity_idx) {
      local_key_id = m_certificates[*end_entity_idx].subject_public_key_bitstring_sha1();
   } else if(!m_private_keys.empty()) {
      // Key-only bundle: derive from SHA-1 of the public key bits (matching the
      // convention used by X509_Certificate::subject_public_key_bitstring_sha1).
      auto sha1 = HashFunction::create_or_throw("SHA-1");
      const auto pub_bits = m_private_keys.front()->public_key_bits();
      sha1->update(pub_bits);
      local_key_id = unlock(sha1->final());
   }

   auto write_attributes = [&](DER_Encoder& enc) {
      const bool has_fn = friendly_name.has_value() && !friendly_name->empty();
      const bool has_id = !local_key_id.empty();
      if(!has_fn && !has_id) {
         return;
      }
      enc.start_set();
      if(has_fn) {
         enc.start_sequence();
         enc.encode(friendly_name_oid);
         enc.start_set();
         encode_bmpstring(enc, *friendly_name);
         enc.end_cons();
         enc.end_cons();
      }
      if(has_id) {
         enc.start_sequence();
         enc.encode(local_key_id_oid);
         enc.start_set();
         enc.encode(local_key_id, ASN1_Type::OctetString);
         enc.end_cons();
         enc.end_cons();
      }
      enc.end_cons();
   };

   // CertBags
   std::vector<uint8_t> cert_safe_contents;
   if(!m_certificates.empty()) {
      DER_Encoder cert_bags(cert_safe_contents);
      cert_bags.start_sequence();

      auto add_cert_bag = [&](const X509_Certificate& c, bool add_attrs) {
         cert_bags.start_sequence();
         cert_bags.encode(cert_bag_oid);

         cert_bags.start_context_specific(0);
         cert_bags.start_sequence();
         cert_bags.encode(x509_cert_oid);
         cert_bags.start_context_specific(0);
         cert_bags.encode(c.BER_encode(), ASN1_Type::OctetString);
         cert_bags.end_cons();
         cert_bags.end_cons();
         cert_bags.end_cons();

         if(add_attrs) {
            write_attributes(cert_bags);
         }

         cert_bags.end_cons();
      };

      // End-entity first (so the file is read in the typical order), then
      // the rest in their stored order.
      if(end_entity_idx) {
         add_cert_bag(m_certificates[*end_entity_idx], true);
         for(size_t i = 0; i < m_certificates.size(); ++i) {
            if(i != *end_entity_idx) {
               add_cert_bag(m_certificates[i], false);
            }
         }
      } else {
         for(const auto& c : m_certificates) {
            add_cert_bag(c, false);
         }
      }

      cert_bags.end_cons();
   }

   // Key SafeBag(s)
   std::vector<uint8_t> key_safe_contents;
   if(!m_private_keys.empty()) {
      DER_Encoder key_bags(key_safe_contents);
      key_bags.start_sequence();

      for(size_t i = 0; i < m_private_keys.size(); ++i) {
         const Private_Key& key = *m_private_keys[i];

         key_bags.start_sequence();
         key_bags.encode(shrouded_key_oid);

         secure_vector<uint8_t> pkcs8_key = PKCS8::BER_encode(key);
         auto [enc_algo, enc_key] =
            pkcs12_pbe_encrypt(pkcs8_key, options.password(), options.key_encryption_algo(), options.iterations(), rng);

         key_bags.start_context_specific(0);
         key_bags.start_sequence();
         key_bags.encode(enc_algo);
         key_bags.encode(enc_key, ASN1_Type::OctetString);
         key_bags.end_cons();
         key_bags.end_cons();

         // Only the first key carries the bundle-level attributes (preserves
         // the historical single-key behavior).
         if(i == 0) {
            write_attributes(key_bags);
         }

         key_bags.end_cons();
      }
      key_bags.end_cons();
   }

   // AuthenticatedSafe
   std::vector<uint8_t> auth_safe_content;
   DER_Encoder auth_safe(auth_safe_content);
   auth_safe.start_sequence();

   if(!cert_safe_contents.empty()) {
      if(!options.cert_encryption_algo().empty()) {
         auto [enc_algo, enc_data] = pkcs12_pbe_encrypt(
            cert_safe_contents, options.password(), options.cert_encryption_algo(), options.iterations(), rng);

         auth_safe.start_sequence();
         auth_safe.encode(pkcs7_enc_data_oid);
         auth_safe.start_context_specific(0);
         auth_safe.start_sequence();
         auth_safe.encode(size_t(0));
         auth_safe.start_sequence();
         auth_safe.encode(pkcs7_data_oid);
         auth_safe.encode(enc_algo);
         auth_safe.add_object(ASN1_Type(0), ASN1_Class::ContextSpecific, enc_data);
         auth_safe.end_cons();
         auth_safe.end_cons();
         auth_safe.end_cons();
         auth_safe.end_cons();
      } else {
         auth_safe.start_sequence();
         auth_safe.encode(pkcs7_data_oid);
         auth_safe.start_context_specific(0);
         auth_safe.encode(cert_safe_contents, ASN1_Type::OctetString);
         auth_safe.end_cons();
         auth_safe.end_cons();
      }
   }

   if(!key_safe_contents.empty()) {
      auth_safe.start_sequence();
      auth_safe.encode(pkcs7_data_oid);
      auth_safe.start_context_specific(0);
      auth_safe.encode(key_safe_contents, ASN1_Type::OctetString);
      auth_safe.end_cons();
      auth_safe.end_cons();
   }

   auth_safe.end_cons();

   // PFX
   std::vector<uint8_t> pfx_data;
   DER_Encoder pfx(pfx_data);
   pfx.start_sequence();
   pfx.encode(size_t(3));

   pfx.start_sequence();
   pfx.encode(pkcs7_data_oid);
   pfx.start_context_specific(0);
   pfx.encode(auth_safe_content, ASN1_Type::OctetString);
   pfx.end_cons();
   pfx.end_cons();

   if(options.include_mac()) {
      const std::string& mac_hash = options.mac_digest();

      auto hmac = MessageAuthenticationCode::create_or_throw(fmt("HMAC({})", mac_hash));

      std::vector<uint8_t> mac_salt(hmac->output_length());
      rng.randomize(mac_salt.data(), mac_salt.size());
      const size_t mac_key_len = hmac->output_length();
      secure_vector<uint8_t> mac_key(mac_key_len);
      const PKCS12_KDF kdf(HashFunction::create_or_throw(mac_hash), 3, options.iterations());
      kdf.derive_key(mac_key.data(),
                     mac_key_len,
                     options.password().data(),
                     options.password().size(),
                     mac_salt.data(),
                     mac_salt.size());

      hmac->set_key(mac_key);
      hmac->update(auth_safe_content);
      const secure_vector<uint8_t> mac_value = hmac->final();

      pfx.start_sequence();
      pfx.start_sequence();
      const auto param_encoding =
         (mac_hash == "SHA-1") ? AlgorithmIdentifier::USE_NULL_PARAM : AlgorithmIdentifier::USE_EMPTY_PARAM;
      pfx.encode(AlgorithmIdentifier(OID::from_string(mac_hash), param_encoding));
      pfx.encode(mac_value, ASN1_Type::OctetString);
      pfx.end_cons();
      pfx.encode(mac_salt, ASN1_Type::OctetString);
      if(options.iterations() != 1) {
         pfx.encode(options.iterations());
      }
      pfx.end_cons();
   }

   pfx.end_cons();

   return pfx_data;
}

}  // namespace Botan
