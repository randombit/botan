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
#include <botan/hash.h>
#include <botan/mac.h>
#include <botan/mem_ops.h>
#include <botan/pkcs8.h>
#include <botan/rng.h>
#include <botan/internal/charset.h>
#include <botan/internal/fmt.h>
#include <botan/internal/pkcs12_kdf.h>
#include <botan/internal/pkcs12_pbe.h>

namespace Botan {

namespace {

// Associates a parsed certificate with its localKeyId bag attribute
struct ParsedCert {
      std::shared_ptr<X509_Certificate> cert;
      std::vector<uint8_t> local_key_id;
};

/*
* Encode a friendly name as a BMPString (UTF-16BE)
* ASN1_String doesn't support encoding BMPStrings, so we do it manually
*/
void encode_bmpstring(DER_Encoder& enc, std::string_view str) {
   // Convert the string to UTF-16BE
   const std::vector<uint8_t> utf16be = Botan::utf8_to_ucs2(std::string(str));
   enc.add_object(ASN1_Type::BmpString, ASN1_Class::Universal, utf16be);
}

/*
* Verify PKCS#12 MAC
*/
void verify_mac(std::span<const uint8_t> auth_safe_data,
                std::span<const uint8_t> mac_value,
                std::span<const uint8_t> mac_salt,
                size_t iterations,
                const OID& digest_algo_oid,
                std::string_view password) {
   std::string hash_name;

   // Map OID to hash name
   const std::string oid_str = digest_algo_oid.to_formatted_string();
   if(oid_str == "SHA-1" || oid_str == "SHA-256") {
      hash_name = oid_str;
   } else {
      throw Decoding_Error(fmt("Unsupported PKCS#12 MAC digest: {}", oid_str));
   }

   // Derive MAC key using PKCS#12 KDF with ID=3
   auto hash = HashFunction::create_or_throw(hash_name);
   const size_t mac_key_len = hash->output_length();

   secure_vector<uint8_t> mac_key(mac_key_len);
   pkcs12_kdf(mac_key.data(), mac_key_len, password, mac_salt.data(), mac_salt.size(), iterations, 3, hash_name);

   // Compute HMAC
   auto hmac = MessageAuthenticationCode::create_or_throw(fmt("HMAC({})", hash_name));
   hmac->set_key(mac_key);
   hmac->update(auth_safe_data);
   secure_vector<uint8_t> computed_mac = hmac->final();

   if(!constant_time_compare(computed_mac, mac_value)) {
      throw Invalid_Authentication_Tag("PKCS#12 MAC verification failed");
   }
}

/*
* Parse attributes from a SafeBag
*/
void parse_bag_attributes(BER_Decoder& decoder, std::string& friendly_name, std::vector<uint8_t>& local_key_id) {
   if(!decoder.more_items()) {
      return;
   }

   BER_Decoder attrs = decoder.start_set();
   while(attrs.more_items()) {
      OID attr_oid;
      BER_Decoder attr_seq = attrs.start_sequence();
      attr_seq.decode(attr_oid);

      BER_Decoder values = attr_seq.start_set();
      if(attr_oid == OID::from_string("PKCS9.FriendlyName")) {
         ASN1_String str;
         values.decode(str);
         friendly_name = str.value();
      } else if(attr_oid == OID::from_string("PKCS9.LocalKeyId")) {
         values.decode(local_key_id, ASN1_Type::OctetString);
      }
   }
}

/*
* Parse SafeContents (sequence of SafeBag)
*/
void parse_safe_contents(BER_Decoder& decoder,
                         std::string_view password,
                         std::vector<ParsedCert>& cert_entries,
                         std::shared_ptr<Private_Key>& key,
                         std::vector<uint8_t>& key_local_key_id,
                         std::string& friendly_name) {
   while(decoder.more_items()) {
      OID bag_type;
      std::string bag_friendly_name;
      std::vector<uint8_t> bag_key_id;

      BER_Decoder bag_seq = decoder.start_sequence();
      bag_seq.decode(bag_type);

      // bagValue is [0] EXPLICIT
      BER_Decoder bag_value = bag_seq.start_context_specific(0);

      bool is_cert_bag = false;
      bool is_key_bag = false;

      if(bag_type == OID::from_string("PKCS12.CertBag")) {
         is_cert_bag = true;
         OID cert_type;
         BER_Decoder cert_bag = bag_value.start_sequence();
         cert_bag.decode(cert_type);

         if(cert_type == OID::from_string("PKCS9.X509Certificate")) {
            // x509Certificate [0] EXPLICIT OCTET STRING
            std::vector<uint8_t> cert_data;
            BER_Decoder cert_value = cert_bag.start_context_specific(0);
            cert_value.decode(cert_data, ASN1_Type::OctetString);

            cert_entries.push_back({std::make_shared<X509_Certificate>(cert_data), {}});
         }
      } else if(bag_type == OID::from_string("PKCS12.PKCS8ShroudedKeyBag")) {
         is_key_bag = true;
         // PKCS8ShroudedKeyBag - encrypted private key
         AlgorithmIdentifier pbe_algo;
         std::vector<uint8_t> encrypted_key;

         BER_Decoder shrouded = bag_value.start_sequence();
         shrouded.decode(pbe_algo);
         shrouded.decode(encrypted_key, ASN1_Type::OctetString);

         auto decrypted = pkcs12_pbe_decrypt(encrypted_key, password, pbe_algo);
         DataSource_Memory src(decrypted);
         key = PKCS8::load_key(src);
      } else if(bag_type == OID::from_string("PKCS12.KeyBag")) {
         is_key_bag = true;
         // KeyBag - unencrypted private key (rarely used)
         std::vector<uint8_t> key_data;
         bag_value.raw_bytes(key_data);
         DataSource_Memory src(key_data);
         key = PKCS8::load_key(src);
      }

      bag_value.end_cons();

      // Parse attributes and associate with the bag they came from
      parse_bag_attributes(bag_seq, bag_friendly_name, bag_key_id);

      if(!bag_friendly_name.empty() && friendly_name.empty()) {
         friendly_name = bag_friendly_name;
      }
      if(!bag_key_id.empty()) {
         if(is_cert_bag && !cert_entries.empty()) {
            cert_entries.back().local_key_id = bag_key_id;
         } else if(is_key_bag && key_local_key_id.empty()) {
            key_local_key_id = bag_key_id;
         }
      }
   }
}

/*
* Parse AuthenticatedSafe (sequence of ContentInfo)
*/
void parse_authenticated_safe(std::span<const uint8_t> data,
                              std::string_view password,
                              std::vector<ParsedCert>& cert_entries,
                              std::shared_ptr<Private_Key>& key,
                              std::vector<uint8_t>& key_local_key_id,
                              std::string& friendly_name) {
   BER_Decoder auth_safe(data);
   BER_Decoder seq = auth_safe.start_sequence();

   while(seq.more_items()) {
      OID content_type;
      BER_Decoder content_info = seq.start_sequence();
      content_info.decode(content_type);

      if(content_type == OID::from_string("PKCS7.Data")) {
         // Unencrypted data: [0] EXPLICIT OCTET STRING containing SafeContents
         std::vector<uint8_t> safe_contents_data;
         BER_Decoder content = content_info.start_context_specific(0);
         content.decode(safe_contents_data, ASN1_Type::OctetString);

         BER_Decoder safe_contents(safe_contents_data);
         BER_Decoder sc_seq = safe_contents.start_sequence();
         parse_safe_contents(sc_seq, password, cert_entries, key, key_local_key_id, friendly_name);
      } else if(content_type == OID::from_string("PKCS7.EncryptedData")) {
         // Encrypted data
         BER_Decoder content = content_info.start_context_specific(0);
         BER_Decoder enc_data = content.start_sequence();

         size_t version = 0;
         enc_data.decode(version);

         // EncryptedContentInfo
         BER_Decoder enc_content_info = enc_data.start_sequence();
         OID enc_content_type;
         AlgorithmIdentifier enc_algo;
         enc_content_info.decode(enc_content_type);
         enc_content_info.decode(enc_algo);

         // Encrypted content is [0] - may be PRIMITIVE (IMPLICIT OCTET STRING)
         // or CONSTRUCTED containing an OCTET STRING
         std::vector<uint8_t> encrypted_content;

         // Get the next object to check if it's primitive or constructed
         const BER_Object enc_content_obj = enc_content_info.get_next_object();

         if(enc_content_obj.is_a(0, ASN1_Class::ContextSpecific)) {
            // PRIMITIVE [0] IMPLICIT OCTET STRING - content is the raw bytes
            encrypted_content.assign(enc_content_obj.bits(), enc_content_obj.bits() + enc_content_obj.length());
         } else if(enc_content_obj.is_a(0, ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
            // CONSTRUCTED [0] - may contain explicit OCTET STRING or raw bytes
            std::vector<uint8_t> raw_context_content(enc_content_obj.bits(),
                                                     enc_content_obj.bits() + enc_content_obj.length());

            // Check if content starts with OCTET STRING tag (0x04) - explicit encoding
            if(!raw_context_content.empty() && raw_context_content[0] == 0x04) {
               BER_Decoder inner(raw_context_content);
               inner.decode(encrypted_content, ASN1_Type::OctetString);
            } else {
               encrypted_content = std::move(raw_context_content);
            }
         } else {
            throw Decoding_Error("PKCS#12: Expected context-specific [0] for encrypted content");
         }

         // Decrypt
         const secure_vector<uint8_t> decrypted = pkcs12_pbe_decrypt(encrypted_content, password, enc_algo);

         BER_Decoder safe_contents(decrypted);
         BER_Decoder sc_seq = safe_contents.start_sequence();
         parse_safe_contents(sc_seq, password, cert_entries, key, key_local_key_id, friendly_name);
      }
   }
}

}  // namespace

std::vector<std::shared_ptr<X509_Certificate>> PKCS12_Data::all_certificates() const {
   std::vector<std::shared_ptr<X509_Certificate>> result;
   if(m_certificate) {
      result.push_back(m_certificate);
   }
   result.insert(result.end(), m_ca_certs.begin(), m_ca_certs.end());
   return result;
}

PKCS12_Data PKCS12::parse(std::span<const uint8_t> data, std::string_view password) {
   DataSource_Memory src(data.data(), data.size());
   return parse(src, password);
}

PKCS12_Data PKCS12::parse(DataSource& source, std::string_view password) {
   PKCS12_Data result;
   std::vector<ParsedCert> cert_entries;

   BER_Decoder pfx(source);
   BER_Decoder pfx_seq = pfx.start_sequence();

   // Version (should be 3)
   size_t version = 0;
   pfx_seq.decode(version);
   if(version != 3) {
      throw Decoding_Error(fmt("Unsupported PKCS#12 version: {}", version));
   }

   // authSafe ContentInfo
   OID auth_safe_type;
   std::vector<uint8_t> auth_safe_content;

   BER_Decoder auth_safe_info = pfx_seq.start_sequence();
   auth_safe_info.decode(auth_safe_type);

   if(auth_safe_type != OID::from_string("PKCS7.Data")) {
      throw Decoding_Error("PKCS#12 authSafe must be of type Data");
   }

   BER_Decoder auth_safe_content_wrapper = auth_safe_info.start_context_specific(0);
   auth_safe_content_wrapper.decode(auth_safe_content, ASN1_Type::OctetString);

   // MacData (optional)
   if(pfx_seq.more_items()) {
      BER_Decoder mac_data = pfx_seq.start_sequence();

      // DigestInfo
      BER_Decoder digest_info = mac_data.start_sequence();
      AlgorithmIdentifier digest_algo;
      std::vector<uint8_t> mac_value;
      digest_info.decode(digest_algo);
      digest_info.decode(mac_value, ASN1_Type::OctetString);

      std::vector<uint8_t> mac_salt;
      size_t iterations = 1;
      mac_data.decode(mac_salt, ASN1_Type::OctetString);
      if(mac_data.more_items()) {
         mac_data.decode(iterations);
      }

      // Verify MAC when password is provided. For empty passwords, some implementations
      // (e.g., older Java keytool) use zero bytes instead of the RFC 7292 null-terminated
      // UTF-16BE encoding, so verification is skipped for empty passwords to maintain
      // interoperability with such files.
      if(!password.empty()) {
         verify_mac(auth_safe_content, mac_value, mac_salt, iterations, digest_algo.oid(), password);
      }
   }

   // Parse AuthenticatedSafe
   std::shared_ptr<Private_Key> key;
   std::vector<uint8_t> key_local_key_id;
   parse_authenticated_safe(auth_safe_content, password, cert_entries, key, key_local_key_id, result.m_friendly_name);

   result.m_private_key = key;
   result.m_local_key_id = key_local_key_id;

   // Separate end-entity cert from CA certs.
   // Prefer matching via localKeyId (the attribute is designed for this purpose),
   // fall back to public key comparison only if localKeyId is absent.
   if(!cert_entries.empty()) {
      if(key != nullptr) {
         // Try localKeyId match first
         if(!key_local_key_id.empty()) {
            for(auto it = cert_entries.begin(); it != cert_entries.end(); ++it) {
               if(it->local_key_id == key_local_key_id) {
                  result.m_certificate = it->cert;
                  cert_entries.erase(it);
                  break;
               }
            }
         }

         // Fall back to public key comparison
         if(!result.m_certificate) {
            for(auto it = cert_entries.begin(); it != cert_entries.end(); ++it) {
               try {
                  auto cert_pk = it->cert->subject_public_key();
                  if(cert_pk && key->public_key_bits() == cert_pk->public_key_bits()) {
                     result.m_certificate = it->cert;
                     cert_entries.erase(it);
                     break;
                  }
               } catch(...) {}
            }
         }
      }

      // If still no match, use the first cert as the end-entity
      if(!result.m_certificate && !cert_entries.empty()) {
         result.m_certificate = cert_entries.front().cert;
         cert_entries.erase(cert_entries.begin());
      }

      for(auto& entry : cert_entries) {
         result.m_ca_certs.push_back(entry.cert);
      }
   }

   // Verify no trailing data
   pfx_seq.verify_end();

   return result;
}

std::vector<uint8_t> PKCS12::create(const Private_Key* key,
                                    const X509_Certificate* cert,
                                    const std::vector<X509_Certificate>& ca_certs,
                                    const PKCS12_Options& options,
                                    RandomNumberGenerator& rng) {
   if(key == nullptr && cert == nullptr && ca_certs.empty()) {
      throw Invalid_Argument("PKCS#12::create requires at least a key or certificate");
   }

   if(key != nullptr && cert != nullptr) {
      if(key->public_key()->subject_public_key() != cert->subject_public_key_info()) {
         throw Invalid_Argument("PKCS#12::create: private key does not match certificate");
      }
   }

   std::vector<uint8_t> auth_safe_content;

   // Generate local key ID from certificate (SHA-1 of public key)
   std::vector<uint8_t> local_key_id;
   if(cert != nullptr) {
      auto hash = HashFunction::create_or_throw("SHA-1");
      hash->update(cert->subject_public_key_bitstring());
      local_key_id.resize(hash->output_length());
      hash->final(local_key_id.data());
   }

   // Create CertBags
   std::vector<uint8_t> cert_safe_contents;
   {
      DER_Encoder cert_bags(cert_safe_contents);
      cert_bags.start_sequence();

      auto add_cert_bag = [&](const X509_Certificate& c, bool add_attrs) {
         cert_bags.start_sequence();
         cert_bags.encode(OID::from_string("PKCS12.CertBag"));

         // CertBag [0] EXPLICIT
         cert_bags.start_context_specific(0);
         cert_bags.start_sequence();
         cert_bags.encode(OID::from_string("PKCS9.X509Certificate"));
         // x509Certificate [0] EXPLICIT OCTET STRING
         cert_bags.start_context_specific(0);
         cert_bags.encode(c.BER_encode(), ASN1_Type::OctetString);
         cert_bags.end_cons();
         cert_bags.end_cons();
         cert_bags.end_cons();

         // Attributes
         if(add_attrs && (!options.friendly_name.empty() || !local_key_id.empty())) {
            cert_bags.start_set();
            if(!options.friendly_name.empty()) {
               cert_bags.start_sequence();
               cert_bags.encode(OID::from_string("PKCS9.FriendlyName"));
               cert_bags.start_set();
               encode_bmpstring(cert_bags, options.friendly_name);
               cert_bags.end_cons();
               cert_bags.end_cons();
            }
            if(!local_key_id.empty()) {
               cert_bags.start_sequence();
               cert_bags.encode(OID::from_string("PKCS9.LocalKeyId"));
               cert_bags.start_set();
               cert_bags.encode(local_key_id, ASN1_Type::OctetString);
               cert_bags.end_cons();
               cert_bags.end_cons();
            }
            cert_bags.end_cons();
         }

         cert_bags.end_cons();
      };

      if(cert != nullptr) {
         add_cert_bag(*cert, true);
      }
      for(const auto& ca : ca_certs) {
         add_cert_bag(ca, false);
      }

      cert_bags.end_cons();
   }

   // Create key SafeBag if key is provided
   std::vector<uint8_t> key_safe_contents;
   if(key != nullptr) {
      DER_Encoder key_bags(key_safe_contents);
      key_bags.start_sequence();
      key_bags.start_sequence();
      key_bags.encode(OID::from_string("PKCS12.PKCS8ShroudedKeyBag"));

      // Encrypt the private key
      secure_vector<uint8_t> pkcs8_key = PKCS8::BER_encode(*key);
      auto [enc_algo, enc_key] =
         pkcs12_pbe_encrypt(pkcs8_key, options.password, options.key_encryption_algo, options.iterations, rng);

      // PKCS8ShroudedKeyBag [0] EXPLICIT
      key_bags.start_context_specific(0);
      key_bags.start_sequence();
      key_bags.encode(enc_algo);
      key_bags.encode(enc_key, ASN1_Type::OctetString);
      key_bags.end_cons();
      key_bags.end_cons();

      // Attributes
      if(!options.friendly_name.empty() || !local_key_id.empty()) {
         key_bags.start_set();
         if(!options.friendly_name.empty()) {
            key_bags.start_sequence();
            key_bags.encode(OID::from_string("PKCS9.FriendlyName"));
            key_bags.start_set();
            encode_bmpstring(key_bags, options.friendly_name);
            key_bags.end_cons();
            key_bags.end_cons();
         }
         if(!local_key_id.empty()) {
            key_bags.start_sequence();
            key_bags.encode(OID::from_string("PKCS9.LocalKeyId"));
            key_bags.start_set();
            key_bags.encode(local_key_id, ASN1_Type::OctetString);
            key_bags.end_cons();
            key_bags.end_cons();
         }
         key_bags.end_cons();
      }

      key_bags.end_cons();
      key_bags.end_cons();
   }

   // Build AuthenticatedSafe
   DER_Encoder auth_safe(auth_safe_content);
   auth_safe.start_sequence();

   // First ContentInfo: certificates (optionally encrypted)
   if(cert != nullptr || !ca_certs.empty()) {
      if(!options.cert_encryption_algo.empty() && !options.password.empty()) {
         // Encrypt certificates
         auto [enc_algo, enc_data] = pkcs12_pbe_encrypt(
            cert_safe_contents, options.password, options.cert_encryption_algo, options.iterations, rng);

         auth_safe.start_sequence();
         auth_safe.encode(OID::from_string("PKCS7.EncryptedData"));
         auth_safe.start_context_specific(0);
         auth_safe.start_sequence();
         auth_safe.encode(size_t(0));  // version
         // EncryptedContentInfo
         auth_safe.start_sequence();
         auth_safe.encode(OID::from_string("PKCS7.Data"));
         auth_safe.encode(enc_algo);
         auth_safe.start_context_specific(0);
         auth_safe.raw_bytes(enc_data);
         auth_safe.end_cons();
         auth_safe.end_cons();
         auth_safe.end_cons();
         auth_safe.end_cons();
         auth_safe.end_cons();
      } else {
         // Unencrypted certificates
         auth_safe.start_sequence();
         auth_safe.encode(OID::from_string("PKCS7.Data"));
         auth_safe.start_context_specific(0);
         auth_safe.encode(cert_safe_contents, ASN1_Type::OctetString);
         auth_safe.end_cons();
         auth_safe.end_cons();
      }
   }

   // Second ContentInfo: private key (always encrypted via PKCS8ShroudedKeyBag)
   if(!key_safe_contents.empty()) {
      auth_safe.start_sequence();
      auth_safe.encode(OID::from_string("PKCS7.Data"));
      auth_safe.start_context_specific(0);
      auth_safe.encode(key_safe_contents, ASN1_Type::OctetString);
      auth_safe.end_cons();
      auth_safe.end_cons();
   }

   auth_safe.end_cons();

   // Build PFX
   std::vector<uint8_t> pfx_data;
   DER_Encoder pfx(pfx_data);
   pfx.start_sequence();
   pfx.encode(size_t(3));  // version

   // authSafe ContentInfo
   pfx.start_sequence();
   pfx.encode(OID::from_string("PKCS7.Data"));
   pfx.start_context_specific(0);
   pfx.encode(auth_safe_content, ASN1_Type::OctetString);
   pfx.end_cons();
   pfx.end_cons();

   // MacData (optional but recommended)
   if(options.include_mac && !options.password.empty()) {
      const std::string& mac_hash = options.mac_digest;

      std::vector<uint8_t> mac_salt(8);
      rng.randomize(mac_salt.data(), mac_salt.size());

      // Derive MAC key using PKCS#12 KDF with ID=3
      auto hmac = MessageAuthenticationCode::create_or_throw(fmt("HMAC({})", mac_hash));
      const size_t mac_key_len = hmac->output_length();
      secure_vector<uint8_t> mac_key(mac_key_len);
      pkcs12_kdf(mac_key.data(),
                 mac_key_len,
                 options.password,
                 mac_salt.data(),
                 mac_salt.size(),
                 options.iterations,
                 3,
                 mac_hash);

      // Compute HMAC
      hmac->set_key(mac_key);
      hmac->update(auth_safe_content);
      const secure_vector<uint8_t> mac_value = hmac->final();

      // MacData
      pfx.start_sequence();
      // DigestInfo
      pfx.start_sequence();
      pfx.encode(AlgorithmIdentifier(OID::from_string(mac_hash), AlgorithmIdentifier::USE_NULL_PARAM));
      pfx.encode(mac_value, ASN1_Type::OctetString);
      pfx.end_cons();
      pfx.encode(mac_salt, ASN1_Type::OctetString);
      pfx.encode(options.iterations);
      pfx.end_cons();
   }

   pfx.end_cons();

   return pfx_data;
}

}  // namespace Botan
