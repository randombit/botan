/*
* PKCS#12
* (C) 2026
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pkcs12.h>

#include <botan/asn1_obj.h>
#include <botan/ber_dec.h>
#include <botan/mem_ops.h>
#include <botan/cipher_mode.h>
#include <botan/data_src.h>
#include <botan/der_enc.h>
#include <botan/hash.h>
#include <botan/mac.h>
#include <botan/pkcs12_kdf.h>
#include <botan/pkcs8.h>
#include <botan/rng.h>
#include <botan/internal/fmt.h>

#if defined(BOTAN_HAS_PKCS5_PBES2)
   #include <botan/internal/pbes2.h>
#endif

namespace Botan {

namespace {

// OID constants for PKCS#12
const OID OID_PKCS7_DATA("1.2.840.113549.1.7.1");
const OID OID_PKCS7_ENCRYPTED_DATA("1.2.840.113549.1.7.6");
const OID OID_PKCS12_KEY_BAG("1.2.840.113549.1.12.10.1.1");
const OID OID_PKCS12_SHROUDED_KEY_BAG("1.2.840.113549.1.12.10.1.2");
const OID OID_PKCS12_CERT_BAG("1.2.840.113549.1.12.10.1.3");
const OID OID_PKCS12_CRL_BAG("1.2.840.113549.1.12.10.1.4");
const OID OID_PKCS9_X509_CERT("1.2.840.113549.1.9.22.1");
const OID OID_PKCS9_FRIENDLY_NAME("1.2.840.113549.1.9.20");
const OID OID_PKCS9_LOCAL_KEY_ID("1.2.840.113549.1.9.21");
const OID OID_PBE_SHA1_3DES("1.2.840.113549.1.12.1.3");
const OID OID_PBE_SHA1_2DES("1.2.840.113549.1.12.1.4");
const OID OID_PBE_SHA1_RC2_128("1.2.840.113549.1.12.1.5");
const OID OID_PBE_SHA1_RC2_40("1.2.840.113549.1.12.1.6");

/*
* Encode a friendly name as a BMPString (UTF-16BE)
* ASN1_String doesn't support encoding BMPStrings, so we do it manually
*/
void encode_bmpstring(DER_Encoder& enc, std::string_view str) {
   // Convert the string to UTF-16BE
   std::vector<uint8_t> utf16be;
   utf16be.reserve(str.size() * 2);
   for(char c : str) {
      utf16be.push_back(0);  // High byte (ASCII chars have 0 high byte)
      utf16be.push_back(static_cast<uint8_t>(c));  // Low byte
   }
   enc.add_object(ASN1_Type::BmpString, ASN1_Class::Universal, utf16be);
}

/*
* Decrypt data using PKCS#12 PBE or PBES2
*/
secure_vector<uint8_t> pkcs12_pbe_decrypt(std::span<const uint8_t> ciphertext,
                                          std::string_view password,
                                          const AlgorithmIdentifier& pbe_algo) {
   const OID& oid = pbe_algo.oid();

   // Check if it's PBES2 (OID formatted as "PBE-PKCS5v20")
   if(oid.to_formatted_string() == "PBE-PKCS5v20") {
#if defined(BOTAN_HAS_PKCS5_PBES2)
      return pbes2_decrypt(ciphertext, password, pbe_algo.parameters());
#else
      throw Decoding_Error("PBES2 encryption used but PBES2 support not available");
#endif
   }

   // PKCS#12 PBE: Decode parameters (salt and iteration count)
   std::vector<uint8_t> salt;
   size_t iterations = 0;

   BER_Decoder(pbe_algo.parameters()).start_sequence().decode(salt, ASN1_Type::OctetString).decode(iterations).end_cons();

   if(iterations == 0 || iterations > 1000000) {
      throw Decoding_Error("PKCS#12 PBE has invalid iteration count");
   }

   std::string cipher_name;
   size_t key_len = 0;
   size_t iv_len = 8;  // DES/RC2 block size

   if(oid == OID_PBE_SHA1_3DES) {
      cipher_name = "TripleDES/CBC";
      key_len = 24;
   } else if(oid == OID_PBE_SHA1_2DES) {
      cipher_name = "TripleDES/CBC";
      key_len = 16;  // Only 2 keys
#if defined(BOTAN_HAS_RC2)
   } else if(oid == OID_PBE_SHA1_RC2_128) {
      cipher_name = "RC2(128)/CBC";
      key_len = 16;  // 128 bits = 16 bytes
   } else if(oid == OID_PBE_SHA1_RC2_40) {
      cipher_name = "RC2(40)/CBC";
      key_len = 5;  // 40 bits = 5 bytes
#endif
   } else {
      throw Decoding_Error(fmt("Unsupported PKCS#12 PBE algorithm: {}", oid.to_string()));
   }

   // Derive key and IV using PKCS#12 KDF
   secure_vector<uint8_t> key(key_len);
   secure_vector<uint8_t> iv(iv_len);

   pkcs12_kdf(key.data(), key_len, password, salt.data(), salt.size(), iterations, 1);
   pkcs12_kdf(iv.data(), iv_len, password, salt.data(), salt.size(), iterations, 2);

   // For 2-key 3DES, duplicate the first key
   if(oid == OID_PBE_SHA1_2DES) {
      key.resize(24);
      std::copy(key.begin(), key.begin() + 8, key.begin() + 16);
   }

   // Decrypt
   auto cipher = Cipher_Mode::create_or_throw(cipher_name, Cipher_Dir::Decryption);
   cipher->set_key(key);
   cipher->start(iv);

   secure_vector<uint8_t> plaintext(ciphertext.begin(), ciphertext.end());
   cipher->finish(plaintext);

   return plaintext;
}

/*
* Encrypt data using PKCS#12 PBE or PBES2
*/
std::pair<AlgorithmIdentifier, std::vector<uint8_t>> pkcs12_pbe_encrypt(std::span<const uint8_t> plaintext,
                                                                         std::string_view password,
                                                                         std::string_view algo,
                                                                         size_t iterations,
                                                                         RandomNumberGenerator& rng) {
   // Check for PBES2 algorithms
   if(algo == "PBES2-SHA256-AES256" || algo == "PBES2(AES-256/CBC,SHA-256)") {
#if defined(BOTAN_HAS_PKCS5_PBES2)
      return pbes2_encrypt_iter(plaintext, password, iterations, "AES-256/CBC", "SHA-256", rng);
#else
      throw Invalid_Argument("PBES2 requested but PBES2 support not available");
#endif
   }
   if(algo == "PBES2-SHA256-AES128" || algo == "PBES2(AES-128/CBC,SHA-256)") {
#if defined(BOTAN_HAS_PKCS5_PBES2)
      return pbes2_encrypt_iter(plaintext, password, iterations, "AES-128/CBC", "SHA-256", rng);
#else
      throw Invalid_Argument("PBES2 requested but PBES2 support not available");
#endif
   }

   // PKCS#12 PBE algorithms
   OID pbe_oid;
   std::string cipher_name;
   size_t key_len = 0;
   size_t iv_len = 8;

   if(algo == "PBE-SHA1-3DES" || algo.empty()) {
      pbe_oid = OID_PBE_SHA1_3DES;
      cipher_name = "TripleDES/CBC";
      key_len = 24;
   } else if(algo == "PBE-SHA1-2DES") {
      pbe_oid = OID_PBE_SHA1_2DES;
      cipher_name = "TripleDES/CBC";
      key_len = 16;
#if defined(BOTAN_HAS_RC2)
   } else if(algo == "PBE-SHA1-RC2-40") {
      pbe_oid = OID_PBE_SHA1_RC2_40;
      cipher_name = "RC2(40)/CBC";
      key_len = 5;   // 40 bits
   } else if(algo == "PBE-SHA1-RC2-128") {
      pbe_oid = OID_PBE_SHA1_RC2_128;
      cipher_name = "RC2(128)/CBC";
      key_len = 16;  // 128 bits
#endif
   } else {
      throw Invalid_Argument(fmt("Unsupported PKCS#12 PBE algorithm: {}", algo));
   }

   // Generate random salt
   std::vector<uint8_t> salt(8);
   rng.randomize(salt.data(), salt.size());

   // Derive key and IV
   secure_vector<uint8_t> key(key_len);
   secure_vector<uint8_t> iv(iv_len);

   pkcs12_kdf(key.data(), key_len, password, salt.data(), salt.size(), iterations, 1);
   pkcs12_kdf(iv.data(), iv_len, password, salt.data(), salt.size(), iterations, 2);

   // For 2-key 3DES, duplicate the first key
   if(algo == "PBE-SHA1-2DES") {
      key.resize(24);
      std::copy(key.begin(), key.begin() + 8, key.begin() + 16);
   }

   // Encrypt
   auto cipher = Cipher_Mode::create_or_throw(cipher_name, Cipher_Dir::Encryption);
   cipher->set_key(key);
   cipher->start(iv);

   secure_vector<uint8_t> ciphertext(plaintext.begin(), plaintext.end());
   cipher->finish(ciphertext);

   // Encode PBE parameters
   std::vector<uint8_t> params;
   DER_Encoder(params).start_sequence().encode(salt, ASN1_Type::OctetString).encode(iterations).end_cons();

   return {AlgorithmIdentifier(pbe_oid, params), std::vector<uint8_t>(ciphertext.begin(), ciphertext.end())};
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
   std::string oid_str = digest_algo_oid.to_formatted_string();
   if(oid_str == "SHA-1" || digest_algo_oid == OID("1.3.14.3.2.26")) {
      hash_name = "SHA-1";
   } else if(oid_str == "SHA-256" || digest_algo_oid == OID("2.16.840.1.101.3.4.2.1")) {
      hash_name = "SHA-256";
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
      if(attr_oid == OID_PKCS9_FRIENDLY_NAME) {
         ASN1_String str;
         values.decode(str);
         friendly_name = str.value();
      } else if(attr_oid == OID_PKCS9_LOCAL_KEY_ID) {
         values.decode(local_key_id, ASN1_Type::OctetString);
      }
   }
}

/*
* Parse SafeContents (sequence of SafeBag)
*/
void parse_safe_contents(BER_Decoder& decoder,
                         std::string_view password,
                         std::vector<std::shared_ptr<X509_Certificate>>& certs,
                         std::shared_ptr<Private_Key>& key,
                         std::string& friendly_name,
                         std::vector<uint8_t>& local_key_id) {
   while(decoder.more_items()) {
      OID bag_type;
      std::string bag_friendly_name;
      std::vector<uint8_t> bag_key_id;

      BER_Decoder bag_seq = decoder.start_sequence();
      bag_seq.decode(bag_type);

      // bagValue is [0] EXPLICIT
      BER_Decoder bag_value = bag_seq.start_context_specific(0);

      if(bag_type == OID_PKCS12_CERT_BAG) {
         // CertBag
         OID cert_type;
         BER_Decoder cert_bag = bag_value.start_sequence();
         cert_bag.decode(cert_type);

         if(cert_type == OID_PKCS9_X509_CERT) {
            // x509Certificate [0] EXPLICIT OCTET STRING
            std::vector<uint8_t> cert_data;
            BER_Decoder cert_value = cert_bag.start_context_specific(0);
            cert_value.decode(cert_data, ASN1_Type::OctetString);

            auto cert = std::make_shared<X509_Certificate>(cert_data);
            certs.push_back(cert);
         }
      } else if(bag_type == OID_PKCS12_SHROUDED_KEY_BAG) {
         // PKCS8ShroudedKeyBag - encrypted private key
         AlgorithmIdentifier pbe_algo;
         std::vector<uint8_t> encrypted_key;

         BER_Decoder shrouded = bag_value.start_sequence();
         shrouded.decode(pbe_algo);
         shrouded.decode(encrypted_key, ASN1_Type::OctetString);

         // Check if it's PBES2 or PKCS#12 PBE
         if(pbe_algo.oid().to_formatted_string() == "PBE-PKCS5v20" ||
            pbe_algo.oid().to_formatted_string() == "PBES2") {
#if defined(BOTAN_HAS_PKCS5_PBES2)
            auto decrypted = pbes2_decrypt(encrypted_key, password, pbe_algo.parameters());
            DataSource_Memory src(decrypted);
            key = PKCS8::load_key(src);
#else
            throw Decoding_Error("PKCS#12 key uses PBES2 but PBES2 support not available");
#endif
         } else {
            // PKCS#12 native PBE
            auto decrypted = pkcs12_pbe_decrypt(encrypted_key, password, pbe_algo);
            DataSource_Memory src(decrypted);
            key = PKCS8::load_key(src);
         }
      } else if(bag_type == OID_PKCS12_KEY_BAG) {
         // KeyBag - unencrypted private key (rarely used)
         std::vector<uint8_t> key_data;
         bag_value.raw_bytes(key_data);
         DataSource_Memory src(key_data);
         key = PKCS8::load_key(src);
      }

      bag_value.end_cons();

      // Parse attributes
      parse_bag_attributes(bag_seq, bag_friendly_name, bag_key_id);

      if(!bag_friendly_name.empty() && friendly_name.empty()) {
         friendly_name = bag_friendly_name;
      }
      if(!bag_key_id.empty() && local_key_id.empty()) {
         local_key_id = bag_key_id;
      }
   }
}

/*
* Parse AuthenticatedSafe (sequence of ContentInfo)
*/
void parse_authenticated_safe(std::span<const uint8_t> data,
                              std::string_view password,
                              std::vector<std::shared_ptr<X509_Certificate>>& certs,
                              std::shared_ptr<Private_Key>& key,
                              std::string& friendly_name,
                              std::vector<uint8_t>& local_key_id) {
   BER_Decoder auth_safe(data);
   BER_Decoder seq = auth_safe.start_sequence();

   while(seq.more_items()) {
      OID content_type;
      BER_Decoder content_info = seq.start_sequence();
      content_info.decode(content_type);

      if(content_type == OID_PKCS7_DATA) {
         // Unencrypted data: [0] EXPLICIT OCTET STRING containing SafeContents
         std::vector<uint8_t> safe_contents_data;
         BER_Decoder content = content_info.start_context_specific(0);
         content.decode(safe_contents_data, ASN1_Type::OctetString);

         BER_Decoder safe_contents(safe_contents_data);
         BER_Decoder sc_seq = safe_contents.start_sequence();
         parse_safe_contents(sc_seq, password, certs, key, friendly_name, local_key_id);
      } else if(content_type == OID_PKCS7_ENCRYPTED_DATA) {
         // Encrypted data
         BER_Decoder content = content_info.start_context_specific(0);
         BER_Decoder enc_data = content.start_sequence();

         size_t version;
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
         BER_Object enc_content_obj = enc_content_info.get_next_object();
         
         if(enc_content_obj.is_a(0, ASN1_Class::ContextSpecific)) {
            // PRIMITIVE [0] IMPLICIT OCTET STRING - content is the raw bytes
            encrypted_content.assign(enc_content_obj.bits(), enc_content_obj.bits() + enc_content_obj.length());
         } else if(enc_content_obj.is_a(0, ASN1_Class::ContextSpecific | ASN1_Class::Constructed)) {
            // CONSTRUCTED [0] - may contain explicit OCTET STRING or raw bytes
            std::vector<uint8_t> raw_context_content(enc_content_obj.bits(), enc_content_obj.bits() + enc_content_obj.length());
            
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
         secure_vector<uint8_t> decrypted = pkcs12_pbe_decrypt(encrypted_content, password, enc_algo);

         BER_Decoder safe_contents(decrypted);
         BER_Decoder sc_seq = safe_contents.start_sequence();
         parse_safe_contents(sc_seq, password, certs, key, friendly_name, local_key_id);
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
   std::vector<std::shared_ptr<X509_Certificate>> all_certs;

   BER_Decoder pfx(source);
   BER_Decoder pfx_seq = pfx.start_sequence();

   // Version (should be 3)
   size_t version;
   pfx_seq.decode(version);
   if(version != 3) {
      throw Decoding_Error(fmt("Unsupported PKCS#12 version: {}", version));
   }

   // authSafe ContentInfo
   OID auth_safe_type;
   std::vector<uint8_t> auth_safe_content;

   BER_Decoder auth_safe_info = pfx_seq.start_sequence();
   auth_safe_info.decode(auth_safe_type);

   if(auth_safe_type != OID_PKCS7_DATA) {
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

      // Verify MAC
      verify_mac(auth_safe_content, mac_value, mac_salt, iterations, digest_algo.oid(), password);
   }

   // Parse AuthenticatedSafe
   std::shared_ptr<Private_Key> key;
   parse_authenticated_safe(auth_safe_content, password, all_certs, key, result.m_friendly_name, result.m_local_key_id);

   result.m_private_key = key;

   // Separate end-entity cert from CA certs
   // The end-entity cert is typically the one matching the private key
   if(!all_certs.empty()) {
      if(key) {
         // Find cert matching the private key
         for(auto it = all_certs.begin(); it != all_certs.end(); ++it) {
            try {
               // Compare public key fingerprints
               auto cert_pk = (*it)->subject_public_key();
               if(cert_pk && key->public_key_bits() == cert_pk->public_key_bits()) {
                  result.m_certificate = *it;
                  all_certs.erase(it);
                  break;
               }
            } catch(...) {
               // Skip comparison errors
            }
         }
      }

      // If no match found, use the first cert as the end-entity
      if(!result.m_certificate && !all_certs.empty()) {
         result.m_certificate = all_certs.front();
         all_certs.erase(all_certs.begin());
      }

      result.m_ca_certs = all_certs;
   }

   return result;
}

std::vector<uint8_t> PKCS12::create(const Private_Key* key,
                                    const X509_Certificate* cert,
                                    const std::vector<X509_Certificate>& ca_certs,
                                    const PKCS12_Options& options,
                                    RandomNumberGenerator& rng) {
   if(!key && !cert && ca_certs.empty()) {
      throw Invalid_Argument("PKCS#12::create requires at least a key or certificate");
   }

   std::vector<uint8_t> auth_safe_content;
   std::vector<uint8_t> safe_bags;

   // Generate local key ID from certificate (SHA-1 of public key)
   std::vector<uint8_t> local_key_id;
   if(cert) {
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
         cert_bags.encode(OID_PKCS12_CERT_BAG);

         // CertBag [0] EXPLICIT
         cert_bags.start_context_specific(0);
         cert_bags.start_sequence();
         cert_bags.encode(OID_PKCS9_X509_CERT);
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
               cert_bags.encode(OID_PKCS9_FRIENDLY_NAME);
               cert_bags.start_set();
               encode_bmpstring(cert_bags, options.friendly_name);
               cert_bags.end_cons();
               cert_bags.end_cons();
            }
            if(!local_key_id.empty()) {
               cert_bags.start_sequence();
               cert_bags.encode(OID_PKCS9_LOCAL_KEY_ID);
               cert_bags.start_set();
               cert_bags.encode(local_key_id, ASN1_Type::OctetString);
               cert_bags.end_cons();
               cert_bags.end_cons();
            }
            cert_bags.end_cons();
         }

         cert_bags.end_cons();
      };

      if(cert) {
         add_cert_bag(*cert, true);
      }
      for(const auto& ca : ca_certs) {
         add_cert_bag(ca, false);
      }

      cert_bags.end_cons();
   }

   // Create key SafeBag if key is provided
   std::vector<uint8_t> key_safe_contents;
   if(key) {
      DER_Encoder key_bags(key_safe_contents);
      key_bags.start_sequence();
      key_bags.start_sequence();
      key_bags.encode(OID_PKCS12_SHROUDED_KEY_BAG);

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
            key_bags.encode(OID_PKCS9_FRIENDLY_NAME);
            key_bags.start_set();
            encode_bmpstring(key_bags, options.friendly_name);
            key_bags.end_cons();
            key_bags.end_cons();
         }
         if(!local_key_id.empty()) {
            key_bags.start_sequence();
            key_bags.encode(OID_PKCS9_LOCAL_KEY_ID);
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
   if(!cert_safe_contents.empty()) {
      if(!options.cert_encryption_algo.empty() && !options.password.empty()) {
         // Encrypt certificates
         auto [enc_algo, enc_data] =
            pkcs12_pbe_encrypt(cert_safe_contents, options.password, options.cert_encryption_algo, options.iterations, rng);

         auth_safe.start_sequence();
         auth_safe.encode(OID_PKCS7_ENCRYPTED_DATA);
         auth_safe.start_context_specific(0);
         auth_safe.start_sequence();
         auth_safe.encode(size_t(0));  // version
         // EncryptedContentInfo
         auth_safe.start_sequence();
         auth_safe.encode(OID_PKCS7_DATA);
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
         auth_safe.encode(OID_PKCS7_DATA);
         auth_safe.start_context_specific(0);
         auth_safe.encode(cert_safe_contents, ASN1_Type::OctetString);
         auth_safe.end_cons();
         auth_safe.end_cons();
      }
   }

   // Second ContentInfo: private key (always encrypted via PKCS8ShroudedKeyBag)
   if(!key_safe_contents.empty()) {
      auth_safe.start_sequence();
      auth_safe.encode(OID_PKCS7_DATA);
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
   pfx.encode(OID_PKCS7_DATA);
   pfx.start_context_specific(0);
   pfx.encode(auth_safe_content, ASN1_Type::OctetString);
   pfx.end_cons();
   pfx.end_cons();

   // MacData (optional but recommended)
   if(options.include_mac && !options.password.empty()) {
      std::vector<uint8_t> mac_salt(8);
      rng.randomize(mac_salt.data(), mac_salt.size());

      // Derive MAC key
      auto hash = HashFunction::create_or_throw("SHA-1");
      const size_t mac_key_len = hash->output_length();
      secure_vector<uint8_t> mac_key(mac_key_len);
      pkcs12_kdf(mac_key.data(), mac_key_len, options.password, mac_salt.data(), mac_salt.size(), options.iterations, 3);

      // Compute HMAC
      auto hmac = MessageAuthenticationCode::create_or_throw("HMAC(SHA-1)");
      hmac->set_key(mac_key);
      hmac->update(auth_safe_content);
      secure_vector<uint8_t> mac_value = hmac->final();

      // MacData
      pfx.start_sequence();
      // DigestInfo
      pfx.start_sequence();
      pfx.encode(AlgorithmIdentifier(OID("1.3.14.3.2.26"), AlgorithmIdentifier::USE_NULL_PARAM));  // SHA-1
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
