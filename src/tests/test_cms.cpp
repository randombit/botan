/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_CMS)
   #include <botan/ber_dec.h>
   #include <botan/certstor.h>
   #include <botan/cms.h>
   #include <botan/data_src.h>
   #include <botan/der_enc.h>
   #include <botan/pkcs8.h>
   #include <botan/rng.h>
   #include <botan/x509cert.h>
   #include <botan/x509path.h>
   #include <botan/internal/cms_helpers.h>
   #include <botan/internal/fmt.h>
   #include <algorithm>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_CMS)

Botan::X509_Certificate load_test_cert(const std::string& path) {
   Botan::DataSource_Memory src(Test::read_binary_data_file(path));
   return Botan::X509_Certificate(src);
}

Botan::X509_Certificate load_cms_cert(const std::string& name) {
   return load_test_cert("cms/" + name);
}

std::vector<Test::Result> test_cms_oids() {
   return {
      CHECK("CMS OID registrations resolve both directions",
            [](Test::Result& result) {
               const std::vector<std::pair<std::string, std::string>> oids = {
                  {"PKCS7.Data", "1.2.840.113549.1.7.1"},
                  {"PKCS7.SignedData", "1.2.840.113549.1.7.2"},
                  {"PKCS7.EnvelopedData", "1.2.840.113549.1.7.3"},
                  {"CMS.AuthEnvelopedData", "1.2.840.113549.1.9.16.1.23"},
                  {"CMS.KEMRecipientInfo", "1.2.840.113549.1.9.16.13.3"},
                  {"PKCS9.ContentType", "1.2.840.113549.1.9.3"},
                  {"PKCS9.MessageDigest", "1.2.840.113549.1.9.4"},
                  {"PKCS9.SigningTime", "1.2.840.113549.1.9.5"},
                  {"PKCS9.CMSAlgorithmProtection", "1.2.840.113549.1.9.52"},
                  {"HKDF(SHA-256)", "1.2.840.113549.1.9.16.3.28"},
                  {"HKDF(SHA-384)", "1.2.840.113549.1.9.16.3.29"},
                  {"HKDF(SHA-512)", "1.2.840.113549.1.9.16.3.30"},
               };

               for(const auto& [name, oid_str] : oids) {
                  const auto oid = Botan::OID::from_name(name);
                  if(result.test_is_true(name + " resolves", oid.has_value())) {
                     result.test_str_eq(name + " string form", oid->to_string(), oid_str);
                  }
                  result.test_str_eq(oid_str + " name", Botan::OID(oid_str).registered_name().value_or(""), name);
               }
            }),
   };
}

std::vector<Test::Result> test_cms_types() {
   return {
      CHECK("IssuerAndSerialNumber round trip",
            [](Test::Result& result) {
               const auto cert = load_cms_cert("rsa_cert.pem");
               const auto other = load_cms_cert("ecdsa_cert.pem");

               const Botan::CMS::IssuerAndSerialNumber iasn(cert);
               result.test_is_true("matches its cert", iasn.matches(cert));
               result.test_is_false("does not match other cert", iasn.matches(other));
               result.test_is_true("serial number", iasn.serial() == cert.serial());
               result.test_is_true("issuer dn", iasn.issuer() == cert.issuer_dn());

               const auto der = iasn.BER_encode();

               Botan::CMS::IssuerAndSerialNumber decoded;
               Botan::BER_Decoder(der, Botan::BER_Decoder::Limits::DER()).decode(decoded).verify_end();
               result.test_is_true("decoded matches cert", decoded.matches(cert));
               result.test_bin_eq("re-encoding is identical", decoded.BER_encode(), der);
            }),

      CHECK("IssuerAndSerialNumber with a negative serial",
            [](Test::Result& result) {
               // Both certs share an issuer; the serials are -255 and 255
               const auto neg = load_test_cert("x509/serial_numbers/neg255.pem");
               const auto pos = load_test_cert("x509/serial_numbers/pos255.pem");

               const Botan::CMS::IssuerAndSerialNumber iasn(neg);
               result.test_is_true("matches the negative serial cert", iasn.matches(neg));
               result.test_is_false("does not match the positive counterpart", iasn.matches(pos));

               const auto der = iasn.BER_encode();

               Botan::CMS::IssuerAndSerialNumber decoded;
               Botan::BER_Decoder(der, Botan::BER_Decoder::Limits::DER()).decode(decoded).verify_end();
               result.test_is_true("decoded serial is negative", decoded.serial().is_negative());
               result.test_is_true("decoded matches the negative serial cert", decoded.matches(neg));
               result.test_is_false("decoded does not match the positive counterpart", decoded.matches(pos));
               result.test_bin_eq("re-encoding is identical", decoded.BER_encode(), der);
            }),

      CHECK("SignerIdentifier issuerAndSerialNumber alternative",
            [](Test::Result& result) {
               const auto cert = load_cms_cert("rsa_cert.pem");
               const auto other = load_cms_cert("ecdsa_cert.pem");

               const Botan::CMS::SignerIdentifier sid(cert);
               result.test_is_true("uses issuerAndSerialNumber", sid.is_issuer_and_serial());
               result.test_is_true("matches its cert", sid.matches(cert));
               result.test_is_false("does not match other cert", sid.matches(other));

               const auto der = sid.BER_encode();
               Botan::CMS::SignerIdentifier decoded;
               Botan::BER_Decoder(der, Botan::BER_Decoder::Limits::DER()).decode(decoded).verify_end();
               result.test_is_true("decoded matches cert", decoded.matches(cert));
               result.test_bin_eq("re-encoding is identical", decoded.BER_encode(), der);
            }),

      CHECK("SignerIdentifier subjectKeyIdentifier alternative",
            [](Test::Result& result) {
               const auto cert = load_cms_cert("rsa_cert.pem");
               const auto other = load_cms_cert("ecdsa_cert.pem");
               result.require("cert has a subject key id", !cert.subject_key_id().empty());

               std::vector<uint8_t> der;
               Botan::DER_Encoder(der).add_object(
                  Botan::ASN1_Type(0), Botan::ASN1_Class::ContextSpecific, cert.subject_key_id());

               Botan::CMS::SignerIdentifier sid;
               Botan::BER_Decoder(der, Botan::BER_Decoder::Limits::DER()).decode(sid).verify_end();
               result.test_is_false("uses subjectKeyIdentifier", sid.is_issuer_and_serial());
               result.test_bin_eq("skid value", sid.subject_key_id(), cert.subject_key_id());
               result.test_is_true("matches its cert", sid.matches(cert));
               result.test_is_false("does not match other cert", sid.matches(other));
               result.test_bin_eq("re-encoding is identical", sid.BER_encode(), der);
            }),

      CHECK("SignerIdentifier rejects other tags",
            [](Test::Result& result) {
               std::vector<uint8_t> der;
               Botan::DER_Encoder(der).encode(size_t(1));

               Botan::CMS::SignerIdentifier sid;
               result.test_throws<Botan::Decoding_Error>("bad tag rejected", [&]() {
                  Botan::BER_Decoder(der, Botan::BER_Decoder::Limits::DER()).decode(sid);
               });
            }),

      CHECK("CMS signed and authenticated attributes require DER",
            [](Test::Result& result) {
               std::vector<uint8_t> content_type_value;
               Botan::DER_Encoder(content_type_value).encode(Botan::OID::from_string("PKCS7.Data"));
               std::vector<uint8_t> digest_value;
               Botan::DER_Encoder(digest_value).encode(std::vector<uint8_t>{1}, Botan::ASN1_Type::OctetString);

               std::vector<uint8_t> content_type_attr;
               Botan::DER_Encoder(content_type_attr)
                  .encode(Botan::Attribute(Botan::OID::from_string("PKCS9.ContentType"), content_type_value));
               std::vector<uint8_t> digest_attr;
               Botan::DER_Encoder(digest_attr)
                  .encode(Botan::Attribute(Botan::OID::from_string("PKCS9.MessageDigest"), digest_value));

               std::vector<uint8_t> unsorted_attributes;
               unsorted_attributes.insert(
                  unsorted_attributes.end(), content_type_attr.begin(), content_type_attr.end());
               unsorted_attributes.insert(unsorted_attributes.end(), digest_attr.begin(), digest_attr.end());
               std::vector<uint8_t> auth_attrs;
               Botan::DER_Encoder(auth_attrs)
                  .add_object(Botan::ASN1_Type(1),
                              Botan::ASN1_Class::ContextSpecific | Botan::ASN1_Class::Constructed,
                              unsorted_attributes);
               const Botan::BER_Object attrs =
                  Botan::BER_Decoder(auth_attrs, Botan::BER_Decoder::Limits::BER()).get_next_object();

               result.test_throws<Botan::Decoding_Error>("non-DER attribute ordering rejected",
                                                         [&]() { Botan::CMS::attrs_as_set_encoding(attrs); });
            }),

      CHECK("ContentInfo helper round trip",
            [](Test::Result& result) {
               const auto data_oid = Botan::OID::from_string("PKCS7.Data");

               std::vector<uint8_t> inner;
               Botan::DER_Encoder(inner).encode(std::vector<uint8_t>{1, 2, 3}, Botan::ASN1_Type::OctetString);

               const auto ci = Botan::CMS::make_content_info(data_oid, inner);
               const auto [type, content] = Botan::CMS::open_content_info(ci);
               result.test_is_true("content type", type == data_oid);
               result.test_is_true("inner object is an octet string",
                                   content.is_a(Botan::ASN1_Type::OctetString, Botan::ASN1_Class::Universal));

               auto with_trailing = ci;
               with_trailing.push_back(0x00);
               result.test_throws<Botan::Decoding_Error>("trailing data rejected",
                                                         [&]() { Botan::CMS::open_content_info(with_trailing); });
            }),
   };
}

std::vector<Test::Result> test_cms_parse_openssl_shells() {
   return {
      CHECK("EnvelopedData shell from openssl",
            [](Test::Result& result) {
               const auto blob = Test::read_binary_data_file("cms/env_ktri_aes256cbc_pkcs15.der");
               const auto rsa_cert = load_cms_cert("rsa_cert.pem");

               auto [type, content] = Botan::CMS::open_content_info(blob);
               result.test_str_eq("content type", type.to_formatted_string(), "PKCS7.EnvelopedData");
               result.require("content is a sequence",
                              content.is_a(Botan::ASN1_Type::Sequence, Botan::ASN1_Class::Constructed));

               Botan::BER_Decoder env(std::move(content), Botan::BER_Decoder::Limits::DER());
               size_t version = 0;
               env.decode(version);
               result.test_sz_eq("EnvelopedData version", version, 0);

               Botan::BER_Decoder ris = env.start_set();
               Botan::BER_Decoder ri = ris.start_sequence();
               size_t ri_version = 0;
               ri.decode(ri_version);
               result.test_sz_eq("ktri version", ri_version, 0);

               Botan::CMS::SignerIdentifier rid;
               ri.decode(rid);
               result.test_is_true("rid matches recipient cert", rid.matches(rsa_cert));
               ri.discard_remaining();
            }),

      CHECK("SignedData shell from openssl",
            [](Test::Result& result) {
               const auto blob = Test::read_binary_data_file("cms/signed_rsa_attached.der");
               const auto rsa_cert = load_cms_cert("rsa_cert.pem");

               auto [type, content] = Botan::CMS::open_content_info(blob);
               result.test_str_eq("content type", type.to_formatted_string(), "PKCS7.SignedData");

               Botan::BER_Decoder sd(std::move(content), Botan::BER_Decoder::Limits::DER());
               size_t version = 0;
               sd.decode(version);
               result.test_sz_eq("SignedData version", version, 1);

               std::vector<Botan::AlgorithmIdentifier> digest_algos;
               sd.decode_list(digest_algos, Botan::ASN1_Type::Set, Botan::ASN1_Class::Universal);
               result.test_sz_eq("one digest algorithm", digest_algos.size(), 1);
               result.test_str_eq("digest algorithm", digest_algos[0].oid().registered_name().value_or(""), "SHA-256");

               Botan::BER_Decoder eci = sd.start_sequence();
               Botan::OID econtent_type;
               eci.decode(econtent_type);
               result.test_str_eq("eContentType", econtent_type.to_formatted_string(), "PKCS7.Data");
               eci.discard_remaining();
               eci.end_cons();

               // certificates [0] IMPLICIT
               const Botan::BER_Object certs = sd.get_next_object();
               result.test_is_true(
                  "certificates present",
                  certs.is_a(Botan::ASN1_Type(0), Botan::ASN1_Class::ContextSpecific | Botan::ASN1_Class::Constructed));

               Botan::BER_Decoder sis = sd.start_set();
               Botan::BER_Decoder si = sis.start_sequence();
               size_t si_version = 0;
               si.decode(si_version);
               result.test_sz_eq("SignerInfo version", si_version, 1);

               Botan::CMS::SignerIdentifier sid;
               si.decode(sid);
               result.test_is_true("sid matches signer cert", sid.matches(rsa_cert));
               si.discard_remaining();
            }),
   };
}

std::unique_ptr<Botan::Private_Key> load_cms_key(const std::string& name) {
   Botan::DataSource_Memory src(Test::read_binary_data_file("cms/" + name));
   return Botan::PKCS8::load_key(src);
}

std::vector<uint8_t> cms_fixture_message() {
   return Test::read_binary_data_file("cms/message.bin");
}

// Flip one bit inside the value of the first TLV whose header announces
// a primitive of the given tag and length
std::vector<uint8_t> tamper_first_tlv(const std::vector<uint8_t>& der, uint8_t tag, size_t value_len) {
   std::vector<uint8_t> header{tag};
   if(value_len < 128) {
      header.push_back(static_cast<uint8_t>(value_len));
   } else if(value_len < 256) {
      header.push_back(0x81);
      header.push_back(static_cast<uint8_t>(value_len));
   } else {
      header.push_back(0x82);
      header.push_back(static_cast<uint8_t>(value_len >> 8));
      header.push_back(static_cast<uint8_t>(value_len & 0xFF));
   }

   const auto found = std::search(der.begin(), der.end(), header.begin(), header.end());
   if(found == der.end()) {
      throw Test_Error("tamper_first_tlv could not locate the requested TLV");
   }

   std::vector<uint8_t> tampered = der;
   tampered[static_cast<size_t>(found - der.begin()) + header.size()] ^= 0x01;
   return tampered;
}

std::vector<Test::Result> test_cms_enveloped_openssl_decrypt() {
   std::vector<Test::Result> results;

   const auto expected = cms_fixture_message();

   struct Fixture {
         std::string file;
         std::string cert;
         std::string key;
   };

   const std::vector<Fixture> fixtures = {
      {"env_ktri_aes128cbc_pkcs15.der", "rsa_cert.pem", "rsa_key.pem"},
      {"env_ktri_aes256cbc_pkcs15.der", "rsa_cert.pem", "rsa_key.pem"},
      {"env_ktri_aes256cbc_oaep_sha1.der", "rsa_cert.pem", "rsa_key.pem"},
      {"env_ktri_aes256cbc_oaep_sha256.der", "rsa_cert.pem", "rsa_key.pem"},
      {"env_kari_ktri_aes256cbc.der", "rsa_cert.pem", "rsa_key.pem"},
      {"aenv_ktri_aes128gcm.der", "rsa_cert.pem", "rsa_key.pem"},
      {"aenv_ktri_aes256gcm.der", "rsa_cert.pem", "rsa_key.pem"},
      {"aenv_kemri_mlkem768_aes256gcm.der", "mlkem_cert.pem", "mlkem_key.pem"},
      {"env_kemri_mlkem768_aes256cbc.der", "mlkem_cert.pem", "mlkem_key.pem"},
      // Streaming BER: indefinite lengths and constructed OCTET STRING content
      {"env_ktri_aes256cbc_streamed.der", "rsa_cert.pem", "rsa_key.pem"},
      {"aenv_ktri_aes256gcm_streamed.der", "rsa_cert.pem", "rsa_key.pem"},
   };

   results.reserve(fixtures.size());
   for(const auto& fixture : fixtures) {
      results.push_back(CHECK(fixture.file.c_str(), [&](Test::Result& result) {
         auto rng = Test::new_rng(fixture.file);
         const auto blob = Test::read_binary_data_file("cms/" + fixture.file);
         const auto cert = load_cms_cert(fixture.cert);
         const auto key = load_cms_key(fixture.key);

         const auto ptext = Botan::CMS::decrypt(blob, *key, cert, *rng);
         result.test_bin_eq("decrypted openssl fixture", ptext, expected);
      }));
   }

   return results;
}

std::vector<Test::Result> test_cms_enveloped_roundtrip() {
   std::vector<Test::Result> results;

   const std::vector<uint8_t> message = {'r', 'o', 'u', 'n', 'd', ' ', 't', 'r', 'i', 'p', '!'};

   const std::vector<std::string> paddings = {"OAEP(SHA-256)", "PKCS1v15"};
   const std::vector<std::string> cbc_algos = {"AES-128/CBC", "AES-256/CBC"};

   for(const auto& padding : paddings) {
      for(const auto& algo : cbc_algos) {
         const std::string name = Botan::fmt("EnvelopedData round trip {} {}", padding, algo);
         results.push_back(CHECK(name.c_str(), [&](Test::Result& result) {
            auto rng = Test::new_rng(name);
            const auto cert = load_cms_cert("rsa_cert.pem");
            const auto key = load_cms_key("rsa_key.pem");

            Botan::CMS::Enveloped_Data_Builder builder;
            builder.add_ktri_recipient(cert, padding).set_content_encryption(algo);
            const auto ci = builder.build(message, *rng);

            const auto ptext = Botan::CMS::decrypt(ci, *key, cert, *rng);
            result.test_bin_eq("round trip", ptext, message);
         }));
      }
   }

   for(const std::string algo : {"AES-128/GCM", "AES-256/GCM"}) {
      const std::string name = "AuthEnvelopedData round trip " + algo;
      results.push_back(CHECK(name.c_str(), [&](Test::Result& result) {
         auto rng = Test::new_rng(name);
         const auto cert = load_cms_cert("rsa_cert.pem");
         const auto key = load_cms_key("rsa_key.pem");

         Botan::CMS::Enveloped_Data_Builder builder;
         builder.add_ktri_recipient(cert).set_content_encryption(algo);
         const auto ci = builder.build(message, *rng);

         const auto [type, content] = Botan::CMS::open_content_info(ci);
         result.test_str_eq("content type", type.to_formatted_string(), "CMS.AuthEnvelopedData");

         const auto ptext = Botan::CMS::decrypt(ci, *key, cert, *rng);
         result.test_bin_eq("round trip", ptext, message);
      }));
   }

   results.push_back(CHECK("KEM recipient round trips", [&](Test::Result& result) {
      auto rng = Test::new_rng("cms kemri round trip");
      const auto cert = load_cms_cert("mlkem_cert.pem");
      const auto key = load_cms_key("mlkem_key.pem");

      for(const std::string algo : {"AES-256/GCM", "AES-256/CBC"}) {
         Botan::CMS::Enveloped_Data_Builder builder;
         builder.add_kem_recipient(cert).set_content_encryption(algo);
         const auto ci = builder.build(message, *rng);

         const auto ptext = Botan::CMS::decrypt(ci, *key, cert, *rng);
         result.test_bin_eq("round trip " + algo, ptext, message);
      }
   }));

   results.push_back(CHECK("Multiple recipients", [&](Test::Result& result) {
      auto rng = Test::new_rng("cms multi recipient");
      const auto rsa_cert = load_cms_cert("rsa_cert.pem");
      const auto rsa_key = load_cms_key("rsa_key.pem");
      const auto kem_cert = load_cms_cert("mlkem_cert.pem");
      const auto kem_key = load_cms_key("mlkem_key.pem");

      Botan::CMS::Enveloped_Data_Builder builder;
      builder.add_ktri_recipient(rsa_cert).add_kem_recipient(kem_cert);
      const auto ci = builder.build(message, *rng);

      result.test_bin_eq("rsa recipient", Botan::CMS::decrypt(ci, *rsa_key, rsa_cert, *rng), message);
      result.test_bin_eq("kem recipient", Botan::CMS::decrypt(ci, *kem_key, kem_cert, *rng), message);
   }));

   results.push_back(CHECK("Builder input validation", [&](Test::Result& result) {
      const auto ecdsa_cert = load_cms_cert("ecdsa_cert.pem");

      Botan::CMS::Enveloped_Data_Builder builder;
      result.test_throws<Botan::Invalid_Argument>("unsupported cipher",
                                                  [&]() { builder.set_content_encryption("Serpent/CBC"); });
      result.test_throws<Botan::Invalid_Argument>(
         "unsupported padding", [&]() { builder.add_ktri_recipient(load_cms_cert("rsa_cert.pem"), "PSS"); });
      result.test_throws<Botan::Invalid_Argument>("non-RSA ktri cert",
                                                  [&]() { builder.add_ktri_recipient(ecdsa_cert); });

      auto rng = Test::new_rng("cms builder validation");
      result.test_throws<Botan::Invalid_State>("no recipients", [&]() {
         const Botan::CMS::Enveloped_Data_Builder empty;
         empty.build(std::vector<uint8_t>{1, 2, 3}, *rng);
      });
   }));

   return results;
}

std::vector<Test::Result> test_cms_enveloped_negative() {
   return {
      CHECK("EnvelopedData version must match its recipients",
            [](Test::Result& result) {
               auto rng = Test::new_rng("cms invalid enveloped version");
               const auto cert = load_cms_cert("rsa_cert.pem");
               const auto key = load_cms_key("rsa_key.pem");
               Botan::CMS::Enveloped_Data_Builder builder;
               builder.add_ktri_recipient(cert).set_content_encryption("AES-256/CBC");
               auto blob = builder.build(std::vector<uint8_t>{1, 2, 3}, *rng);

               const std::vector<uint8_t> version_zero = {0x02, 0x01, 0x00};
               const auto found = std::search(blob.begin(), blob.end(), version_zero.begin(), version_zero.end());
               result.require("top-level version found", found != blob.end());
               blob[static_cast<size_t>(found - blob.begin()) + 2] = 2;
               result.test_throws<Botan::Decoding_Error>("inconsistent version rejected",
                                                         [&]() { Botan::CMS::decrypt(blob, *key, cert, *rng); });
            }),

      CHECK("EncryptedContentInfo accepts only id-data",
            [](Test::Result& result) {
               auto rng = Test::new_rng("cms wrong encrypted content type");
               const auto cert = load_cms_cert("rsa_cert.pem");
               const auto key = load_cms_key("rsa_key.pem");
               Botan::CMS::Enveloped_Data_Builder builder;
               builder.add_ktri_recipient(cert).set_content_encryption("AES-256/CBC");
               auto blob = builder.build(std::vector<uint8_t>{1, 2, 3}, *rng);

               const std::vector<uint8_t> data_oid = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01};
               const auto found = std::search(blob.begin(), blob.end(), data_oid.begin(), data_oid.end());
               result.require("EncryptedContentInfo type found", found != blob.end());
               *(found + data_oid.size() - 1) = 0x02;
               result.test_throws<Botan::Decoding_Error>("non-id-data rejected",
                                                         [&]() { Botan::CMS::decrypt(blob, *key, cert, *rng); });
            }),

      CHECK("No matching recipient",
            [](Test::Result& result) {
               auto rng = Test::new_rng("cms no recipient");
               const auto blob = Test::read_binary_data_file("cms/env_ktri_aes256cbc_pkcs15.der");
               const auto cert = load_cms_cert("ecdsa_cert.pem");
               const auto key = load_cms_key("ecdsa_key.pem");

               result.test_throws<Botan::Invalid_Argument>("no match throws",
                                                           [&]() { Botan::CMS::decrypt(blob, *key, cert, *rng); });
            }),

      CHECK("Unsupported kari recipient is skipped",
            [](Test::Result& result) {
               auto rng = Test::new_rng("cms kari skip");
               const auto blob = Test::read_binary_data_file("cms/env_kari_ktri_aes256cbc.der");
               const auto cert = load_cms_cert("ecdh_cert.pem");
               const auto key = load_cms_key("ecdh_key.pem");

               // The kari entry does identify this cert, but kari is
               // unsupported and skipped, so no recipient matches
               result.test_throws<Botan::Invalid_Argument>("kari skipped",
                                                           [&]() { Botan::CMS::decrypt(blob, *key, cert, *rng); });
            }),

      CHECK("Tampered encryptedKey",
            [](Test::Result& result) {
               auto rng = Test::new_rng("cms tampered key");
               const auto blob = Test::read_binary_data_file("cms/env_ktri_aes256cbc_pkcs15.der");
               const auto cert = load_cms_cert("rsa_cert.pem");
               const auto key = load_cms_key("rsa_key.pem");

               // The RSA-2048 encryptedKey is the only 256 byte OCTET STRING
               const auto tampered = tamper_first_tlv(blob, 0x04, 256);
               result.test_throws<Botan::CMS::Decryption_Error>(
                  "tampered encryptedKey", [&]() { Botan::CMS::decrypt(tampered, *key, cert, *rng); });
            }),

      CHECK("Tampered CBC ciphertext",
            [](Test::Result& result) {
               auto rng = Test::new_rng("cms tampered ctext");
               auto blob = Test::read_binary_data_file("cms/env_ktri_aes256cbc_pkcs15.der");
               const auto cert = load_cms_cert("rsa_cert.pem");
               const auto key = load_cms_key("rsa_key.pem");

               // The encryptedContent is the final element of EnvelopedData
               blob.back() ^= 0x01;
               result.test_throws<Botan::CMS::Decryption_Error>("tampered ciphertext",
                                                                [&]() { Botan::CMS::decrypt(blob, *key, cert, *rng); });
            }),

      CHECK("Tampered GCM mac",
            [](Test::Result& result) {
               auto rng = Test::new_rng("cms tampered mac");
               auto blob = Test::read_binary_data_file("cms/aenv_ktri_aes256gcm.der");
               const auto cert = load_cms_cert("rsa_cert.pem");
               const auto key = load_cms_key("rsa_key.pem");

               // The mac is the final element of AuthEnvelopedData
               blob.back() ^= 0x01;
               result.test_throws<Botan::CMS::Decryption_Error>("tampered mac",
                                                                [&]() { Botan::CMS::decrypt(blob, *key, cert, *rng); });
            }),

      CHECK("Tampered KEM ciphertext",
            [](Test::Result& result) {
               auto rng = Test::new_rng("cms tampered kemct");
               const auto blob = Test::read_binary_data_file("cms/aenv_kemri_mlkem768_aes256gcm.der");
               const auto cert = load_cms_cert("mlkem_cert.pem");
               const auto key = load_cms_key("mlkem_key.pem");

               // The ML-KEM-768 kemct is the only 1088 byte OCTET STRING
               const auto tampered = tamper_first_tlv(blob, 0x04, 1088);
               result.test_throws<Botan::CMS::Decryption_Error>(
                  "tampered kemct", [&]() { Botan::CMS::decrypt(tampered, *key, cert, *rng); });
            }),

      CHECK("Truncated input",
            [](Test::Result& result) {
               auto rng = Test::new_rng("cms truncated");
               auto blob = Test::read_binary_data_file("cms/env_ktri_aes256cbc_pkcs15.der");
               const auto cert = load_cms_cert("rsa_cert.pem");
               const auto key = load_cms_key("rsa_key.pem");

               blob.resize(blob.size() - 1);
               result.test_throws<Botan::Decoding_Error>("truncated input",
                                                         [&]() { Botan::CMS::decrypt(blob, *key, cert, *rng); });
            }),

      CHECK("SignedData input rejected",
            [](Test::Result& result) {
               auto rng = Test::new_rng("cms wrong type");
               const auto blob = Test::read_binary_data_file("cms/signed_rsa_attached.der");
               const auto cert = load_cms_cert("rsa_cert.pem");
               const auto key = load_cms_key("rsa_key.pem");

               result.test_throws<Botan::Decoding_Error>("wrong content type",
                                                         [&]() { Botan::CMS::decrypt(blob, *key, cert, *rng); });
            }),
   };
}

std::vector<Test::Result> test_cms_signed_openssl_verify() {
   std::vector<Test::Result> results;

   const auto expected = cms_fixture_message();
   const auto now = std::chrono::system_clock::now();

   struct Fixture {
         std::string file;
         std::string cert;
   };

   const std::vector<Fixture> attached = {
      {"signed_rsa_attached.der", "rsa_cert.pem"},
      {"signed_rsa_attached_noattr.der", "rsa_cert.pem"},
      {"signed_ecdsa_attached.der", "ecdsa_cert.pem"},
      // As signed_ecdsa_attached.der, with NULL digest parameters added via der2ascii/ascii2der
      {"signed_ecdsa_nullparam_attached.der", "ecdsa_cert.pem"},
      {"signed_ecdsa_attached_noattr.der", "ecdsa_cert.pem"},
      {"signed_ed25519_attached.der", "ed25519_cert.pem"},
      {"signed_mldsa_attached.der", "mldsa_cert.pem"},
      {"signed_rsa_chain_attached.der", "rsa_cert.pem"},
      // Streaming BER: indefinite lengths and constructed OCTET STRING content
      {"signed_rsa_attached_streamed.der", "rsa_cert.pem"},
   };

   const std::vector<Fixture> detached = {
      {"signed_rsa_detached.der", "rsa_cert.pem"},
      {"signed_ecdsa_detached.der", "ecdsa_cert.pem"},
      {"signed_ed25519_detached.der", "ed25519_cert.pem"},
      {"signed_mldsa_detached.der", "mldsa_cert.pem"},
   };

   results.reserve(attached.size() + detached.size());

   for(const auto& fixture : attached) {
      results.push_back(CHECK(fixture.file.c_str(), [&](Test::Result& result) {
         const auto blob = Test::read_binary_data_file("cms/" + fixture.file);
         const auto signer_cert = load_cms_cert(fixture.cert);

         const auto verified = Botan::CMS::verify(blob, std::nullopt, nullptr, now);
         result.test_bin_eq("content", verified.content(), expected);
         result.test_sz_eq("one signer", verified.signers().size(), 1);
         result.test_is_true("signer cert", verified.signers().at(0) == signer_cert);
         result.test_is_false("no path result without roots", verified.path_result().has_value());
      }));
   }

   for(const auto& fixture : detached) {
      results.push_back(CHECK(fixture.file.c_str(), [&](Test::Result& result) {
         const auto blob = Test::read_binary_data_file("cms/" + fixture.file);
         const auto signer_cert = load_cms_cert(fixture.cert);

         const auto verified = Botan::CMS::verify(blob, expected, nullptr, now);
         result.test_is_false("no content returned", verified.has_content());
         result.test_sz_eq("one signer", verified.signers().size(), 1);
         result.test_is_true("signer cert", verified.signers().at(0) == signer_cert);
      }));
   }

   results.push_back(CHECK("Path validation against the test CA", [&](Test::Result& result) {
      const auto blob = Test::read_binary_data_file("cms/signed_rsa_chain_attached.der");

      Botan::Certificate_Store_In_Memory roots;
      roots.add_certificate(load_cms_cert("ca_cert.pem"));

      const auto verified = Botan::CMS::verify(blob, std::nullopt, &roots, now);
      result.require("path result present", verified.path_result().has_value());
      result.test_is_true("path validation succeeded", verified.path_result()->successful_validation());

      // An empty store means no path can be built
      Botan::Certificate_Store_In_Memory empty;
      const auto unverified = Botan::CMS::verify(blob, std::nullopt, &empty, now);
      result.require("path result present", unverified.path_result().has_value());
      result.test_is_false("path validation failed", unverified.path_result()->successful_validation());
   }));

   return results;
}

std::vector<Test::Result> test_cms_signed_negative() {
   const auto now = std::chrono::system_clock::now();

   return {
      CHECK("Tampered content",
            [&](Test::Result& result) {
               auto blob = Test::read_binary_data_file("cms/signed_rsa_attached.der");
               const auto message = cms_fixture_message();

               // Locate the eContent by searching for the message bytes
               const auto found = std::search(blob.begin(), blob.end(), message.begin(), message.end());
               result.require("content found in message", found != blob.end());
               *found ^= 0x01;

               result.test_throws<Botan::CMS::Verification_Error>(
                  "tampered content", [&]() { Botan::CMS::verify(blob, std::nullopt, nullptr, now); });
            }),

      CHECK("Tampered content without signedAttrs",
            [&](Test::Result& result) {
               auto blob = Test::read_binary_data_file("cms/signed_rsa_attached_noattr.der");
               const auto message = cms_fixture_message();

               const auto found = std::search(blob.begin(), blob.end(), message.begin(), message.end());
               result.require("content found in message", found != blob.end());
               *found ^= 0x01;

               result.test_throws<Botan::CMS::Verification_Error>(
                  "tampered content", [&]() { Botan::CMS::verify(blob, std::nullopt, nullptr, now); });
            }),

      CHECK("Tampered signature",
            [&](Test::Result& result) {
               auto blob = Test::read_binary_data_file("cms/signed_rsa_attached.der");

               // The signature is the final element of the final SignerInfo
               blob.back() ^= 0x01;
               result.test_throws<Botan::CMS::Verification_Error>(
                  "tampered signature", [&]() { Botan::CMS::verify(blob, std::nullopt, nullptr, now); });
            }),

      CHECK("Detached content mismatch",
            [&](Test::Result& result) {
               const auto blob = Test::read_binary_data_file("cms/signed_rsa_detached.der");
               const std::vector<uint8_t> wrong = {'w', 'r', 'o', 'n', 'g'};

               result.test_throws<Botan::CMS::Verification_Error>(
                  "wrong detached content", [&]() { Botan::CMS::verify(blob, wrong, nullptr, now); });
            }),

      CHECK("Digest algorithm outside the allowlist",
            [&](Test::Result& result) {
               const auto blob = Test::read_binary_data_file("cms/signed_rsa_sha1_attached.der");

               result.test_throws<Botan::Decoding_Error>(
                  "sha1 rejected", [&]() { Botan::CMS::verify(blob, std::nullopt, nullptr, now); });
            }),

      CHECK(
         "Digest algorithm must match the signature algorithm",
         [&](Test::Result& result) {
            // The signature algorithm is ecdsa-with-SHA256, so changing the
            // SignerInfo digestAlgorithm to SHA-384 makes them inconsistent
            auto blob = Test::read_binary_data_file("cms/signed_ecdsa_attached.der");
            const std::vector<uint8_t> sha256_oid = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};
            std::vector<size_t> offsets;
            for(auto search_position = blob.begin(); search_position != blob.end();) {
               const auto found = std::search(search_position, blob.end(), sha256_oid.begin(), sha256_oid.end());
               if(found == blob.end()) {
                  break;
               }
               offsets.push_back(static_cast<size_t>(found - blob.begin()));
               search_position = found + sha256_oid.size();
            }
            // The first match is in digestAlgorithms, the second is the SignerInfo digestAlgorithm
            result.require("digest algorithm identifiers found", offsets.size() >= 2);
            blob[offsets[1] + sha256_oid.size() - 1] = 0x02;

            result.test_throws<Botan::Decoding_Error>(
               "mismatched hash rejected",
               "CMS SignerInfo digest algorithm is incompatible with signature algorithm",
               [&]() { Botan::CMS::verify(blob, std::nullopt, nullptr, now); });
         }),

      CHECK("SignedData version must match SignerInfo versions",
            [&](Test::Result& result) {
               auto blob = Test::read_binary_data_file("cms/signed_rsa_attached.der");
               const std::vector<uint8_t> version_one = {0x02, 0x01, 0x01};
               const auto found = std::search(blob.begin(), blob.end(), version_one.begin(), version_one.end());
               result.require("top-level version found", found != blob.end());
               blob[static_cast<size_t>(found - blob.begin()) + 2] = 3;

               result.test_throws<Botan::Decoding_Error>(
                  "inconsistent version rejected", [&]() { Botan::CMS::verify(blob, std::nullopt, nullptr, now); });
            }),

      CHECK("Attached/detached argument mismatch",
            [&](Test::Result& result) {
               const auto attached = Test::read_binary_data_file("cms/signed_rsa_attached.der");
               const auto detached = Test::read_binary_data_file("cms/signed_rsa_detached.der");
               const auto message = cms_fixture_message();

               result.test_throws<Botan::Invalid_Argument>(
                  "attached with detached content", [&]() { Botan::CMS::verify(attached, message, nullptr, now); });
               result.test_throws<Botan::Invalid_Argument>(
                  "detached without content", [&]() { Botan::CMS::verify(detached, std::nullopt, nullptr, now); });
            }),

      CHECK("EnvelopedData input rejected",
            [&](Test::Result& result) {
               const auto blob = Test::read_binary_data_file("cms/env_ktri_aes256cbc_pkcs15.der");

               result.test_throws<Botan::Decoding_Error>(
                  "wrong content type", [&]() { Botan::CMS::verify(blob, std::nullopt, nullptr, now); });
            }),
   };
}

std::vector<Test::Result> test_cms_signed_roundtrip() {
   std::vector<Test::Result> results;

   const std::vector<uint8_t> message = {'s', 'i', 'g', 'n', ' ', 'm', 'e'};
   const auto now = std::chrono::system_clock::now();

   struct Signer {
         std::string name;
         std::string hash_fn;
   };

   const std::vector<Signer> signers = {
      {"rsa", "SHA-256"},
      {"ecdsa", "SHA-256"},
      {"ecdsa", "SHA-384"},
      {"ed25519", "SHA-256"},  // the hash choice is ignored for Ed25519
      {"mldsa", "SHA-512"},
   };

   for(const auto& signer : signers) {
      const std::string test_name = Botan::fmt("SignedData round trip {} {}", signer.name, signer.hash_fn);
      results.push_back(CHECK(test_name.c_str(), [&](Test::Result& result) {
         auto rng = Test::new_rng(test_name);
         const auto cert = load_cms_cert(signer.name + "_cert.pem");
         const auto key = load_cms_key(signer.name + "_key.pem");

         for(const bool detached : {false, true}) {
            Botan::CMS::Signed_Data_Builder builder;
            builder.add_signer(cert, *key, signer.hash_fn).detached(detached);
            const auto ci = builder.sign(message, *rng);

            const auto detached_arg = detached ? std::optional<std::span<const uint8_t>>(message) : std::nullopt;
            const auto verified = Botan::CMS::verify(ci, detached_arg, nullptr, now);
            result.test_sz_eq("one signer", verified.signers().size(), 1);
            result.test_is_true("signer cert", verified.signers().at(0) == cert);
            if(!detached) {
               result.test_bin_eq("content", verified.content(), message);
            }
         }
      }));
   }

   results.push_back(CHECK("Two signers with sorted SETs", [&](Test::Result& result) {
      auto rng = Test::new_rng("cms two signers");
      const auto rsa_cert = load_cms_cert("rsa_cert.pem");
      const auto rsa_key = load_cms_key("rsa_key.pem");
      const auto ecdsa_cert = load_cms_cert("ecdsa_cert.pem");
      const auto ecdsa_key = load_cms_key("ecdsa_key.pem");

      Botan::CMS::Signed_Data_Builder builder;
      builder.add_signer(rsa_cert, *rsa_key).add_signer(ecdsa_cert, *ecdsa_key, "SHA-384");
      const auto ci = builder.sign(message, *rng);

      // Decoding in DER mode enforces that the signerInfos SET, the
      // digestAlgorithms SET and each signedAttrs SET are sorted
      const auto verified = Botan::CMS::verify(ci, std::nullopt, nullptr, now);
      result.test_sz_eq("two signers", verified.signers().size(), 2);
   }));

   results.push_back(CHECK("Path validation of a Botan-signed message", [&](Test::Result& result) {
      auto rng = Test::new_rng("cms sign path validate");
      const auto cert = load_cms_cert("ecdsa_cert.pem");
      const auto key = load_cms_key("ecdsa_key.pem");
      const auto ca = load_cms_cert("ca_cert.pem");

      Botan::CMS::Signed_Data_Builder builder;
      builder.add_signer(cert, *key).include_certificate(ca);
      const auto ci = builder.sign(message, *rng);

      Botan::Certificate_Store_In_Memory roots;
      roots.add_certificate(ca);

      const auto verified = Botan::CMS::verify(ci, std::nullopt, &roots, now);
      result.require("path result present", verified.path_result().has_value());
      result.test_is_true("path validation succeeded", verified.path_result()->successful_validation());
   }));

   results.push_back(CHECK("Builder without signers", [&](Test::Result& result) {
      auto rng = Test::new_rng("cms no signers");
      Botan::CMS::Signed_Data_Builder builder;
      result.test_throws<Botan::Invalid_State>("no signers", [&]() { builder.sign(message, *rng); });
   }));

   results.push_back(CHECK("Empty attached content is distinguished from detached", [&](Test::Result& result) {
      auto rng = Test::new_rng("cms empty content");
      const auto cert = load_cms_cert("rsa_cert.pem");
      const auto key = load_cms_key("rsa_key.pem");
      const std::vector<uint8_t> empty;

      Botan::CMS::Signed_Data_Builder builder;
      builder.add_signer(cert, *key);
      const auto attached = Botan::CMS::verify(builder.sign(empty, *rng), std::nullopt, nullptr, now);
      result.test_is_true("attached message has content", attached.has_content());
      result.test_sz_eq("attached content is empty", attached.content().size(), 0);

      builder.detached(true);
      const auto detached = Botan::CMS::verify(builder.sign(empty, *rng), empty, nullptr, now);
      result.test_is_false("detached message has no content", detached.has_content());
      result.test_throws<Botan::Invalid_State>("content() requires has_content()", [&]() { detached.content(); });
   }));

   results.push_back(CHECK("Builder rejects unsupported signature digest", [&](Test::Result& result) {
      auto rng = Test::new_rng("cms unsupported signature digest");
      const auto cert = load_cms_cert("rsa_cert.pem");
      const auto key = load_cms_key("rsa_key.pem");
      Botan::CMS::Signed_Data_Builder builder;
      builder.add_signer(cert, *key, "SHA-1");
      result.test_throws<Botan::Invalid_Argument>("sha1 rejected", [&]() { builder.sign(message, *rng); });
   }));

   return results;
}

BOTAN_REGISTER_TEST_FN("cms", "cms_oids", test_cms_oids);
BOTAN_REGISTER_TEST_FN("cms", "cms_types", test_cms_types);
BOTAN_REGISTER_TEST_FN("cms", "cms_parse_shells", test_cms_parse_openssl_shells);
BOTAN_REGISTER_TEST_FN("cms", "cms_enveloped_openssl", test_cms_enveloped_openssl_decrypt);
BOTAN_REGISTER_TEST_FN("cms", "cms_enveloped_roundtrip", test_cms_enveloped_roundtrip);
BOTAN_REGISTER_TEST_FN("cms", "cms_enveloped_negative", test_cms_enveloped_negative);
BOTAN_REGISTER_TEST_FN("cms", "cms_signed_openssl", test_cms_signed_openssl_verify);
BOTAN_REGISTER_TEST_FN("cms", "cms_signed_negative", test_cms_signed_negative);
BOTAN_REGISTER_TEST_FN("cms", "cms_signed_roundtrip", test_cms_signed_roundtrip);

#endif

}  // namespace

}  // namespace Botan_Tests
