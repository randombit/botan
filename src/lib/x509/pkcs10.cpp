/*
* PKCS #10
* (C) 1999-2007,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pkcs10.h>

#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/pem.h>
#include <botan/pubkey.h>
#include <botan/x509_ext.h>
#include <botan/x509_key.h>
#include <botan/x509cert.h>

namespace Botan {

struct PKCS10_Data {
      X509_DN m_subject_dn;
      std::vector<uint8_t> m_public_key_bits;
      AlternativeName m_alt_name;
      std::string m_challenge;
      Extensions m_extensions;
};

std::string PKCS10_Request::PEM_label() const {
   return "CERTIFICATE REQUEST";
}

std::vector<std::string> PKCS10_Request::alternate_PEM_labels() const {
   return {"NEW CERTIFICATE REQUEST"};
}

PKCS10_Request::PKCS10_Request(DataSource& src) {
   load_data(src);
}

PKCS10_Request::PKCS10_Request(const std::vector<uint8_t>& vec) {
   DataSource_Memory src(vec.data(), vec.size());
   load_data(src);
}

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
PKCS10_Request::PKCS10_Request(std::string_view fsname) {
   DataSource_Stream src(fsname, true);
   load_data(src);
}
#endif

//static
PKCS10_Request PKCS10_Request::create(const Private_Key& key,
                                      const X509_DN& subject_dn,
                                      const Extensions& extensions,
                                      std::string_view hash_fn,
                                      RandomNumberGenerator& rng,
                                      std::string_view padding_scheme,
                                      std::string_view challenge) {
   auto signer = choose_sig_format(key, rng, hash_fn, padding_scheme);
   const AlgorithmIdentifier sig_algo = signer->algorithm_identifier();

   const size_t PKCS10_VERSION = 0;

   DER_Encoder tbs_req;

   tbs_req.start_sequence()
      .encode(PKCS10_VERSION)
      .encode(subject_dn)
      .raw_bytes(key.subject_public_key())
      .start_explicit(0);

   if(challenge.empty() == false) {
      std::vector<uint8_t> value;
      DER_Encoder(value).encode(ASN1_String(challenge));
      tbs_req.encode(Attribute("PKCS9.ChallengePassword", value));
   }

   std::vector<uint8_t> extension_req;
   DER_Encoder(extension_req).start_sequence().encode(extensions).end_cons();
   tbs_req.encode(Attribute("PKCS9.ExtensionRequest", extension_req));

   // end the start_explicit above
   tbs_req.end_explicit().end_cons();

   const std::vector<uint8_t> req = X509_Object::make_signed(*signer, rng, sig_algo, tbs_req.get_contents());

   return PKCS10_Request(req);
}

/*
* Decode the CertificateRequestInfo
*/
namespace {

std::unique_ptr<PKCS10_Data> decode_pkcs10(const std::vector<uint8_t>& body) {
   auto data = std::make_unique<PKCS10_Data>();

   BER_Decoder cert_req_info(body);

   size_t version;
   cert_req_info.decode(version);
   if(version != 0) {
      throw Decoding_Error("Unknown version code in PKCS #10 request: " + std::to_string(version));
   }

   cert_req_info.decode(data->m_subject_dn);

   BER_Object public_key = cert_req_info.get_next_object();
   if(public_key.is_a(ASN1_Type::Sequence, ASN1_Class::Constructed) == false) {
      throw BER_Bad_Tag("PKCS10_Request: Unexpected tag for public key", public_key.tagging());
   }

   data->m_public_key_bits = ASN1::put_in_sequence(public_key.bits(), public_key.length());

   BER_Object attr_bits = cert_req_info.get_next_object();

   std::set<std::string> pkcs9_email;

   if(attr_bits.is_a(0, ASN1_Class::Constructed | ASN1_Class::ContextSpecific)) {
      BER_Decoder attributes(attr_bits);
      while(attributes.more_items()) {
         Attribute attr;
         attributes.decode(attr);

         const OID& oid = attr.object_identifier();
         BER_Decoder value(attr.get_parameters());

         if(oid == OID::from_string("PKCS9.EmailAddress")) {
            ASN1_String email;
            value.decode(email);
            pkcs9_email.insert(email.value());
         } else if(oid == OID::from_string("PKCS9.ChallengePassword")) {
            ASN1_String challenge_password;
            value.decode(challenge_password);
            data->m_challenge = challenge_password.value();
         } else if(oid == OID::from_string("PKCS9.ExtensionRequest")) {
            value.decode(data->m_extensions).verify_end();
         }
      }
      attributes.verify_end();
   } else if(attr_bits.is_set()) {
      throw BER_Bad_Tag("PKCS10_Request: Unexpected tag for attributes", attr_bits.tagging());
   }

   cert_req_info.verify_end();

   if(auto ext = data->m_extensions.get_extension_object_as<Cert_Extension::Subject_Alternative_Name>()) {
      data->m_alt_name = ext->get_alt_name();
   }

   for(const auto& email : pkcs9_email) {
      data->m_alt_name.add_email(email);
   }

   return data;
}

}  // namespace

void PKCS10_Request::force_decode() {
   m_data.reset();

   m_data = decode_pkcs10(signed_body());

   auto key = this->subject_public_key();
   if(!this->check_signature(*key)) {
      throw Decoding_Error("PKCS #10 request: Bad signature detected");
   }
}

const PKCS10_Data& PKCS10_Request::data() const {
   if(m_data == nullptr) {
      throw Decoding_Error("PKCS10_Request decoding failed");
   }
   return *m_data;
}

/*
* Return the challenge password (if any)
*/
std::string PKCS10_Request::challenge_password() const {
   return data().m_challenge;
}

/*
* Return the name of the requestor
*/
const X509_DN& PKCS10_Request::subject_dn() const {
   return data().m_subject_dn;
}

/*
* Return the public key of the requestor
*/
const std::vector<uint8_t>& PKCS10_Request::raw_public_key() const {
   return data().m_public_key_bits;
}

/*
* Return the public key of the requestor
*/
std::unique_ptr<Public_Key> PKCS10_Request::subject_public_key() const {
   DataSource_Memory source(raw_public_key());
   return X509::load_key(source);
}

/*
* Return the alternative names of the requestor
*/
const AlternativeName& PKCS10_Request::subject_alt_name() const {
   return data().m_alt_name;
}

/*
* Return the X509v3 extensions
*/
const Extensions& PKCS10_Request::extensions() const {
   return data().m_extensions;
}

/*
* Return the key constraints (if any)
*/
Key_Constraints PKCS10_Request::constraints() const {
   if(auto ext = extensions().get(OID::from_string("X509v3.KeyUsage"))) {
      return dynamic_cast<Cert_Extension::Key_Usage&>(*ext).get_constraints();
   }

   return Key_Constraints::None;
}

/*
* Return the extendend key constraints (if any)
*/
std::vector<OID> PKCS10_Request::ex_constraints() const {
   if(auto ext = extensions().get(OID::from_string("X509v3.ExtendedKeyUsage"))) {
      return dynamic_cast<Cert_Extension::Extended_Key_Usage&>(*ext).object_identifiers();
   }

   return {};
}

/*
* Return is a CA certificate is requested
*/
bool PKCS10_Request::is_CA() const {
   if(auto ext = extensions().get(OID::from_string("X509v3.BasicConstraints"))) {
      return dynamic_cast<Cert_Extension::Basic_Constraints&>(*ext).get_is_ca();
   }

   return false;
}

/*
* Return the desired path limit (if any)
*/
size_t PKCS10_Request::path_limit() const {
   if(auto ext = extensions().get(OID::from_string("X509v3.BasicConstraints"))) {
      Cert_Extension::Basic_Constraints& basic_constraints = dynamic_cast<Cert_Extension::Basic_Constraints&>(*ext);
      if(basic_constraints.get_is_ca()) {
         return basic_constraints.get_path_limit();
      }
   }

   return 0;
}

}  // namespace Botan
