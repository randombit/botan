/*
* X.509 SIGNED Object
* (C) 1999-2007,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/x509_obj.h>

#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/pem.h>
#include <botan/pubkey.h>
#include <botan/internal/emsa.h>
#include <botan/internal/fmt.h>
#include <algorithm>
#include <sstream>

namespace Botan {

/*
* Read a PEM or BER X.509 object
*/
void X509_Object::load_data(DataSource& in) {
   try {
      if(ASN1::maybe_BER(in) && !PEM_Code::matches(in)) {
         BER_Decoder dec(in);
         decode_from(dec);
      } else {
         std::string got_label;
         DataSource_Memory ber(PEM_Code::decode(in, got_label));

         if(got_label != PEM_label()) {
            bool is_alternate = false;
            for(std::string_view alt_label : alternate_PEM_labels()) {
               if(got_label == alt_label) {
                  is_alternate = true;
                  break;
               }
            }

            if(!is_alternate) {
               throw Decoding_Error("Unexpected PEM label for " + PEM_label() + " of " + got_label);
            }
         }

         BER_Decoder dec(ber);
         decode_from(dec);
      }
   } catch(Decoding_Error& e) {
      throw Decoding_Error(PEM_label() + " decoding", e);
   }
}

void X509_Object::encode_into(DER_Encoder& to) const {
   to.start_sequence()
      .start_sequence()
      .raw_bytes(signed_body())
      .end_cons()
      .encode(signature_algorithm())
      .encode(signature(), ASN1_Type::BitString)
      .end_cons();
}

/*
* Read a BER encoded X.509 object
*/
void X509_Object::decode_from(BER_Decoder& from) {
   from.start_sequence()
      .start_sequence()
      .raw_bytes(m_tbs_bits)
      .end_cons()
      .decode(m_sig_algo)
      .decode(m_sig, ASN1_Type::BitString)
      .end_cons();

   force_decode();
}

/*
* Return a PEM encoded X.509 object
*/
std::string X509_Object::PEM_encode() const {
   return PEM_Code::encode(BER_encode(), PEM_label());
}

/*
* Return the TBS data
*/
std::vector<uint8_t> X509_Object::tbs_data() const {
   return ASN1::put_in_sequence(m_tbs_bits);
}

/*
* Check the signature on an object
*/
bool X509_Object::check_signature(const Public_Key& pub_key) const {
   const auto result = this->verify_signature(pub_key);
   return (result.first == Certificate_Status_Code::VERIFIED);
}

std::pair<Certificate_Status_Code, std::string> X509_Object::verify_signature(const Public_Key& pub_key) const {
   try {
      PK_Verifier verifier(pub_key, signature_algorithm());
      const bool valid = verifier.verify_message(tbs_data(), signature());

      if(valid) {
         return std::make_pair(Certificate_Status_Code::VERIFIED, verifier.hash_function());
      } else {
         return std::make_pair(Certificate_Status_Code::SIGNATURE_ERROR, "");
      }
   } catch(Decoding_Error&) {
      return std::make_pair(Certificate_Status_Code::SIGNATURE_ALGO_BAD_PARAMS, "");
   } catch(Lookup_Error&) {
      return std::make_pair(Certificate_Status_Code::SIGNATURE_ALGO_UNKNOWN, "");
   } catch(...) {
      // This shouldn't happen, fallback to generic signature error
      return std::make_pair(Certificate_Status_Code::SIGNATURE_ERROR, "");
   }
}

/*
* Apply the X.509 SIGNED macro
*/
std::vector<uint8_t> X509_Object::make_signed(PK_Signer& signer,
                                              RandomNumberGenerator& rng,
                                              const AlgorithmIdentifier& algo,
                                              const secure_vector<uint8_t>& tbs_bits) {
   const std::vector<uint8_t> signature = signer.sign_message(tbs_bits, rng);

   std::vector<uint8_t> output;
   DER_Encoder(output)
      .start_sequence()
      .raw_bytes(tbs_bits)
      .encode(algo)
      .encode(signature, ASN1_Type::BitString)
      .end_cons();

   return output;
}

namespace {

std::string x509_signature_padding_for(const std::string& algo_name,
                                       std::string_view hash_fn,
                                       std::string_view user_specified_padding) {
   if(algo_name == "DSA" || algo_name == "ECDSA" || algo_name == "ECGDSA" || algo_name == "ECKCDSA" ||
      algo_name == "GOST-34.10" || algo_name == "GOST-34.10-2012-256" || algo_name == "GOST-34.10-2012-512") {
      BOTAN_ARG_CHECK(user_specified_padding.empty() || user_specified_padding == "EMSA1",
                      "Invalid padding scheme for DSA-like scheme");

      return hash_fn.empty() ? "SHA-256" : std::string(hash_fn);
   } else if(algo_name == "RSA") {
      // set to PKCSv1.5 for compatibility reasons, originally it was the only option

      if(user_specified_padding.empty()) {
         if(hash_fn.empty()) {
            return "EMSA3(SHA-256)";
         } else {
            return fmt("EMSA3({})", hash_fn);
         }
      } else {
         if(hash_fn.empty()) {
            return fmt("{}(SHA-256)", user_specified_padding);
         } else {
            return fmt("{}({})", user_specified_padding, hash_fn);
         }
      }
   } else if(algo_name == "Ed25519" || algo_name == "Ed448") {
      return user_specified_padding.empty() ? "Pure" : std::string(user_specified_padding);
   } else if(algo_name.starts_with("Dilithium-") || algo_name == "ML-DSA") {
      return user_specified_padding.empty() ? "Randomized" : std::string(user_specified_padding);
   } else if(algo_name == "XMSS" || algo_name == "HSS-LMS" || algo_name == "SLH-DSA") {
      // These algorithms do not take any padding, but if the user insists, we pass it along
      return std::string(user_specified_padding);
   } else {
      throw Invalid_Argument("Unknown X.509 signing key type: " + algo_name);
   }
}

std::string format_padding_error_message(std::string_view key_name,
                                         std::string_view signer_hash_fn,
                                         std::string_view user_hash_fn,
                                         std::string_view chosen_padding,
                                         std::string_view user_specified_padding) {
   std::ostringstream oss;

   oss << "Specified hash function " << user_hash_fn << " is incompatible with " << key_name;

   if(!signer_hash_fn.empty()) {
      oss << " chose hash function " << signer_hash_fn;
   }

   if(!chosen_padding.empty()) {
      oss << " chose padding " << chosen_padding;
   }
   if(!user_specified_padding.empty()) {
      oss << " with user specified padding " << user_specified_padding;
   }

   return oss.str();
}

}  // namespace

/*
* Choose a signing format for the key
*/
std::unique_ptr<PK_Signer> X509_Object::choose_sig_format(const Private_Key& key,
                                                          RandomNumberGenerator& rng,
                                                          std::string_view hash_fn,
                                                          std::string_view user_specified_padding) {
   const Signature_Format format = key.default_x509_signature_format();

   if(!user_specified_padding.empty()) {
      try {
         auto pk_signer = std::make_unique<PK_Signer>(key, rng, user_specified_padding, format);
         if(!hash_fn.empty() && pk_signer->hash_function() != hash_fn) {
            throw Invalid_Argument(format_padding_error_message(
               key.algo_name(), pk_signer->hash_function(), hash_fn, "", user_specified_padding));
         }
         return pk_signer;
      } catch(Lookup_Error&) {}
   }

   const std::string padding = x509_signature_padding_for(key.algo_name(), hash_fn, user_specified_padding);

   try {
      auto pk_signer = std::make_unique<PK_Signer>(key, rng, padding, format);
      if(!hash_fn.empty() && pk_signer->hash_function() != hash_fn) {
         throw Invalid_Argument(format_padding_error_message(
            key.algo_name(), pk_signer->hash_function(), hash_fn, padding, user_specified_padding));
      }
      return pk_signer;
   } catch(Not_Implemented&) {
      throw Invalid_Argument("Signatures using " + key.algo_name() + "/" + padding + " are not supported");
   }
}

}  // namespace Botan
