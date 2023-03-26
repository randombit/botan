/*
* PK Key Types
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pk_keys.h>
#include <botan/internal/pk_ops.h>
#include <botan/der_enc.h>
#include <botan/hash.h>
#include <botan/hex.h>

namespace Botan {

const BigInt& Asymmetric_Key::get_int_field(const std::string& field) const
   {
   throw Unknown_PK_Field_Name(algo_name(), field);
   }

OID Asymmetric_Key::object_identifier() const
   {
   try
      {
      return OID::from_string(algo_name());
      }
   catch(Lookup_Error&)
      {
      throw Lookup_Error("PK algo " + algo_name() + " has no defined OIDs");
      }
   }

std::string create_hex_fingerprint(const uint8_t bits[],
                                   size_t bits_len,
                                   const std::string& hash_name)
   {
   auto hash_fn = HashFunction::create_or_throw(hash_name);
   const std::string hex_hash = hex_encode(hash_fn->process(bits, bits_len));

   std::string fprint;

   for(size_t i = 0; i != hex_hash.size(); i += 2)
      {
      if(i != 0)
         fprint.push_back(':');

      fprint.push_back(hex_hash[i]);
      fprint.push_back(hex_hash[i+1]);
      }

   return fprint;
   }

std::vector<uint8_t> Public_Key::subject_public_key() const
   {
   std::vector<uint8_t> output;

   DER_Encoder(output).start_sequence()
         .encode(algorithm_identifier())
         .encode(public_key_bits(), ASN1_Type::BitString)
      .end_cons();

   return output;
   }

secure_vector<uint8_t> Private_Key::private_key_info() const
   {
   const size_t PKCS8_VERSION = 0;

   return DER_Encoder()
         .start_sequence()
            .encode(PKCS8_VERSION)
            .encode(pkcs8_algorithm_identifier())
            .encode(private_key_bits(), ASN1_Type::OctetString)
         .end_cons()
      .get_contents();
   }

/*
* Hash of the X.509 subjectPublicKey encoding
*/
std::string Public_Key::fingerprint_public(const std::string& hash_algo) const
   {
   return create_hex_fingerprint(subject_public_key(), hash_algo);
   }

/*
* Hash of the PKCS #8 encoding for this key object
*/
std::string Private_Key::fingerprint_private(const std::string& hash_algo) const
   {
   return create_hex_fingerprint(private_key_bits(), hash_algo);
   }

std::unique_ptr<PK_Ops::Encryption>
Public_Key::create_encryption_op(RandomNumberGenerator& /*rng*/,
                                 std::string_view /*params*/,
                                 std::string_view /*provider*/) const
   {
   throw Lookup_Error(algo_name() + " does not support encryption");
   }

std::unique_ptr<PK_Ops::KEM_Encryption>
Public_Key::create_kem_encryption_op(std::string_view /*params*/,
                                     std::string_view /*provider*/) const
   {
   throw Lookup_Error(algo_name() + " does not support KEM encryption");
   }

std::unique_ptr<PK_Ops::Verification>
Public_Key::create_verification_op(std::string_view /*params*/,
                                   std::string_view /*provider*/) const
   {
   throw Lookup_Error(algo_name() + " does not support verification");
   }

std::unique_ptr<PK_Ops::Verification>
Public_Key::create_x509_verification_op(const AlgorithmIdentifier& /*params*/,
                                        std::string_view /*provider*/) const
   {
   throw Lookup_Error(algo_name() + " does not support X.509 verification");
   }

std::unique_ptr<PK_Ops::Decryption>
Private_Key::create_decryption_op(RandomNumberGenerator& /*rng*/,
                                  std::string_view /*params*/,
                                  std::string_view /*provider*/) const
   {
   throw Lookup_Error(algo_name() + " does not support decryption");
   }

std::unique_ptr<PK_Ops::KEM_Decryption>
Private_Key::create_kem_decryption_op(RandomNumberGenerator& /*rng*/,
                                      std::string_view /*params*/,
                                      std::string_view /*provider*/) const
   {
   throw Lookup_Error(algo_name() + " does not support KEM decryption");
   }

std::unique_ptr<PK_Ops::Signature>
Private_Key::create_signature_op(RandomNumberGenerator& /*rng*/,
                                 std::string_view /*params*/,
                                 std::string_view /*provider*/) const
   {
   throw Lookup_Error(algo_name() + " does not support signatures");
   }

std::unique_ptr<PK_Ops::Key_Agreement>
Private_Key::create_key_agreement_op(RandomNumberGenerator& /*rng*/,
                                     std::string_view /*params*/,
                                     std::string_view /*provider*/) const
   {
   throw Lookup_Error(algo_name() + " does not support key agreement");
   }

}
