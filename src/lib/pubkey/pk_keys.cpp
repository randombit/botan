/*
* PK Key Types
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pk_keys.h>
#include <botan/pk_ops.h>
#include <botan/der_enc.h>
#include <botan/oids.h>
#include <botan/hash.h>
#include <botan/hex.h>

namespace Botan {

std::string create_hex_fingerprint(const uint8_t bits[],
                                   size_t bits_len,
                                   const std::string& hash_name)
   {
   std::unique_ptr<HashFunction> hash_fn(HashFunction::create_or_throw(hash_name));
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

   DER_Encoder(output).start_cons(SEQUENCE)
         .encode(algorithm_identifier())
         .encode(public_key_bits(), BIT_STRING)
      .end_cons();

   return output;
   }

/*
* Default OID access
*/
OID Public_Key::get_oid() const
   {
   const OID o = OIDS::str2oid_or_empty(algo_name());
   if(o.empty())
      throw Lookup_Error("PK algo " + algo_name() + " has no defined OIDs");
   return o;
   }

secure_vector<uint8_t> Private_Key::private_key_info() const
   {
   const size_t PKCS8_VERSION = 0;

   return DER_Encoder()
         .start_cons(SEQUENCE)
            .encode(PKCS8_VERSION)
            .encode(pkcs8_algorithm_identifier())
            .encode(private_key_bits(), OCTET_STRING)
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
                                 const std::string& /*params*/,
                                 const std::string& /*provider*/) const
   {
   throw Lookup_Error(algo_name() + " does not support encryption");
   }

std::unique_ptr<PK_Ops::KEM_Encryption>
Public_Key::create_kem_encryption_op(RandomNumberGenerator& /*rng*/,
                                     const std::string& /*params*/,
                                     const std::string& /*provider*/) const
   {
   throw Lookup_Error(algo_name() + " does not support KEM encryption");
   }

std::unique_ptr<PK_Ops::Verification>
Public_Key::create_verification_op(const std::string& /*params*/,
                                   const std::string& /*provider*/) const
   {
   throw Lookup_Error(algo_name() + " does not support verification");
   }

std::unique_ptr<PK_Ops::Decryption>
Private_Key::create_decryption_op(RandomNumberGenerator& /*rng*/,
                                  const std::string& /*params*/,
                                  const std::string& /*provider*/) const
   {
   throw Lookup_Error(algo_name() + " does not support decryption");
   }

std::unique_ptr<PK_Ops::KEM_Decryption>
Private_Key::create_kem_decryption_op(RandomNumberGenerator& /*rng*/,
                                      const std::string& /*params*/,
                                      const std::string& /*provider*/) const
   {
   throw Lookup_Error(algo_name() + " does not support KEM decryption");
   }

std::unique_ptr<PK_Ops::Signature>
Private_Key::create_signature_op(RandomNumberGenerator& /*rng*/,
                                 const std::string& /*params*/,
                                 const std::string& /*provider*/) const
   {
   throw Lookup_Error(algo_name() + " does not support signatures");
   }

std::unique_ptr<PK_Ops::Key_Agreement>
Private_Key::create_key_agreement_op(RandomNumberGenerator& /*rng*/,
                                     const std::string& /*params*/,
                                     const std::string& /*provider*/) const
   {
   throw Lookup_Error(algo_name() + " does not support key agreement");
   }

}
