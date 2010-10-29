/*
* X.509 Public Key
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/x509_key.h>
#include <botan/filters.h>
#include <botan/asn1_obj.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/pem.h>
#include <botan/internal/pk_algs.h>
#include <memory>

namespace Botan {

namespace X509 {

MemoryVector<byte> BER_encode(const Public_Key& key)
   {
   return DER_Encoder()
         .start_cons(SEQUENCE)
            .encode(key.algorithm_identifier())
            .encode(key.x509_subject_public_key(), BIT_STRING)
         .end_cons()
      .get_contents();
   }

/*
* PEM encode a X.509 public key
*/
std::string PEM_encode(const Public_Key& key)
   {
   return PEM_Code::encode(X509::BER_encode(key),
                           "PUBLIC KEY");
   }

/*
* Extract a public key and return it
*/
Public_Key* load_key(DataSource& source)
   {
   try {
      AlgorithmIdentifier alg_id;
      MemoryVector<byte> key_bits;

      if(ASN1::maybe_BER(source) && !PEM_Code::matches(source))
         {
         BER_Decoder(source)
            .start_cons(SEQUENCE)
            .decode(alg_id)
            .decode(key_bits, BIT_STRING)
            .verify_end()
         .end_cons();
         }
      else
         {
         DataSource_Memory ber(
            PEM_Code::decode_check_label(source, "PUBLIC KEY")
            );

         BER_Decoder(ber)
            .start_cons(SEQUENCE)
            .decode(alg_id)
            .decode(key_bits, BIT_STRING)
            .verify_end()
         .end_cons();
         }

      if(key_bits.empty())
         throw Decoding_Error("X.509 public key decoding failed");

      return make_public_key(alg_id, key_bits);
      }
   catch(Decoding_Error)
      {
      throw Decoding_Error("X.509 public key decoding failed");
      }
   }

/*
* Extract a public key and return it
*/
Public_Key* load_key(const std::string& fsname)
   {
   DataSource_Stream source(fsname, true);
   return X509::load_key(source);
   }

/*
* Extract a public key and return it
*/
Public_Key* load_key(const MemoryRegion<byte>& mem)
   {
   DataSource_Memory source(mem);
   return X509::load_key(source);
   }

/*
* Make a copy of this public key
*/
Public_Key* copy_key(const Public_Key& key)
   {
   DataSource_Memory source(PEM_encode(key));
   return X509::load_key(source);
   }

/*
* Find the allowable key constraints
*/
Key_Constraints find_constraints(const Public_Key& pub_key,
                                 Key_Constraints limits)
   {
   const std::string name = pub_key.algo_name();

   size_t constraints = 0;

   if(name == "DH" || name == "ECDH")
      constraints |= KEY_AGREEMENT;

   if(name == "RSA" || name == "ElGamal")
      constraints |= KEY_ENCIPHERMENT | DATA_ENCIPHERMENT;

   if(name == "RSA" || name == "RW" || name == "NR" ||
      name == "DSA" || name == "ECDSA")
      constraints |= DIGITAL_SIGNATURE | NON_REPUDIATION;

   if(limits)
      constraints &= limits;

   return Key_Constraints(constraints);
   }

}

}
