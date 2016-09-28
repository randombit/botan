/*
* X.509 Public Key
* (C) 1999-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/x509_key.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/pem.h>
#include <botan/alg_id.h>
#include <botan/pk_algs.h>

namespace Botan {

namespace X509 {

std::vector<byte> BER_encode(const Public_Key& key)
   {
   return DER_Encoder()
         .start_cons(SEQUENCE)
            .encode(key.algorithm_identifier())
            .encode(key.x509_subject_public_key(), BIT_STRING)
         .end_cons()
      .get_contents_unlocked();
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
      secure_vector<byte> key_bits;

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

      return load_public_key(alg_id, key_bits).release();
      }
   catch(Decoding_Error& e)
      {
      throw Decoding_Error("X.509 public key decoding failed: " + std::string(e.what()));
      }
   }

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
/*
* Extract a public key and return it
*/
Public_Key* load_key(const std::string& fsname)
   {
   DataSource_Stream source(fsname, true);
   return X509::load_key(source);
   }
#endif

/*
* Extract a public key and return it
*/
Public_Key* load_key(const std::vector<byte>& mem)
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

}

}
