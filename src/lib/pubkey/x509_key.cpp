/*
* X.509 Public Key
* (C) 1999-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/x509_key.h>

#include <botan/asn1_obj.h>
#include <botan/ber_dec.h>
#include <botan/data_src.h>
#include <botan/pem.h>
#include <botan/pk_algs.h>

namespace Botan::X509 {

/*
* PEM encode a X.509 public key
*/
std::string PEM_encode(const Public_Key& key) {
   return PEM_Code::encode(key.subject_public_key(), "PUBLIC KEY");
}

/*
* Extract a public key and return it
*/
std::unique_ptr<Public_Key> load_key(DataSource& source) {
   try {
      AlgorithmIdentifier alg_id;
      std::vector<uint8_t> key_bits;

      if(ASN1::maybe_BER(source) && !PEM_Code::matches(source)) {
         BER_Decoder(source).start_sequence().decode(alg_id).decode(key_bits, ASN1_Type::BitString).end_cons();
      } else {
         DataSource_Memory ber(PEM_Code::decode_check_label(source, "PUBLIC KEY"));

         BER_Decoder(ber).start_sequence().decode(alg_id).decode(key_bits, ASN1_Type::BitString).end_cons();
      }

      if(key_bits.empty()) {
         throw Decoding_Error("X.509 public key decoding");
      }

      return load_public_key(alg_id, key_bits);
   } catch(Decoding_Error& e) {
      throw Decoding_Error("X.509 public key decoding", e);
   }
}

}  // namespace Botan::X509
