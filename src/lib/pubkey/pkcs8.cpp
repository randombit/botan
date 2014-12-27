/*
* PKCS #8
* (C) 1999-2010,2014 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/pkcs8.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/alg_id.h>
#include <botan/oids.h>
#include <botan/pem.h>
#include <botan/pbes2.h>
#include <botan/libstate.h>
#include <botan/scan_name.h>
#include <botan/internal/pk_algs.h>

namespace Botan {

namespace PKCS8 {

namespace {

/*
* Get info from an EncryptedPrivateKeyInfo
*/
secure_vector<byte> PKCS8_extract(DataSource& source,
                                  AlgorithmIdentifier& pbe_alg_id)
   {
   secure_vector<byte> key_data;

   BER_Decoder(source)
      .start_cons(SEQUENCE)
         .decode(pbe_alg_id)
         .decode(key_data, OCTET_STRING)
      .verify_end();

   return key_data;
   }

/*
* PEM decode and/or decrypt a private key
*/
secure_vector<byte> PKCS8_decode(
   DataSource& source,
   std::function<std::pair<bool,std::string> ()> get_passphrase,
   AlgorithmIdentifier& pk_alg_id)
   {
   AlgorithmIdentifier pbe_alg_id;
   secure_vector<byte> key_data, key;
   bool is_encrypted = true;

   try {
      if(ASN1::maybe_BER(source) && !PEM_Code::matches(source))
         key_data = PKCS8_extract(source, pbe_alg_id);
      else
         {
         std::string label;
         key_data = PEM_Code::decode(source, label);
         if(label == "PRIVATE KEY")
            is_encrypted = false;
         else if(label == "ENCRYPTED PRIVATE KEY")
            {
            DataSource_Memory key_source(key_data);
            key_data = PKCS8_extract(key_source, pbe_alg_id);
            }
         else
            throw PKCS8_Exception("Unknown PEM label " + label);
         }

      if(key_data.empty())
         throw PKCS8_Exception("No key data found");
      }
   catch(Decoding_Error& e)
      {
      throw Decoding_Error("PKCS #8 private key decoding failed: " + std::string(e.what()));
      }

   if(!is_encrypted)
      key = key_data;

   const size_t MAX_TRIES = 3;

   size_t tries = 0;
   while(true)
      {
      try {
         if(MAX_TRIES && tries >= MAX_TRIES)
            break;

         if(is_encrypted)
            {
            std::pair<bool, std::string> pass = get_passphrase();

            if(pass.first == false)
               break;

            if(OIDS::lookup(pbe_alg_id.oid) != "PBE-PKCS5v20")
               throw std::runtime_error("Unknown PBE type " + pbe_alg_id.oid.as_string());

            key = pbes2_decrypt(key_data, pass.second, pbe_alg_id.parameters,
                                global_state().algorithm_factory());
            }

         BER_Decoder(key)
            .start_cons(SEQUENCE)
               .decode_and_check<size_t>(0, "Unknown PKCS #8 version number")
               .decode(pk_alg_id)
               .decode(key, OCTET_STRING)
               .discard_remaining()
            .end_cons();

         break;
         }
      catch(Decoding_Error)
         {
         ++tries;
         }
      }

   if(key.empty())
      throw Decoding_Error("PKCS #8 private key decoding failed");
   return key;
   }

}

/*
* BER encode a PKCS #8 private key, unencrypted
*/
secure_vector<byte> BER_encode(const Private_Key& key)
   {
   const size_t PKCS8_VERSION = 0;

   return DER_Encoder()
         .start_cons(SEQUENCE)
            .encode(PKCS8_VERSION)
            .encode(key.pkcs8_algorithm_identifier())
            .encode(key.pkcs8_private_key(), OCTET_STRING)
         .end_cons()
      .get_contents();
   }

/*
* PEM encode a PKCS #8 private key, unencrypted
*/
std::string PEM_encode(const Private_Key& key)
   {
   return PEM_Code::encode(PKCS8::BER_encode(key), "PRIVATE KEY");
   }

namespace {

std::pair<std::string, std::string>
choose_pbe_params(const std::string& pbe_algo, const std::string& key_algo)
   {
   if(pbe_algo == "")
      {
      // Defaults:
      if(key_algo == "Curve25519" || key_algo == "McEliece")
         return std::make_pair("AES-256/GCM", "SHA-512");
      else // for everything else (RSA, DSA, ECDSA, GOST, ...)
         return std::make_pair("AES-256/CBC", "SHA-256");
      }

   SCAN_Name request(pbe_algo);
   if(request.algo_name() != "PBE-PKCS5v20" || request.arg_count() != 2)
      throw std::runtime_error("Unsupported PBE " + pbe_algo);
   return std::make_pair(request.arg(1), request.arg(0));
   }

}

/*
* BER encode a PKCS #8 private key, encrypted
*/
std::vector<byte> BER_encode(const Private_Key& key,
                             RandomNumberGenerator& rng,
                             const std::string& pass,
                             std::chrono::milliseconds msec,
                             const std::string& pbe_algo)
   {
   const auto pbe_params = choose_pbe_params(pbe_algo, key.algo_name());

   const std::pair<AlgorithmIdentifier, std::vector<byte>> pbe_info =
      pbes2_encrypt(PKCS8::BER_encode(key), pass, msec,
                    pbe_params.first, pbe_params.second,
                    rng, global_state().algorithm_factory());

   return DER_Encoder()
         .start_cons(SEQUENCE)
            .encode(pbe_info.first)
            .encode(pbe_info.second, OCTET_STRING)
         .end_cons()
      .get_contents_unlocked();
   }

/*
* PEM encode a PKCS #8 private key, encrypted
*/
std::string PEM_encode(const Private_Key& key,
                       RandomNumberGenerator& rng,
                       const std::string& pass,
                       std::chrono::milliseconds msec,
                       const std::string& pbe_algo)
   {
   if(pass == "")
      return PEM_encode(key);

   return PEM_Code::encode(PKCS8::BER_encode(key, rng, pass, msec, pbe_algo),
                           "ENCRYPTED PRIVATE KEY");
   }

/*
* Extract a private key and return it
*/
Private_Key* load_key(DataSource& source,
                      RandomNumberGenerator& rng,
                      std::function<std::pair<bool, std::string> ()> get_pass)
   {
   AlgorithmIdentifier alg_id;
   secure_vector<byte> pkcs8_key = PKCS8_decode(source, get_pass, alg_id);

   const std::string alg_name = OIDS::lookup(alg_id.oid);
   if(alg_name == "" || alg_name == alg_id.oid.as_string())
      throw PKCS8_Exception("Unknown algorithm OID: " +
                            alg_id.oid.as_string());

   return make_private_key(alg_id, pkcs8_key, rng);
   }

/*
* Extract a private key and return it
*/
Private_Key* load_key(const std::string& fsname,
                      RandomNumberGenerator& rng,
                      std::function<std::pair<bool, std::string> ()> get_pass)
   {
   DataSource_Stream source(fsname, true);
   return PKCS8::load_key(source, rng, get_pass);
   }

namespace {

class Single_Shot_Passphrase
   {
   public:
      Single_Shot_Passphrase(const std::string& pass) :
         passphrase(pass), first(true) {}

      std::pair<bool, std::string> operator()()
         {
         if(first)
            {
            first = false;
            return std::make_pair(true, passphrase);
            }
         else
            return std::make_pair(false, "");
         }

   private:
      std::string passphrase;
      bool first;
   };

}

/*
* Extract a private key and return it
*/
Private_Key* load_key(DataSource& source,
                      RandomNumberGenerator& rng,
                      const std::string& pass)
   {
   return PKCS8::load_key(source, rng, Single_Shot_Passphrase(pass));
   }

/*
* Extract a private key and return it
*/
Private_Key* load_key(const std::string& fsname,
                      RandomNumberGenerator& rng,
                      const std::string& pass)
   {
   return PKCS8::load_key(fsname, rng, Single_Shot_Passphrase(pass));
   }

/*
* Make a copy of this private key
*/
Private_Key* copy_key(const Private_Key& key,
                      RandomNumberGenerator& rng)
   {
   DataSource_Memory source(PEM_encode(key));
   return PKCS8::load_key(source, rng);
   }

}

}
