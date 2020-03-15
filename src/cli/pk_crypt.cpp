/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_RSA) && defined(BOTAN_HAS_AEAD_MODES) && defined(BOTAN_HAS_EME_OAEP) && defined(BOTAN_HAS_SHA2_32) && defined(BOTAN_HAS_PEM_CODEC) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

#include <botan/pubkey.h>
#include <botan/x509_key.h>
#include <botan/pkcs8.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/oids.h>
#include <botan/aead.h>
#include <botan/pem.h>
#include <botan/rng.h>

namespace Botan_CLI {

namespace {

class PK_Encrypt final : public Command
   {
   public:
      PK_Encrypt() : Command("pk_encrypt --aead=AES-256/GCM pubkey datafile") {}

      std::string group() const override
         {
         return "pubkey";
         }

      std::string description() const override
         {
         return "Encrypt a file using a RSA public key";
         }

      void go() override
         {
         std::unique_ptr<Botan::Public_Key> key(Botan::X509::load_key(get_arg("pubkey")));
         if(!key)
            {
            throw CLI_Error("Unable to load public key");
            }

         if(key->algo_name() != "RSA")
            {
            throw CLI_Usage_Error("This function requires an RSA key");
            }

         const std::string OAEP_HASH = "SHA-256";
         const std::string aead_algo = get_arg("aead");

         std::unique_ptr<Botan::AEAD_Mode> aead =
            Botan::AEAD_Mode::create(aead_algo, Botan::ENCRYPTION);

         if(!aead)
            throw CLI_Usage_Error("The AEAD '" + aead_algo + "' is not available");

         const Botan::OID aead_oid = Botan::OID::from_string(aead_algo);
         if(aead_oid.empty())
            throw CLI_Usage_Error("No OID defined for AEAD '" + aead_algo + "'");

         Botan::secure_vector<uint8_t> data;
         auto insert_fn = [&](const uint8_t b[], size_t l)
            {
            data.insert(data.end(), b, b + l);
            };
         this->read_file(get_arg("datafile"), insert_fn);

         const Botan::AlgorithmIdentifier hash_id(OAEP_HASH, Botan::AlgorithmIdentifier::USE_EMPTY_PARAM);
         const Botan::AlgorithmIdentifier pk_alg_id("RSA/OAEP", hash_id.BER_encode());

         Botan::PK_Encryptor_EME enc(*key, rng(), "OAEP(" + OAEP_HASH + ")");

         const Botan::secure_vector<uint8_t> file_key = rng().random_vec(aead->key_spec().maximum_keylength());

         const std::vector<uint8_t> encrypted_key = enc.encrypt(file_key, rng());

         const Botan::secure_vector<uint8_t> nonce = rng().random_vec(aead->default_nonce_length());
         aead->set_key(file_key);
         aead->set_associated_data_vec(encrypted_key);
         aead->start(nonce);

         aead->finish(data);

         std::vector<uint8_t> buf;
         Botan::DER_Encoder der(buf);

         der.start_cons(Botan::SEQUENCE)
            .encode(pk_alg_id)
            .encode(encrypted_key, Botan::OCTET_STRING)
            .encode(aead_oid)
            .encode(nonce, Botan::OCTET_STRING)
            .encode(data, Botan::OCTET_STRING)
            .end_cons();

         output() << Botan::PEM_Code::encode(buf, "PUBKEY ENCRYPTED MESSAGE", 72);
         }
   };

BOTAN_REGISTER_COMMAND("pk_encrypt", PK_Encrypt);

class PK_Decrypt final : public Command
   {
   public:
      PK_Decrypt() : Command("pk_decrypt privkey datafile") {}

      std::string group() const override
         {
         return "pubkey";
         }

      std::string description() const override
         {
         return "Decrypt a file using a RSA private key";
         }

      void go() override
         {
         Botan::DataSource_Stream input_stream(get_arg("privkey"));
         auto get_pass = [this]() { return get_passphrase("Password"); };
         std::unique_ptr<Botan::Private_Key> key = Botan::PKCS8::load_key(input_stream, get_pass);

         if(!key)
            {
            throw CLI_Error("Unable to load public key");
            }

         if(key->algo_name() != "RSA")
            {
            throw CLI_Usage_Error("This function requires an RSA key");
            }

         Botan::secure_vector<uint8_t> data;
         std::vector<uint8_t> encrypted_key;
         std::vector<uint8_t> nonce;
         Botan::AlgorithmIdentifier pk_alg_id;
         Botan::OID aead_oid;

         try
            {
            Botan::DataSource_Stream input(get_arg("datafile"));

            Botan::BER_Decoder(Botan::PEM_Code::decode_check_label(input, "PUBKEY ENCRYPTED MESSAGE"))
               .start_cons(Botan::SEQUENCE)
                  .decode(pk_alg_id)
                  .decode(encrypted_key, Botan::OCTET_STRING)
                  .decode(aead_oid)
                  .decode(nonce, Botan::OCTET_STRING)
                  .decode(data, Botan::OCTET_STRING)
               .end_cons();
            }
         catch(Botan::Decoding_Error&)
            {
            error_output() << "Parsing input file failed: invalid format?\n";
            return set_return_code(1);
            }

         const std::string aead_algo = Botan::OIDS::oid2str_or_empty(aead_oid);
         if(aead_algo == "")
            {
            error_output() << "Ciphertext was encrypted with an unknown algorithm";
            return set_return_code(1);
            }

         if(pk_alg_id.get_oid() != Botan::OID::from_string("RSA/OAEP"))
            {
            error_output() << "Ciphertext was encrypted with something other than RSA/OAEP";
            return set_return_code(1);
            }

         Botan::AlgorithmIdentifier oaep_hash_id;
         Botan::BER_Decoder(pk_alg_id.get_parameters()).decode(oaep_hash_id);

         const std::string oaep_hash = Botan::OIDS::oid2str_or_empty(oaep_hash_id.get_oid());

         if(oaep_hash.empty())
            {
            error_output() << "Unknown hash function used with OAEP, OID " << oaep_hash_id.get_oid().to_string() << "\n";
            return set_return_code(1);
            }

         if(oaep_hash_id.get_parameters().empty() == false)
            {
            error_output() << "Unknown OAEP parameters used\n";
            return set_return_code(1);
            }

         std::unique_ptr<Botan::AEAD_Mode> aead =
            Botan::AEAD_Mode::create_or_throw(aead_algo, Botan::DECRYPTION);

         const size_t expected_keylen = aead->key_spec().maximum_keylength();

         Botan::PK_Decryptor_EME dec(*key, rng(), "OAEP(" + oaep_hash + ")");

         const Botan::secure_vector<uint8_t> file_key =
            dec.decrypt_or_random(encrypted_key.data(),
                                  encrypted_key.size(),
                                  expected_keylen,
                                  rng());

         aead->set_key(file_key);
         aead->set_associated_data_vec(encrypted_key);
         aead->start(nonce);

         try
            {
            aead->finish(data);

            output().write(reinterpret_cast<const char*>(data.data()), data.size());
            }
         catch(Botan::Integrity_Failure&)
            {
            error_output() << "Message authentication failure, possible ciphertext tampering\n";
            return set_return_code(1);
            }
         }
   };

BOTAN_REGISTER_COMMAND("pk_decrypt", PK_Decrypt);

}

}

#endif
