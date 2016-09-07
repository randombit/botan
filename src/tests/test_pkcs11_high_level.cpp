/*
* (C) 2016 Daniel Neus
* (C) 2016 Philipp Weber
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include "test_pkcs11.h"

#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <array>
#include <type_traits>
#include <map>
#include <numeric>

#if defined(BOTAN_HAS_PKCS11)
   #include <botan/p11.h>
   #include <botan/p11_slot.h>
   #include <botan/p11_session.h>
   #include <botan/p11_module.h>
   #include <botan/p11_object.h>
   #include <botan/p11_randomgenerator.h>
#endif

#if defined(BOTAN_HAS_ASN1)
   #include <botan/der_enc.h>
#endif

#if defined (BOTAN_HAS_PUBLIC_KEY_CRYPTO)
   #include <botan/pubkey.h>
#endif

#if defined(BOTAN_HAS_RSA) && defined(BOTAN_HAS_PKCS11) 
   #include <botan/rsa.h>
   #include <botan/p11_rsa.h>
#endif

#if defined(BOTAN_HAS_ECC_PUBLIC_KEY_CRYPTO) && defined(BOTAN_HAS_PKCS11)
   #include <botan/ecc_key.h>
   #include <botan/ecdsa.h>
   #include <botan/ecdh.h>
   #include <botan/p11_ecc_key.h>
   #include <botan/p11_ecdh.h>
   #include <botan/p11_ecdsa.h>
#endif

#if defined(BOTAN_HAS_X509_CERTIFICATES) && defined(BOTAN_HAS_PKCS11)
   #include <botan/p11_x509.h>
#endif

#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
   #include <botan/auto_rng.h>
#endif

#if defined(BOTAN_HAS_HMAC_DRBG)
   #include <botan/hmac_drbg.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_PKCS11)

using namespace Botan;
using namespace PKCS11;

class TestSession
   {
   public:
      explicit TestSession(bool login) :
         m_module(new Module(Test::pkcs11_lib()))
         {
         std::vector<SlotId> slot_vec = Slot::get_available_slots(*m_module, true);
         m_slot.reset(new Slot(*m_module, slot_vec.at(0)));
         m_session.reset(new Session(*m_slot, false));
         if(login)
            {
            m_session->login(UserType::User, PIN_SECVEC);
            }
         }

      inline Module& module() const { return *m_module; }
      inline Slot& slot() const { return *m_slot; }
      inline Session& session() const { return *m_session; }

   private:
      std::unique_ptr<Module> m_module = nullptr;
      std::unique_ptr<Slot> m_slot = nullptr;
      std::unique_ptr<Session> m_session = nullptr;
   };

/***************************** Module *****************************/

Test::Result test_module_ctor()
   {
   Test::Result result("Module ctor");

   result.test_throws("Module ctor fails for non existent path", []()
      {
      Module module("/a/b/c");
      });

   Module module(Test::pkcs11_lib());
   result.test_success("Module ctor did not throw and completed successfully");

   return result;
   }

Test::Result test_module_reload()
   {
   Test::Result result("Module reload");

   Module module(Test::pkcs11_lib());

   module.reload();
   result.test_success("Module reload did not throw and completed successfully");

   module.get_info();
   result.test_success("Module get_info() still works after reload");

   return result;
   }

Test::Result test_multiple_modules()
   {
   Test::Result result("Module copy");
   Module first_module(Test::pkcs11_lib());

   result.test_throws("Module ctor fails if module is already initialized", []()
      {
      Module second_module(Test::pkcs11_lib());
      });

   return result;
   }

Test::Result test_module_get_info()
   {
   Test::Result result("Module info");

   Module module(Test::pkcs11_lib());

   Info info = module.get_info();
   result.test_ne("Cryptoki version != 0", info.cryptokiVersion.major, 0);

   return result;
   }

class Module_Tests : public PKCS11_Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<std::function<Test::Result()>> fns =
            {
            test_module_ctor,
            test_multiple_modules,
            test_module_get_info,
            test_module_reload

            };

         return run_pkcs11_tests("Module", fns);
         }
   };

BOTAN_REGISTER_TEST("pkcs11-module", Module_Tests);

/***************************** Slot *****************************/

Test::Result test_slot_get_available_slots()
   {
   Test::Result result("Slot get_available_slots");

   Module module(Test::pkcs11_lib());
   std::vector<SlotId> slot_vec = Slot::get_available_slots(module, true);
   result.test_gte("Available Slots with attached token >= 1", slot_vec.size(), 1);

   return result;
   }

Test::Result test_slot_ctor()
   {
   Test::Result result("Slot ctor");

   Module module(Test::pkcs11_lib());
   std::vector<SlotId> slot_vec = Slot::get_available_slots(module, true);

   Slot slot(module, slot_vec.at(0));
   result.test_success("Slot ctor completed successfully");
   result.test_is_eq(slot.slot_id(), slot_vec.at(0));

   return result;
   }

Test::Result test_get_slot_info()
   {
   Test::Result result("Slot get_slot_info");

   Module module(Test::pkcs11_lib());
   std::vector<SlotId> slot_vec = Slot::get_available_slots(module, true);
   Slot slot(module, slot_vec.at(0));

   SlotInfo info = slot.get_slot_info();
   std::string description = reinterpret_cast< char* >(info.slotDescription);
   result.confirm("Slot description is not empty", !description.empty());

   return result;
   }

Test::Result test_get_token_info()
   {
   Test::Result result("Slot get_token_info");

   Module module(Test::pkcs11_lib());
   std::vector<SlotId> slot_vec = Slot::get_available_slots(module, true);
   Slot slot(module, slot_vec.at(0));

   TokenInfo info = slot.get_token_info();
   std::string label = reinterpret_cast< char* >(info.label);
   result.confirm("Token label is not empty", ! label.empty());

   return result;
   }

Test::Result test_get_mechanism_list()
   {
   Test::Result result("Slot get_mechanism_list");

   Module module(Test::pkcs11_lib());
   std::vector<SlotId> slot_vec = Slot::get_available_slots(module, true);
   Slot slot(module, slot_vec.at(0));

   std::vector<MechanismType> mechanisms = slot.get_mechanism_list();
   result.confirm("The Slot supports at least one mechanism", !mechanisms.empty());

   return result;
   }

Test::Result test_get_mechanisms_info()
   {
   Test::Result result("Slot get_mechanism_info");

   Module module(Test::pkcs11_lib());
   std::vector<SlotId> slot_vec = Slot::get_available_slots(module, true);
   Slot slot(module, slot_vec.at(0));

   slot.get_mechanism_info(MechanismType::RsaPkcsKeyPairGen);
   result.test_success("get_mechanism_info() completed successfully.");

   return result;
   }

class Slot_Tests : public PKCS11_Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<std::function<Test::Result()>> fns =
            {
            test_slot_get_available_slots,
            test_slot_ctor,
            test_get_slot_info,
            test_get_token_info,
            test_get_mechanism_list,
            test_get_mechanisms_info
            };

         return run_pkcs11_tests("Slot", fns);
         }
   };

BOTAN_REGISTER_TEST("pkcs11-slot", Slot_Tests);

/***************************** Session *****************************/

Test::Result test_session_ctor()
   {
   Test::Result result("Session ctor");

   Module module(Test::pkcs11_lib());
   std::vector<SlotId> slot_vec = Slot::get_available_slots(module, true);
   Slot slot(module, slot_vec.at(0));

      {
      Session read_only_session(slot, true);
      result.test_success("read only session opened successfully");
      }
      {
      Session read_write_session(slot, false);
      result.test_success("read write session opened successfully");
      }
      {
      Flags flags = PKCS11::flags(Flag::SerialSession | Flag::RwSession);
      Session read_write_session2(slot, flags, nullptr, nullptr);
      result.test_success("read write session with flags param opened successfully");
      }
      {
      Session read_only_session(slot, true);
      Session read_write_session(slot, false);
      result.test_success("Opened multiple sessions successfully");
      }

   return result;
   }

Test::Result test_session_release()
   {
   Test::Result result("Session release/take ownership");

   Module module(Test::pkcs11_lib());
   std::vector<SlotId> slot_vec = Slot::get_available_slots(module, true);
   Slot slot(module, slot_vec.at(0));

   Session session(slot, false);
   SessionHandle handle = session.release();

   Session session2(slot, handle);
   result.test_success("releasing ownership and taking ownership works as expected.");

   return result;
   }

Test::Result test_session_login_logout()
   {
   Test::Result result("Session login/logout");

   Module module(Test::pkcs11_lib());
   std::vector<SlotId> slot_vec = Slot::get_available_slots(module, true);
   Slot slot(module, slot_vec.at(0));

   Session session(slot, false);
   session.login(UserType::User, PIN_SECVEC);
   session.logoff();
   result.test_success("user login/logout succeeded");

   session.login(UserType::SO, SO_PIN_SECVEC);
   result.test_success("SO login succeeded");

   return result;
   }

Test::Result test_session_info()
   {
   Test::Result result("Session session info");

   Module module(Test::pkcs11_lib());
   std::vector<SlotId> slot_vec = Slot::get_available_slots(module, true);
   Slot slot(module, slot_vec.at(0));

   Session session(slot, false);
   SessionInfo info = session.get_info();
   result.test_is_eq("slot id is correct", info.slotID, slot_vec.at(0));
   result.test_is_eq("state is a read write public session", info.state,
                     static_cast<CK_STATE>(SessionState::RwPublicSession));

   session.login(UserType::User, PIN_SECVEC);
   info = session.get_info();
   result.test_is_eq("state is a read write user session", info.state,
                     static_cast<CK_STATE>(SessionState::RwUserFunctions));

   session.logoff();
   result.test_success("user login/logout succeeded");

   session.login(UserType::SO, SO_PIN_SECVEC);
   result.test_success("SO login succeeded");

   return result;
   }

class Session_Tests : public PKCS11_Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<std::function<Test::Result()>> fns =
            {
            test_session_ctor,
            test_session_release,
            test_session_login_logout,
            test_session_info
            };

         return run_pkcs11_tests("Session", fns);
         }
   };

BOTAN_REGISTER_TEST("pkcs11-session", Session_Tests);

/***************************** Object *****************************/

Test::Result test_attribute_container()
   {
   Test::Result result("AttributeContainer");

   AttributeContainer attributes;
   attributes.add_class(ObjectClass::PrivateKey);

   std::string label("test");
   attributes.add_string(AttributeType::Label, label);

   std::vector<byte> bin(4);
   attributes.add_binary(AttributeType::Value, bin);

   attributes.add_bool(AttributeType::Sensitive, true);
   attributes.add_numeric(AttributeType::ObjectId, 12);

   result.test_eq("Five elements in attribute container", attributes.count(), 5);

   return result;
   }

#if defined(BOTAN_HAS_ASN1)
Test::Result test_create_destroy_data_object()
   {
   Test::Result result("Object create/delete data object");

   TestSession test_session(true);

   std::string value_string("test data");
   secure_vector<byte> value(value_string.begin(), value_string.end());

   std::size_t id = 1337;
   std::string label = "Botan test data object";
   std::string application = "Botan test application";
   DataObjectProperties data_obj_props;
   data_obj_props.set_application(application);
   data_obj_props.set_label(label);
   data_obj_props.set_value(value);
   data_obj_props.set_token(true);
   data_obj_props.set_modifiable(true);
   data_obj_props.set_object_id(DER_Encoder().encode(id).get_contents_unlocked());

   Object data_obj(test_session.session(), data_obj_props);
   result.test_success("Data object creation was successful");

   data_obj.destroy();
   result.test_success("Data object deletion  was successful");

   return result;
   }

Test::Result test_get_set_attribute_values()
   {
   Test::Result result("Object get/set attributes");

   TestSession test_session(true);

   // create object
   std::string value_string("test data");
   secure_vector<byte> value(value_string.begin(), value_string.end());

   std::size_t id = 1337;
   std::string label = "Botan test data object";
   std::string application = "Botan test application";
   DataObjectProperties data_obj_props;
   data_obj_props.set_application(application);
   data_obj_props.set_label(label);
   data_obj_props.set_value(value);
   data_obj_props.set_token(true);
   data_obj_props.set_modifiable(true);
   data_obj_props.set_object_id(DER_Encoder().encode(id).get_contents_unlocked());
   Object data_obj(test_session.session(), data_obj_props);

   // get attribute
   secure_vector<byte> retrieved_label = data_obj.get_attribute_value(AttributeType::Label);
   std::string retrieved_label_string(retrieved_label.begin(), retrieved_label.end());
   result.test_eq("label was set correctly", retrieved_label_string, label);

   // set attribute
   std::string new_label = "Botan test modified data object label";
   secure_vector<byte> new_label_secvec(new_label.begin(), new_label.end());
   data_obj.set_attribute_value(AttributeType::Label, new_label_secvec);

   // get and check attribute
   retrieved_label = data_obj.get_attribute_value(AttributeType::Label);
   retrieved_label_string = std::string(retrieved_label.begin(), retrieved_label.end());
   result.test_eq("label was modified correctly", retrieved_label_string, new_label);

   data_obj.destroy();
   return result;
   }

Test::Result test_object_finder()
   {
   Test::Result result("ObjectFinder");

   TestSession test_session(true);

   // create object
   std::string value_string("test data");
   secure_vector<byte> value(value_string.begin(), value_string.end());

   std::size_t id = 1337;
   std::string label = "Botan test data object";
   std::string application = "Botan test application";
   DataObjectProperties data_obj_props;
   data_obj_props.set_application(application);
   data_obj_props.set_label(label);
   data_obj_props.set_value(value);
   data_obj_props.set_token(true);
   data_obj_props.set_modifiable(true);
   data_obj_props.set_object_id(DER_Encoder().encode(id).get_contents_unlocked());
   Object data_obj(test_session.session(), data_obj_props);

   // search created object
   AttributeContainer search_template;
   search_template.add_string(AttributeType::Label, label);
   ObjectFinder finder(test_session.session(), search_template.attributes());

   auto search_result = finder.find();
   result.test_eq("one object found", search_result.size(), 1);
   finder.finish();

   Object obj_found(test_session.session(), search_result.at(0));
   result.test_eq("found the object just created (same application)",
                  obj_found.get_attribute_value(AttributeType::Application) , data_obj.get_attribute_value(AttributeType::Application));

   auto search_result2 = Object::search<Object>(test_session.session(), search_template.attributes());
   result.test_eq("found the object just created (same label)", obj_found.get_attribute_value(AttributeType::Label),
                  search_result2.at(0).get_attribute_value(AttributeType::Label));

   data_obj.destroy();
   return result;
   }

Test::Result test_object_copy()
   {
   Test::Result result("Object copy");

   TestSession test_session(true);

   // create object
   std::string value_string("test data");
   secure_vector<byte> value(value_string.begin(), value_string.end());

   std::size_t id = 1337;
   std::string label = "Botan test data object";
   std::string application = "Botan test application";
   DataObjectProperties data_obj_props;
   data_obj_props.set_application(application);
   data_obj_props.set_label(label);
   data_obj_props.set_value(value);
   data_obj_props.set_token(true);
   data_obj_props.set_modifiable(true);
   data_obj_props.set_object_id(DER_Encoder().encode(id).get_contents_unlocked());
   Object data_obj(test_session.session(), data_obj_props);

   // copy created object
   AttributeContainer copy_attributes;
   copy_attributes.add_string(AttributeType::Label, "Botan test copied object");
   ObjectHandle copied_obj_handle = data_obj.copy(copy_attributes);

   ObjectFinder searcher(test_session.session(), copy_attributes.attributes());
   auto search_result = searcher.find();
   result.test_eq("one object found", search_result.size(), 1);

   data_obj.destroy();

   Object copied_obj(test_session.session(), copied_obj_handle);
   copied_obj.destroy();
   return result;
   }
#endif

class Object_Tests : public PKCS11_Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<std::function<Test::Result()>> fns =
            {
            test_attribute_container
#if defined(BOTAN_HAS_ASN1)
            ,test_create_destroy_data_object
            ,test_get_set_attribute_values
            ,test_object_finder
            ,test_object_copy
#endif
            };

         return run_pkcs11_tests("Object", fns);
         }
   };

BOTAN_REGISTER_TEST("pkcs11-object", Object_Tests);

/***************************** PKCS11 RSA *****************************/

#if defined(BOTAN_HAS_RSA)

Test::Result test_rsa_privkey_import()
   {
   Test::Result result("PKCS11 import RSA private key");

   TestSession test_session(true);

   // create private key
   RSA_PrivateKey priv_key(Test::rng(), 2048);

   // import to card
   RSA_PrivateKeyImportProperties props(priv_key.get_n(), priv_key.get_d());
   props.set_pub_exponent(priv_key.get_e());
   props.set_prime_1(priv_key.get_p());
   props.set_prime_2(priv_key.get_q());
   props.set_coefficient(priv_key.get_c());
   props.set_exponent_1(priv_key.get_d1());
   props.set_exponent_2(priv_key.get_d2());

   props.set_token(true);
   props.set_private(true);
   props.set_decrypt(true);
   props.set_sign(true);

   PKCS11_RSA_PrivateKey pk(test_session.session(), props);
   result.test_success("RSA private key import was successful");

   pk.destroy();
   return result;
   }

Test::Result test_rsa_privkey_export()
   {
   Test::Result result("PKCS11 export RSA private key");

   TestSession test_session(true);

   // create private key
   RSA_PrivateKey priv_key(Test::rng(), 2048);

   // import to card
   RSA_PrivateKeyImportProperties props(priv_key.get_n(), priv_key.get_d());
   props.set_pub_exponent(priv_key.get_e());
   props.set_prime_1(priv_key.get_p());
   props.set_prime_2(priv_key.get_q());
   props.set_coefficient(priv_key.get_c());
   props.set_exponent_1(priv_key.get_d1());
   props.set_exponent_2(priv_key.get_d2());

   props.set_token(true);
   props.set_private(true);
   props.set_decrypt(true);
   props.set_sign(true);
   props.set_extractable(true);
   props.set_sensitive(false);

   PKCS11_RSA_PrivateKey pk(test_session.session(), props);

   RSA_PrivateKey exported = pk.export_key();
   result.test_success("RSA private key export was successful");
   result.test_eq("pkcs8 private key", pk.pkcs8_private_key(), priv_key.pkcs8_private_key());

   pk.destroy();
   return result;
   }

Test::Result test_rsa_pubkey_import()
   {
   Test::Result result("PKCS11 import RSA public key");

   TestSession test_session(true);

   // create public key from private key
   RSA_PrivateKey priv_key(Test::rng(), 2048);

   // import to card
   RSA_PublicKeyImportProperties props(priv_key.get_n(), priv_key.get_e());
   props.set_token(true);
   props.set_encrypt(true);
   props.set_private(false);

   PKCS11_RSA_PublicKey pk(test_session.session(), props);
   result.test_success("RSA public key import was successful");

   pk.destroy();

   return result;
   }

Test::Result test_rsa_generate_private_key()
   {
   Test::Result result("PKCS11 generate RSA private key");
   TestSession test_session(true);

   RSA_PrivateKeyGenerationProperties props;
   props.set_token(true);
   props.set_private(true);
   props.set_sign(true);
   props.set_decrypt(true);

   PKCS11_RSA_PrivateKey pk(test_session.session(), 2048, props);
   result.test_success("RSA private key generation was successful");

   pk.destroy();

   return result;
   }

PKCS11_RSA_KeyPair generate_rsa_keypair(const TestSession& test_session)
   {
   RSA_PublicKeyGenerationProperties pub_props(2048UL);
   pub_props.set_pub_exponent();
   pub_props.set_label("BOTAN_TEST_RSA_PUB_KEY");
   pub_props.set_token(true);
   pub_props.set_encrypt(true);
   pub_props.set_verify(true);
   pub_props.set_private(false);

   RSA_PrivateKeyGenerationProperties priv_props;
   priv_props.set_label("BOTAN_TEST_RSA_PRIV_KEY");
   priv_props.set_token(true);
   priv_props.set_private(true);
   priv_props.set_sign(true);
   priv_props.set_decrypt(true);

   return PKCS11::generate_rsa_keypair(test_session.session(), pub_props, priv_props);
   }

Test::Result test_rsa_generate_key_pair()
   {
   Test::Result result("PKCS11 generate RSA key pair");
   TestSession test_session(true);

   PKCS11_RSA_KeyPair keypair = generate_rsa_keypair(test_session);
   result.test_success("RSA key pair generation was successful");

   keypair.first.destroy();
   keypair.second.destroy();

   return result;
   }

Test::Result test_rsa_encrypt_decrypt()
   {
   Test::Result result("PKCS11 RSA encrypt decrypt");
   TestSession test_session(true);

   // generate key pair
   PKCS11_RSA_KeyPair keypair = generate_rsa_keypair(test_session);

   auto encrypt_and_decrypt = [&keypair, &result](const std::vector<byte>& plaintext, const std::string& padding) -> void
      {
      Botan::PK_Encryptor_EME encryptor(keypair.first, padding, "pkcs11");
      auto encrypted = encryptor.encrypt(plaintext, Test::rng());

      Botan::PK_Decryptor_EME decryptor(keypair.second, padding, "pkcs11");
      auto decrypted = decryptor.decrypt(encrypted);

      // some token / middlewares do not remove the padding bytes
      decrypted.resize(plaintext.size());

      result.test_eq("RSA PKCS11 encrypt and decrypt: " + padding, decrypted, plaintext);
      };

   std::vector<byte> plaintext(256);
   std::iota(std::begin(plaintext), std::end(plaintext), 0);
   encrypt_and_decrypt(plaintext, "Raw");

   plaintext = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x00 };
   encrypt_and_decrypt(plaintext, "EME-PKCS1-v1_5");

   encrypt_and_decrypt(plaintext, "OAEP(SHA-1)");

   keypair.first.destroy();
   keypair.second.destroy();

   return result;
   }

Test::Result test_rsa_sign_verify()
   {
   Test::Result result("PKCS11 RSA sign and verify");
   TestSession test_session(true);

   // generate key pair
   PKCS11_RSA_KeyPair keypair = generate_rsa_keypair(test_session);

   std::vector<byte> plaintext(256);
   std::iota(std::begin(plaintext), std::end(plaintext), 0);

   auto sign_and_verify = [&keypair, &plaintext, &result](const std::string& emsa, bool multipart) -> void
      {
      Botan::PK_Signer signer(keypair.second, emsa, Botan::IEEE_1363, "pkcs11");
      std::vector<byte> signature;
      if ( multipart )
         {
         signer.update(plaintext.data(), plaintext.size() / 2);
         signature = signer.sign_message(plaintext.data() + plaintext.size() / 2, plaintext.size() / 2, Test::rng());
         }
      else
         {
         signature = signer.sign_message(plaintext, Test::rng());
         }


      Botan::PK_Verifier verifier(keypair.first, emsa, Botan::IEEE_1363, "pkcs11");
      bool rsa_ok = false;
      if ( multipart )
         {
         verifier.update(plaintext.data(), plaintext.size() / 2);
         rsa_ok = verifier.verify_message(plaintext.data() + plaintext.size() / 2, plaintext.size() / 2, signature.data(), signature.size());
         }
      else
         {
         rsa_ok = verifier.verify_message(plaintext, signature);
         }

      result.test_eq("RSA PKCS11 sign and verify: " + emsa, rsa_ok, true);
      };

   // single-part sign
   sign_and_verify("Raw", false);
   sign_and_verify("EMSA3(SHA-256)", false);
   sign_and_verify("EMSA4(SHA-256)", false);

   // multi-part sign
   sign_and_verify("EMSA3(SHA-256)", true);
   sign_and_verify("EMSA4(SHA-256)", true);

   keypair.first.destroy();
   keypair.second.destroy();

   return result;
   }

class PKCS11_RSA_Tests : public PKCS11_Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<std::function<Test::Result()>> fns =
            {
            test_rsa_privkey_import,
            test_rsa_pubkey_import,
            test_rsa_privkey_export,
            test_rsa_generate_private_key,
            test_rsa_generate_key_pair,
            test_rsa_encrypt_decrypt,
            test_rsa_sign_verify
            };

         return run_pkcs11_tests("PKCS11 RSA", fns);
         }
   };

BOTAN_REGISTER_TEST("pkcs11-rsa", PKCS11_RSA_Tests);
#endif

/***************************** PKCS11 ECDSA *****************************/

#if defined(BOTAN_HAS_ECC_PUBLIC_KEY_CRYPTO)

Test::Result test_ecdsa_privkey_import()
   {
   Test::Result result("PKCS11 import ECDSA private key");

   TestSession test_session(true);

   // create ecdsa private key
   ECDSA_PrivateKey priv_key(Test::rng(), EC_Group("secp256r1"));
   priv_key.set_parameter_encoding(EC_Group_Encoding::EC_DOMPAR_ENC_OID);

   // import to card
   EC_PrivateKeyImportProperties props(priv_key.DER_domain(), priv_key.private_value());
   props.set_token(true);
   props.set_private(true);
   props.set_sign(true);

   // label
   std::string label = "Botan test ecdsa key";
   props.set_label(label);

   PKCS11_ECDSA_PrivateKey pk(test_session.session(), props);
   result.test_success("ECDSA private key import was successful");

   pk.destroy();
   return result;
   }

Test::Result test_ecdsa_privkey_export()
   {
   Test::Result result("PKCS11 export ECDSA private key");

   TestSession test_session(true);

   // create private key
   ECDSA_PrivateKey priv_key(Test::rng(), EC_Group("secp256r1"));
   priv_key.set_parameter_encoding(EC_Group_Encoding::EC_DOMPAR_ENC_OID);

   // import to card
   EC_PrivateKeyImportProperties props(priv_key.DER_domain(), priv_key.private_value());
   props.set_token(true);
   props.set_private(true);
   props.set_sign(true);
   props.set_extractable(true);

   // label
   std::string label = "Botan test ecdsa key";
   props.set_label(label);

   PKCS11_ECDSA_PrivateKey pk(test_session.session(), props);

   ECDSA_PrivateKey exported = pk.export_key();
   result.test_success("ECDSA private key export was successful");

   pk.destroy();
   return result;
   }

Test::Result test_ecdsa_pubkey_import()
   {
   Test::Result result("PKCS11 import ECDSA public key");

   TestSession test_session(true);

   // create ecdsa private key
   ECDSA_PrivateKey priv_key(Test::rng(), EC_Group("secp256r1"));
   priv_key.set_parameter_encoding(EC_Group_Encoding::EC_DOMPAR_ENC_OID);

   // import to card
   EC_PublicKeyImportProperties props(priv_key.DER_domain(), DER_Encoder().encode(EC2OSP(priv_key.public_point(),
                                      PointGFp::UNCOMPRESSED), OCTET_STRING).get_contents_unlocked());
   props.set_token(true);
   props.set_verify(true);
   props.set_private(false);

   // label
   std::string label = "Botan test ecdsa pub key";
   props.set_label(label);

   PKCS11_ECDSA_PublicKey pk(test_session.session(), props);
   result.test_success("ECDSA public key import was successful");

   pk.destroy();
   return result;
   }

Test::Result test_ecdsa_pubkey_export()
   {
   Test::Result result("PKCS11 export ECDSA public key");

   TestSession test_session(true);

   // create public key from private key
   ECDSA_PrivateKey priv_key(Test::rng(), EC_Group("secp256r1"));
   priv_key.set_parameter_encoding(EC_Group_Encoding::EC_DOMPAR_ENC_OID);

   // import to card
   EC_PublicKeyImportProperties props(priv_key.DER_domain(), DER_Encoder().encode(EC2OSP(priv_key.public_point(),
                                      PointGFp::UNCOMPRESSED), OCTET_STRING).get_contents_unlocked());
   props.set_token(true);
   props.set_verify(true);
   props.set_private(false);

   // label
   std::string label = "Botan test ecdsa pub key";
   props.set_label(label);

   PKCS11_ECDSA_PublicKey pk(test_session.session(), props);

   ECDSA_PublicKey exported = pk.export_key();
   result.test_success("ECDSA public key export was successful");

   pk.destroy();

   return result;
   }

Test::Result test_ecdsa_generate_private_key()
   {
   Test::Result result("PKCS11 generate ECDSA private key");
   TestSession test_session(true);

   EC_PrivateKeyGenerationProperties props;
   props.set_token(true);
   props.set_private(true);
   props.set_sign(true);

   PKCS11_ECDSA_PrivateKey pk(test_session.session(),
                              EC_Group("secp256r1").DER_encode(EC_Group_Encoding::EC_DOMPAR_ENC_OID), props);
   result.test_success("ECDSA private key generation was successful");

   pk.destroy();

   return result;
   }

PKCS11_ECDSA_KeyPair generate_ecdsa_keypair(const TestSession& test_session)
   {
   EC_PublicKeyGenerationProperties pub_props(EC_Group("secp256r1").DER_encode(
            EC_Group_Encoding::EC_DOMPAR_ENC_OID));
   pub_props.set_label("BOTAN_TEST_ECDSA_PUB_KEY");
   pub_props.set_token(true);
   pub_props.set_verify(true);
   pub_props.set_private(false);
   pub_props.set_modifiable(true);

   EC_PrivateKeyGenerationProperties priv_props;
   priv_props.set_label("BOTAN_TEST_ECDSA_PRIV_KEY");
   priv_props.set_token(true);
   priv_props.set_private(true);
   priv_props.set_sensitive(true);
   priv_props.set_extractable(false);
   priv_props.set_sign(true);
   priv_props.set_modifiable(true);

   return PKCS11::generate_ecdsa_keypair(test_session.session(), pub_props, priv_props);
   }

Test::Result test_ecdsa_generate_keypair()
   {
   Test::Result result("PKCS11 generate ECDSA key pair");
   TestSession test_session(true);

   PKCS11_ECDSA_KeyPair keypair = generate_ecdsa_keypair(test_session);
   result.test_success("ECDSA key pair generation was successful");

   keypair.first.destroy();
   keypair.second.destroy();

   return result;
   }

Test::Result test_ecdsa_sign_verify()
   {
   Test::Result result("PKCS11 ECDSA sign and verify");
   TestSession test_session(true);

   // generate key pair
   PKCS11_ECDSA_KeyPair keypair = generate_ecdsa_keypair(test_session);

   std::vector<byte> plaintext(20, 0x01);

   auto sign_and_verify = [ &keypair, &plaintext, &result ](const std::string& emsa) -> void
      {
      Botan::PK_Signer signer(keypair.second, emsa, Botan::IEEE_1363, "pkcs11");
      auto signature = signer.sign_message(plaintext, Test::rng());

      Botan::PK_Verifier token_verifier(keypair.first, emsa, Botan::IEEE_1363, "pkcs11");
      bool ecdsa_ok = token_verifier.verify_message(plaintext, signature);

      result.test_eq("ECDSA PKCS11 sign and verify: " + emsa, ecdsa_ok, true);

// test against software implementation if available
#if defined (BOTAN_HAS_EMSA_RAW)
      Botan::PK_Verifier soft_verifier(keypair.first, emsa, Botan::IEEE_1363);
      bool soft_ecdsa_ok = soft_verifier.verify_message(plaintext, signature);

      result.test_eq("ECDSA PKCS11 verify (in software): " + emsa, soft_ecdsa_ok, true);
#endif
      };

   sign_and_verify("Raw");   // SoftHSMv2 until now only supports "Raw"

   keypair.first.destroy();
   keypair.second.destroy();

   return result;
   }

class PKCS11_ECDSA_Tests : public PKCS11_Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<std::function<Test::Result()>> fns =
            {
            test_ecdsa_privkey_import,
            test_ecdsa_privkey_export,
            test_ecdsa_pubkey_import,
            test_ecdsa_pubkey_export,
            test_ecdsa_generate_private_key,
            test_ecdsa_generate_keypair,
            test_ecdsa_sign_verify
            };

         return run_pkcs11_tests("PKCS11 ECDSA", fns);
         }
   };

BOTAN_REGISTER_TEST("pkcs11-ecdsa", PKCS11_ECDSA_Tests);

/***************************** PKCS11 ECDH *****************************/

Test::Result test_ecdh_privkey_import()
   {
   Test::Result result("PKCS11 import ECDH private key");

   TestSession test_session(true);

   // create ecdh private key
   ECDH_PrivateKey priv_key(Test::rng(), EC_Group("secp256r1"));
   priv_key.set_parameter_encoding(EC_Group_Encoding::EC_DOMPAR_ENC_OID);

   // import to card
   EC_PrivateKeyImportProperties props(priv_key.DER_domain(), priv_key.private_value());
   props.set_token(true);
   props.set_private(true);
   props.set_derive(true);

   // label
   std::string label = "Botan test ecdh key";
   props.set_label(label);

   PKCS11_ECDH_PrivateKey pk(test_session.session(), props);
   result.test_success("ECDH private key import was successful");

   pk.destroy();
   return result;
   }

Test::Result test_ecdh_privkey_export()
   {
   Test::Result result("PKCS11 export ECDH private key");

   TestSession test_session(true);

   // create private key
   ECDH_PrivateKey priv_key(Test::rng(), EC_Group("secp256r1"));
   priv_key.set_parameter_encoding(EC_Group_Encoding::EC_DOMPAR_ENC_OID);

   // import to card
   EC_PrivateKeyImportProperties props(priv_key.DER_domain(), priv_key.private_value());
   props.set_token(true);
   props.set_private(true);
   props.set_derive(true);
   props.set_extractable(true);

   // label
   std::string label = "Botan test ecdh key";
   props.set_label(label);

   PKCS11_ECDH_PrivateKey pk(test_session.session(), props);

   ECDH_PrivateKey exported = pk.export_key();
   result.test_success("ECDH private key export was successful");

   pk.destroy();
   return result;
   }

Test::Result test_ecdh_pubkey_import()
   {
   Test::Result result("PKCS11 import ECDH public key");

   TestSession test_session(true);

   // create ECDH private key
   ECDH_PrivateKey priv_key(Test::rng(), EC_Group("secp256r1"));
   priv_key.set_parameter_encoding(EC_Group_Encoding::EC_DOMPAR_ENC_OID);

   // import to card
   EC_PublicKeyImportProperties props(priv_key.DER_domain(), DER_Encoder().encode(EC2OSP(priv_key.public_point(),
                                      PointGFp::UNCOMPRESSED), OCTET_STRING).get_contents_unlocked());
   props.set_token(true);
   props.set_private(false);
   props.set_derive(true);

   // label
   std::string label = "Botan test ECDH pub key";
   props.set_label(label);

   PKCS11_ECDH_PublicKey pk(test_session.session(), props);
   result.test_success("ECDH public key import was successful");

   pk.destroy();
   return result;
   }

Test::Result test_ecdh_pubkey_export()
   {
   Test::Result result("PKCS11 export ECDH public key");

   TestSession test_session(true);

   // create public key from private key
   ECDH_PrivateKey priv_key(Test::rng(), EC_Group("secp256r1"));
   priv_key.set_parameter_encoding(EC_Group_Encoding::EC_DOMPAR_ENC_OID);

   // import to card
   EC_PublicKeyImportProperties props(priv_key.DER_domain(), DER_Encoder().encode(EC2OSP(priv_key.public_point(),
                                      PointGFp::UNCOMPRESSED), OCTET_STRING).get_contents_unlocked());
   props.set_token(true);
   props.set_derive(true);
   props.set_private(false);

   // label
   std::string label = "Botan test ECDH pub key";
   props.set_label(label);

   PKCS11_ECDH_PublicKey pk(test_session.session(), props);

   ECDH_PublicKey exported = pk.export_key();
   result.test_success("ECDH public key export was successful");

   pk.destroy();

   return result;
   }

Test::Result test_ecdh_generate_private_key()
   {
   Test::Result result("PKCS11 generate ECDH private key");
   TestSession test_session(true);

   EC_PrivateKeyGenerationProperties props;
   props.set_token(true);
   props.set_private(true);
   props.set_derive(true);

   PKCS11_ECDH_PrivateKey pk(test_session.session(),
                             EC_Group("secp256r1").DER_encode(EC_Group_Encoding::EC_DOMPAR_ENC_OID), props);
   result.test_success("ECDH private key generation was successful");

   pk.destroy();

   return result;
   }

PKCS11_ECDH_KeyPair generate_ecdh_keypair(const TestSession& test_session, const std::string& label)
   {
   EC_PublicKeyGenerationProperties pub_props(EC_Group("secp256r1").DER_encode(
            EC_Group_Encoding::EC_DOMPAR_ENC_OID));
   pub_props.set_label(label + "_PUB_KEY");
   pub_props.set_token(true);
   pub_props.set_derive(true);
   pub_props.set_private(false);
   pub_props.set_modifiable(true);

   EC_PrivateKeyGenerationProperties priv_props;
   priv_props.set_label(label + "_PRIV_KEY");
   priv_props.set_token(true);
   priv_props.set_private(true);
   priv_props.set_sensitive(true);
   priv_props.set_extractable(false);
   priv_props.set_derive(true);
   priv_props.set_modifiable(true);

   return PKCS11::generate_ecdh_keypair(test_session.session(), pub_props, priv_props);
   }

Test::Result test_ecdh_generate_keypair()
   {
   Test::Result result("PKCS11 generate ECDH key pair");
   TestSession test_session(true);

   PKCS11_ECDH_KeyPair keypair = generate_ecdh_keypair(test_session, "Botan test ECDH key1");
   result.test_success("ECDH key pair generation was successful");

   keypair.first.destroy();
   keypair.second.destroy();

   return result;
   }

Test::Result test_ecdh_derive()
   {
   Test::Result result("PKCS11 ECDH derive");
   TestSession test_session(true);

   PKCS11_ECDH_KeyPair keypair = generate_ecdh_keypair(test_session, "Botan test ECDH key1");
   PKCS11_ECDH_KeyPair keypair2 = generate_ecdh_keypair(test_session, "Botan test ECDH key2");

   // SoftHSMv2 only supports CKD_NULL KDF at the moment
   Botan::PK_Key_Agreement ka(keypair.second, "Raw", "pkcs11");
   Botan::PK_Key_Agreement kb(keypair2.second, "Raw", "pkcs11");

   Botan::SymmetricKey alice_key = ka.derive_key(32, unlock(EC2OSP(keypair2.first.public_point(),
                                   PointGFp::UNCOMPRESSED)));
   Botan::SymmetricKey bob_key = kb.derive_key(32, unlock(EC2OSP(keypair.first.public_point(), PointGFp::UNCOMPRESSED)));

   bool eq = alice_key == bob_key;
   result.test_eq("same secret key derived", eq, true);

   keypair.first.destroy();
   keypair.second.destroy();
   keypair2.first.destroy();
   keypair2.second.destroy();

   return result;
   }

class PKCS11_ECDH_Tests : public PKCS11_Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<std::function<Test::Result()>> fns =
            {
            test_ecdh_privkey_import,
            test_ecdh_privkey_export,
            test_ecdh_pubkey_import,
            test_ecdh_pubkey_export,
            test_ecdh_generate_private_key,
            test_ecdh_generate_keypair,
            test_ecdh_derive
            };

         return run_pkcs11_tests("PKCS11 ECDH", fns);
         }
   };

BOTAN_REGISTER_TEST("pkcs11-ecdh", PKCS11_ECDH_Tests);

#endif

/***************************** PKCS11 RNG *****************************/

Test::Result test_rng_generate_random()
   {
   Test::Result result("PKCS11 RNG generate random");
   TestSession test_session(true);

   PKCS11_RNG rng(test_session.session());

   std::vector<byte> random(20);
   rng.randomize(random.data(), random.size());
   result.test_ne("random data generated", random, std::vector<byte>(20));

   return result;
   }

Test::Result test_rng_add_entropy()
   {
   Test::Result result("PKCS11 RNG add entropy random");
   TestSession test_session(true);

   PKCS11_RNG rng(test_session.session());

   auto random = Test::rng().random_vec(20);
   rng.add_entropy(random.data(), random.size());
   result.test_success("entropy added");

   return result;
   }

#if defined(BOTAN_HAS_HMAC_DRBG) && defined(BOTAN_HAS_SHA2_64)

Test::Result test_pkcs11_hmac_drbg()
   {
   Test::Result result("PKCS11 HMAC_DRBG using PKCS11_RNG");
   TestSession test_session(true);

   PKCS11_RNG p11_rng(test_session.session());
   HMAC_DRBG drbg(MessageAuthenticationCode::create("HMAC(SHA-512)"), p11_rng);
   // result.test_success("HMAC_DRBG(HMAC(SHA512)) instantiated with PKCS11_RNG");

   result.test_eq("HMAC_DRBG is not seeded yet.", drbg.is_seeded(), false);
   secure_vector<byte> rnd = drbg.random_vec(64);
   result.test_eq("HMAC_DRBG is seeded now", drbg.is_seeded(), true);

   std::string personalization_string = "Botan PKCS#11 Tests";
   std::vector<byte> personalization_data(personalization_string.begin(), personalization_string.end());
   drbg.add_entropy(personalization_data.data(), personalization_data.size());

   auto rnd_vec = drbg.random_vec(256);
   result.test_ne("HMAC_DRBG generated a random vector", rnd_vec, std::vector<byte>(256));

   return result;
   }
#endif

class PKCS11_RNG_Tests : public PKCS11_Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<std::function<Test::Result()>> fns =
            {
            test_rng_generate_random
            ,test_rng_add_entropy
#if defined(BOTAN_HAS_HMAC_DRBG )&& defined(BOTAN_HAS_SHA2_64)
            ,test_pkcs11_hmac_drbg
#endif
            };

         return run_pkcs11_tests("PKCS11 RNG", fns);
         }
   };

BOTAN_REGISTER_TEST("pkcs11-rng", PKCS11_RNG_Tests);

/***************************** PKCS11 token management *****************************/

Test::Result test_set_pin()
   {
   Test::Result result("PKCS11 set pin");

   Module module(Test::pkcs11_lib());
   std::vector<SlotId> slot_vec = Slot::get_available_slots(module, true);
   Slot slot(module, slot_vec.at(0));

   PKCS11::set_pin(slot, SO_PIN_SECVEC, TEST_PIN_SECVEC);
   result.test_success("PIN set with SO_PIN to TEST_PIN");

   PKCS11::set_pin(slot, SO_PIN_SECVEC, PIN_SECVEC);
   result.test_success("PIN changed back with SO_PIN");

   return result;
   }

Test::Result test_initialize()
   {
   Test::Result result("PKCS11 initialize token");

   Module module(Test::pkcs11_lib());
   std::vector<SlotId> slot_vec = Slot::get_available_slots(module, true);
   Slot slot(module, slot_vec.at(0));

   PKCS11::initialize_token(slot, "Botan PKCS#11 tests", SO_PIN_SECVEC, PIN_SECVEC);
   result.test_success("token initialized");

   return result;
   }

Test::Result test_change_pin()
   {
   Test::Result result("PKCS11 change pin");

   Module module(Test::pkcs11_lib());
   std::vector<SlotId> slot_vec = Slot::get_available_slots(module, true);
   Slot slot(module, slot_vec.at(0));

   PKCS11::change_pin(slot, PIN_SECVEC, TEST_PIN_SECVEC);
   result.test_success("PIN changed with PIN to TEST_PIN");

   PKCS11::change_pin(slot, TEST_PIN_SECVEC, PIN_SECVEC);
   result.test_success("PIN changed back with TEST_PIN to PIN");

   return result;
   }

Test::Result test_change_so_pin()
   {
   Test::Result result("PKCS11 change so_pin");

   Module module(Test::pkcs11_lib());
   std::vector<SlotId> slot_vec = Slot::get_available_slots(module, true);
   Slot slot(module, slot_vec.at(0));

   PKCS11::change_so_pin(slot, SO_PIN_SECVEC, TEST_SO_PIN_SECVEC);
   result.test_success("SO_PIN changed with SO_PIN to TEST_SO_PIN");

   PKCS11::change_so_pin(slot, TEST_SO_PIN_SECVEC, SO_PIN_SECVEC);
   result.test_success("SO_PIN changed back with TEST_SO_PIN to SO_PIN");

   return result;
   }

class PKCS11_Token_Management_Tests : public PKCS11_Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<std::function<Test::Result()>> fns =
            {
            test_set_pin,
            test_initialize,
            test_change_pin,
            test_change_so_pin
            };

         return run_pkcs11_tests("PKCS11 token management", fns);
         }
   };

BOTAN_REGISTER_TEST("pkcs11-manage", PKCS11_Token_Management_Tests);

/***************************** PKCS11 token management *****************************/

#if defined(BOTAN_HAS_X509_CERTIFICATES)

Test::Result test_x509_import()
   {
   Test::Result result("PKCS11 X509 cert import");

   TestSession test_session(true);

   X509_Certificate root(Test::data_file("nist_x509/test01/end.crt"));
   X509_CertificateProperties props(DER_Encoder().encode(root.subject_dn()).get_contents_unlocked(), root.BER_encode());
   props.set_label("Botan PKCS#11 test certificate");
   props.set_private(false);
   props.set_token(true);

   PKCS11_X509_Certificate pkcs11_cert(test_session.session(), props);
   result.test_success("X509 certificate imported");

   PKCS11_X509_Certificate pkcs11_cert2(test_session.session(), pkcs11_cert.handle());
   result.test_eq("X509 certificate by handle", pkcs11_cert == pkcs11_cert2, true);

   pkcs11_cert.destroy();

   return result;
   }

class PKCS11_X509_Tests : public PKCS11_Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<std::function<Test::Result()>> fns =
            {
            test_x509_import
            };

         return run_pkcs11_tests("PKCS11 X509", fns);
         }
   };

BOTAN_REGISTER_TEST("pkcs11-x509", PKCS11_X509_Tests);

#endif

#endif

}
}
