/*
* (C) 2016 Daniel Neus
* (C) 2016 Philipp Weber
* (C) 2019 Michael Boric
* (C) 2020 René Korthaus
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "test_pkcs11.h"
#include "tests.h"

#include <memory>
#include <numeric>
#include <sstream>
#include <string>
#include <vector>

#if defined(BOTAN_HAS_PKCS11)
   #include <botan/p11.h>
   #include <botan/p11_object.h>
   #include <botan/p11_randomgenerator.h>
#endif

#if defined(BOTAN_HAS_ASN1)
   #include <botan/der_enc.h>
#endif

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)
   #include <botan/pubkey.h>
#endif

#if defined(BOTAN_HAS_ECC_GROUP)
   #include <botan/ec_group.h>
#endif

#if defined(BOTAN_HAS_RSA) && defined(BOTAN_HAS_PKCS11)
   #include <botan/p11_rsa.h>
   #include <botan/rsa.h>
#endif

#if defined(BOTAN_HAS_ECDSA) && defined(BOTAN_HAS_PKCS11)
   #include <botan/ecdsa.h>
   #include <botan/p11_ecdsa.h>
#endif

#if defined(BOTAN_HAS_ECDH) && defined(BOTAN_HAS_PKCS11)
   #include <botan/ecdh.h>
   #include <botan/p11_ecdh.h>
#endif

#if defined(BOTAN_HAS_X509_CERTIFICATES) && defined(BOTAN_HAS_PKCS11)
   #include <botan/p11_x509.h>
   #include <botan/pkix_types.h>
#endif

#if defined(BOTAN_HAS_HMAC_DRBG)
   #include <botan/hmac_drbg.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_PKCS11)

std::vector<Test::Result> run_pkcs11_tests(const std::string& name,
                                           std::vector<std::pair<std::string, std::function<Test::Result()>>>& fns) {
   std::vector<Test::Result> results;

   for(size_t i = 0; i != fns.size(); ++i) {
      try {
         results.push_back(fns[i].second());
      } catch(Botan::PKCS11::PKCS11_ReturnError& e) {
         results.push_back(Test::Result::Failure(name + " test " + fns[i].first, e.what()));

         if(e.get_return_value() == Botan::PKCS11::ReturnValue::PinIncorrect) {
            break;  // Do not continue to not potentially lock the token
         }
      } catch(std::exception& e) {
         results.push_back(Test::Result::Failure(name + " test " + fns[i].first, e.what()));
      }
   }

   return results;
}

namespace {

using namespace Botan;
using namespace PKCS11;

class TestSession {
   public:
      explicit TestSession(bool login) : m_module(new Module(Test::pkcs11_lib())) {
         std::vector<SlotId> slot_vec = Slot::get_available_slots(*m_module, true);
         m_slot = std::make_unique<Slot>(*m_module, slot_vec.at(0));
         m_session = std::make_unique<Session>(*m_slot, false);
         if(login) {
            m_session->login(UserType::User, PIN());
         }
      }

      Session& session() const { return *m_session; }

      Slot& slot() const { return *m_slot; }

   private:
      std::unique_ptr<Module> m_module = nullptr;
      std::unique_ptr<Slot> m_slot = nullptr;
      std::unique_ptr<Session> m_session = nullptr;
};

/***************************** Module *****************************/

Test::Result test_module_ctor() {
   Test::Result result("Module ctor");

   result.test_throws("Module ctor fails for non existent path", []() { Module failing_module("/a/b/c"); });

   Module module(Test::pkcs11_lib());
   result.test_success("Module ctor did not throw and completed successfully");

   return result;
}

Test::Result test_module_reload() {
   Test::Result result("Module reload");

   Module module(Test::pkcs11_lib());

   module.reload();
   result.test_success("Module reload did not throw and completed successfully");

   module.get_info();
   result.test_success("Module get_info() still works after reload");

   return result;
}

Test::Result test_multiple_modules() {
   Test::Result result("Module copy");
   Module first_module(Test::pkcs11_lib());

   result.test_throws("Module ctor fails if module is already initialized",
                      []() { Module second_module(Test::pkcs11_lib()); });

   return result;
}

Test::Result test_module_get_info() {
   Test::Result result("Module info");

   Module module(Test::pkcs11_lib());

   Info info = module.get_info();
   result.test_ne("Cryptoki version != 0", info.cryptokiVersion.major, 0);

   return result;
}

class Module_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<std::pair<std::string, std::function<Test::Result()>>> fns = {
            {STRING_AND_FUNCTION(test_module_ctor)},
            {STRING_AND_FUNCTION(test_multiple_modules)},
            {STRING_AND_FUNCTION(test_module_get_info)},
            {STRING_AND_FUNCTION(test_module_reload)}};

         return run_pkcs11_tests("Module", fns);
      }
};

BOTAN_REGISTER_SERIALIZED_TEST("pkcs11", "pkcs11-module", Module_Tests);

/***************************** Slot *****************************/

Test::Result test_slot_get_available_slots() {
   Test::Result result("Slot get_available_slots");

   Module module(Test::pkcs11_lib());
   std::vector<SlotId> slot_vec = Slot::get_available_slots(module, true);
   result.test_gte("Available Slots with attached token >= 1", slot_vec.size(), 1);

   return result;
}

Test::Result test_slot_ctor() {
   Test::Result result("Slot ctor");

   Module module(Test::pkcs11_lib());
   std::vector<SlotId> slot_vec = Slot::get_available_slots(module, true);

   Slot slot(module, slot_vec.at(0));
   result.test_success("Slot ctor completed successfully");
   result.test_is_eq(slot.slot_id(), slot_vec.at(0));

   return result;
}

Test::Result test_get_slot_info() {
   Test::Result result("Slot get_slot_info");

   Module module(Test::pkcs11_lib());
   std::vector<SlotId> slot_vec = Slot::get_available_slots(module, true);
   Slot slot(module, slot_vec.at(0));

   SlotInfo info = slot.get_slot_info();
   std::string description = reinterpret_cast<char*>(info.slotDescription);
   result.confirm("Slot description is not empty", !description.empty());

   return result;
}

SlotId get_invalid_slot_id(Module& module) {
   std::vector<SlotId> slot_vec = Slot::get_available_slots(module, false);

   SlotId invalid_id = 0;

   // find invalid slot id
   while(std::find(slot_vec.begin(), slot_vec.end(), invalid_id) != slot_vec.end()) {
      invalid_id++;
   }

   return invalid_id;
}

Test::Result test_slot_invalid_id() {
   Test::Result result("Slot get_slot_info with invalid slot id");

   Module module(Test::pkcs11_lib());

   SlotId invalid_id = get_invalid_slot_id(module);

   Slot slot(module, invalid_id);

   result.test_throws("get_slot_info fails for non existent slot id", [&slot]() { slot.get_slot_info(); });

   return result;
}

Test::Result test_get_token_info() {
   Test::Result result("Slot get_token_info");

   Module module(Test::pkcs11_lib());
   std::vector<SlotId> slot_vec = Slot::get_available_slots(module, true);
   Slot slot(module, slot_vec.at(0));

   TokenInfo info = slot.get_token_info();
   std::string label = reinterpret_cast<char*>(info.label);
   result.confirm("Token label is not empty", !label.empty());

   return result;
}

Test::Result test_get_mechanism_list() {
   Test::Result result("Slot get_mechanism_list");

   Module module(Test::pkcs11_lib());
   std::vector<SlotId> slot_vec = Slot::get_available_slots(module, true);
   Slot slot(module, slot_vec.at(0));

   std::vector<MechanismType> mechanisms = slot.get_mechanism_list();
   result.confirm("The Slot supports at least one mechanism", !mechanisms.empty());

   return result;
}

Test::Result test_get_mechanisms_info() {
   Test::Result result("Slot get_mechanism_info");

   Module module(Test::pkcs11_lib());
   std::vector<SlotId> slot_vec = Slot::get_available_slots(module, true);
   Slot slot(module, slot_vec.at(0));

   slot.get_mechanism_info(MechanismType::RsaPkcsKeyPairGen);
   result.test_success("get_mechanism_info() completed successfully.");

   return result;
}

class Slot_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<std::pair<std::string, std::function<Test::Result()>>> fns = {
            {STRING_AND_FUNCTION(test_slot_get_available_slots)},
            {STRING_AND_FUNCTION(test_slot_ctor)},
            {STRING_AND_FUNCTION(test_get_slot_info)},
            {STRING_AND_FUNCTION(test_slot_invalid_id)},
            {STRING_AND_FUNCTION(test_get_token_info)},
            {STRING_AND_FUNCTION(test_get_mechanism_list)},
            {STRING_AND_FUNCTION(test_get_mechanisms_info)}};

         return run_pkcs11_tests("Slot", fns);
      }
};

BOTAN_REGISTER_SERIALIZED_TEST("pkcs11", "pkcs11-slot", Slot_Tests);

/***************************** Session *****************************/

Test::Result test_session_ctor() {
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

Test::Result test_session_ctor_invalid_slot() {
   Test::Result result("Session ctor with invalid slot id");

   Module module(Test::pkcs11_lib());

   SlotId invalid_id = get_invalid_slot_id(module);
   Slot slot(module, invalid_id);

   result.test_throws("Session ctor with invalid slot id fails", [&slot]() { Session session(slot, true); });

   return result;
}

Test::Result test_session_release() {
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

Test::Result test_session_login_logout() {
   Test::Result result("Session login/logout");

   Module module(Test::pkcs11_lib());
   std::vector<SlotId> slot_vec = Slot::get_available_slots(module, true);
   Slot slot(module, slot_vec.at(0));

   Session session(slot, false);
   session.login(UserType::User, PIN());
   session.logoff();
   result.test_success("user login/logout succeeded");

   session.login(UserType::SO, SO_PIN());
   result.test_success("SO login succeeded");

   return result;
}

Test::Result test_session_info() {
   Test::Result result("Session session info");

   Module module(Test::pkcs11_lib());
   std::vector<SlotId> slot_vec = Slot::get_available_slots(module, true);
   Slot slot(module, slot_vec.at(0));

   Session session(slot, false);
   SessionInfo info = session.get_info();
   result.test_is_eq("slot id is correct", info.slotID, slot_vec.at(0));
   result.test_is_eq(
      "state is a read write public session", info.state, static_cast<CK_STATE>(SessionState::RwPublicSession));

   session.login(UserType::User, PIN());
   info = session.get_info();
   result.test_is_eq(
      "state is a read write user session", info.state, static_cast<CK_STATE>(SessionState::RwUserFunctions));

   session.logoff();
   result.test_success("user login/logout succeeded");

   session.login(UserType::SO, SO_PIN());
   result.test_success("SO login succeeded");

   return result;
}

class Session_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<std::pair<std::string, std::function<Test::Result()>>> fns = {
            {STRING_AND_FUNCTION(test_session_ctor)},
            {STRING_AND_FUNCTION(test_session_ctor_invalid_slot)},
            {STRING_AND_FUNCTION(test_session_release)},
            {STRING_AND_FUNCTION(test_session_login_logout)},
            {STRING_AND_FUNCTION(test_session_info)}};

         return run_pkcs11_tests("Session", fns);
      }
};

BOTAN_REGISTER_SERIALIZED_TEST("pkcs11", "pkcs11-session", Session_Tests);

/***************************** Object *****************************/

Test::Result test_attribute_container() {
   Test::Result result("AttributeContainer");

   AttributeContainer attributes;
   attributes.add_class(ObjectClass::PrivateKey);

   std::string label("test");
   attributes.add_string(AttributeType::Label, label);

   std::vector<uint8_t> bin(4);
   attributes.add_binary(AttributeType::Value, bin);

   attributes.add_bool(AttributeType::Sensitive, true);
   attributes.add_numeric(AttributeType::ObjectId, 10);
   attributes.add_numeric(AttributeType::Id, 20);
   attributes.add_numeric(AttributeType::PixelX, 30);
   // Test that overwriting the existing Id attribute works. The numeric attributes above should not be affected by this.
   attributes.add_numeric(AttributeType::Id, 21);
   attributes.add_numeric(AttributeType::PixelY, 40);

   result.test_eq("8 elements in attribute container", attributes.count(), 8);

   const std::vector<Botan::PKCS11::Attribute>& storedAttributes = attributes.attributes();
   result.test_int_eq("ObjectId type", storedAttributes.at(4).type, AttributeType::ObjectId);
   result.test_int_eq("ObjectId value", *reinterpret_cast<uint64_t*>(storedAttributes.at(4).pValue), 10);
   result.test_int_eq("Id type", storedAttributes.at(5).type, AttributeType::Id);
   result.test_int_eq("Id value", *reinterpret_cast<uint64_t*>(storedAttributes.at(5).pValue), 21);
   result.test_int_eq("PixelX type", storedAttributes.at(6).type, AttributeType::PixelX);
   result.test_int_eq("PixelX value", *reinterpret_cast<uint64_t*>(storedAttributes.at(6).pValue), 30);
   result.test_int_eq("PixelY type", storedAttributes.at(7).type, AttributeType::PixelY);
   result.test_int_eq("PixelY value", *reinterpret_cast<uint64_t*>(storedAttributes.at(7).pValue), 40);

   return result;
}

DataObjectProperties make_test_object(const std::string& label) {
   std::string value_string("test data");
   secure_vector<uint8_t> value(value_string.begin(), value_string.end());

   std::size_t id = 1337;
   std::string application = "Botan test application";

   std::vector<uint8_t> encoded_id;
   DER_Encoder(encoded_id).encode(id);

   DataObjectProperties data_obj_props;
   data_obj_props.set_application(application);
   data_obj_props.set_label(label);
   data_obj_props.set_value(value);
   data_obj_props.set_token(true);
   data_obj_props.set_modifiable(true);
   data_obj_props.set_object_id(encoded_id);

   return data_obj_props;
}

   #if defined(BOTAN_HAS_ASN1)
Test::Result test_create_destroy_data_object() {
   Test::Result result("Object create/delete data object");

   TestSession test_session(true);

   const std::string label = "Botan test data object";
   auto data_obj_props = make_test_object(label);
   Object data_obj(test_session.session(), data_obj_props);
   result.test_success("Data object creation was successful");

   data_obj.destroy();
   result.test_success("Data object deletion  was successful");

   return result;
}

Test::Result test_get_set_attribute_values() {
   Test::Result result("Object get/set attributes");

   TestSession test_session(true);

   // create object
   const std::string label = "Botan test data object";
   auto data_obj_props = make_test_object(label);
   Object data_obj(test_session.session(), data_obj_props);

   // get attribute
   secure_vector<uint8_t> retrieved_label = data_obj.get_attribute_value(AttributeType::Label);
   std::string retrieved_label_string(retrieved_label.begin(), retrieved_label.end());
   result.test_eq("label was set correctly", retrieved_label_string, label);

   // set attribute
   std::string new_label = "Botan test modified data object label";
   secure_vector<uint8_t> new_label_secvec(new_label.begin(), new_label.end());
   data_obj.set_attribute_value(AttributeType::Label, new_label_secvec);

   // get and check attribute
   retrieved_label = data_obj.get_attribute_value(AttributeType::Label);
   retrieved_label_string = std::string(retrieved_label.begin(), retrieved_label.end());
   result.test_eq("label was modified correctly", retrieved_label_string, new_label);

   data_obj.destroy();
   return result;
}

Test::Result test_object_finder() {
   Test::Result result("ObjectFinder");

   TestSession test_session(true);

   // create object
   const std::string label = "Botan test data object";
   auto data_obj_props = make_test_object(label);
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
                  obj_found.get_attribute_value(AttributeType::Application),
                  data_obj.get_attribute_value(AttributeType::Application));

   auto search_result2 = Object::search<Object>(test_session.session(), search_template.attributes());
   result.test_eq("found the object just created (same label)",
                  obj_found.get_attribute_value(AttributeType::Label),
                  search_result2.at(0).get_attribute_value(AttributeType::Label));

   data_obj.destroy();
   return result;
}

Test::Result test_object_copy() {
   Test::Result result("Object copy");

   TestSession test_session(true);

   // create object
   const std::string label = "Botan test data object";
   auto data_obj_props = make_test_object(label);
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

class Object_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<std::pair<std::string, std::function<Test::Result()>>> fns = {
            {STRING_AND_FUNCTION(test_attribute_container)}
   #if defined(BOTAN_HAS_ASN1)
            ,
            {STRING_AND_FUNCTION(test_create_destroy_data_object)},
            {STRING_AND_FUNCTION(test_get_set_attribute_values)},
            {STRING_AND_FUNCTION(test_object_finder)},
            {STRING_AND_FUNCTION(test_object_copy)}
   #endif
         };

         return run_pkcs11_tests("Object", fns);
      }
};

BOTAN_REGISTER_SERIALIZED_TEST("pkcs11", "pkcs11-object", Object_Tests);

/***************************** PKCS11 RSA *****************************/

   #if defined(BOTAN_HAS_RSA)

Test::Result test_rsa_privkey_import() {
   Test::Result result("PKCS11 import RSA private key");

   TestSession test_session(true);

   auto rng = Test::new_rng(__func__);

   // create private key
   RSA_PrivateKey priv_key(*rng, 2048);
   result.confirm("Key self test OK", priv_key.check_key(*rng, true));

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
   result.confirm("PK self test OK", pk.check_key(*rng, true));

   pk.destroy();
   return result;
}

Test::Result test_rsa_privkey_export() {
   Test::Result result("PKCS11 export RSA private key");

   TestSession test_session(true);

   auto rng = Test::new_rng(__func__);

   // create private key
   RSA_PrivateKey priv_key(*rng, 2048);

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
   result.confirm("Check PK11 key", pk.check_key(*rng, true));

   RSA_PrivateKey exported = pk.export_key();
   result.test_success("RSA private key export was successful");
   result.confirm("Check exported key", exported.check_key(*rng, true));

   pk.destroy();
   return result;
}

Test::Result test_rsa_pubkey_import() {
   Test::Result result("PKCS11 import RSA public key");

   TestSession test_session(true);

   auto rng = Test::new_rng(__func__);

   // create public key from private key
   RSA_PrivateKey priv_key(*rng, 2048);

   // import to card
   RSA_PublicKeyImportProperties props(priv_key.get_n(), priv_key.get_e());
   props.set_token(true);
   props.set_encrypt(true);
   props.set_private(false);

   PKCS11_RSA_PublicKey pk(test_session.session(), props);
   result.test_success("RSA public key import was successful");
   result.confirm("Check PK11 key", pk.check_key(*rng, true));

   pk.destroy();

   return result;
}

Test::Result test_rsa_generate_private_key() {
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

PKCS11_RSA_KeyPair generate_rsa_keypair(const TestSession& test_session) {
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

Test::Result test_rsa_generate_key_pair() {
   Test::Result result("PKCS11 generate RSA key pair");
   TestSession test_session(true);

   PKCS11_RSA_KeyPair keypair = generate_rsa_keypair(test_session);
   result.test_success("RSA key pair generation was successful");

   keypair.first.destroy();
   keypair.second.destroy();

   return result;
}

Test::Result test_rsa_encrypt_decrypt() {
   Test::Result result("PKCS11 RSA encrypt decrypt");
   TestSession test_session(true);

   // generate key pair
   PKCS11_RSA_KeyPair keypair = generate_rsa_keypair(test_session);

   auto rng = Test::new_rng(__func__);

   auto encrypt_and_decrypt =
      [&](const std::vector<uint8_t>& plaintext, const std::string& padding, const bool blinding) {
         std::vector<uint8_t> encrypted;

         try {
            Botan::PK_Encryptor_EME encryptor(keypair.first, *rng, padding);
            encrypted = encryptor.encrypt(plaintext, *rng);
         } catch(Botan::PKCS11::PKCS11_ReturnError& e) {
            result.test_failure("PKCS11 RSA encrypt " + padding, e.what());
         }

         Botan::secure_vector<uint8_t> decrypted;

         try {
            keypair.second.set_use_software_padding(blinding);
            Botan::PK_Decryptor_EME decryptor(keypair.second, *rng, padding);
            decrypted = decryptor.decrypt(encrypted);
         } catch(Botan::PKCS11::PKCS11_ReturnError& e) {
            std::ostringstream err;
            err << "PKCS11 RSA decrypt " << padding;
            if(blinding) {
               err << " with userspace blinding";
            }

            result.test_failure(err.str(), e.what());
         }

         result.test_eq("RSA PKCS11 encrypt and decrypt: " + padding, decrypted, plaintext);
      };

   std::vector<uint8_t> plaintext(256);
   std::iota(std::begin(plaintext), std::end(plaintext), static_cast<uint8_t>(0));
   encrypt_and_decrypt(plaintext, "Raw", false);

   plaintext = {0x00, 0x01, 0x02, 0x03, 0x04, 0x00};
   encrypt_and_decrypt(plaintext, "EME-PKCS1-v1_5", false);
   encrypt_and_decrypt(plaintext, "EME-PKCS1-v1_5", true);

   encrypt_and_decrypt(plaintext, "OAEP(SHA-1)", false);
   encrypt_and_decrypt(plaintext, "OAEP(SHA-1)", true);

   keypair.first.destroy();
   keypair.second.destroy();

   return result;
}

Test::Result test_rsa_sign_verify() {
   Test::Result result("PKCS11 RSA sign and verify");
   TestSession test_session(true);

   // generate key pair
   PKCS11_RSA_KeyPair keypair = generate_rsa_keypair(test_session);

   auto rng = Test::new_rng(__func__);

   std::vector<uint8_t> plaintext(256);
   std::iota(std::begin(plaintext), std::end(plaintext), static_cast<uint8_t>(0));

   auto sign_and_verify = [&](const std::string& emsa, bool multipart) {
      Botan::PK_Signer signer(keypair.second, *rng, emsa, Botan::Signature_Format::Standard);
      std::vector<uint8_t> signature;
      if(multipart) {
         signer.update(plaintext.data(), plaintext.size() / 2);
         signature = signer.sign_message(plaintext.data() + plaintext.size() / 2, plaintext.size() / 2, *rng);
      } else {
         signature = signer.sign_message(plaintext, *rng);
      }

      Botan::PK_Verifier verifier(keypair.first, emsa, Botan::Signature_Format::Standard);
      bool rsa_ok = false;
      if(multipart) {
         verifier.update(plaintext.data(), plaintext.size() / 2);
         rsa_ok = verifier.verify_message(
            plaintext.data() + plaintext.size() / 2, plaintext.size() / 2, signature.data(), signature.size());
      } else {
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

class PKCS11_RSA_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<std::pair<std::string, std::function<Test::Result()>>> fns = {
            {STRING_AND_FUNCTION(test_rsa_privkey_import)},
            {STRING_AND_FUNCTION(test_rsa_pubkey_import)},
            {STRING_AND_FUNCTION(test_rsa_privkey_export)},
            {STRING_AND_FUNCTION(test_rsa_generate_private_key)},
            {STRING_AND_FUNCTION(test_rsa_generate_key_pair)},
            {STRING_AND_FUNCTION(test_rsa_encrypt_decrypt)},
            {STRING_AND_FUNCTION(test_rsa_sign_verify)}};

         return run_pkcs11_tests("PKCS11 RSA", fns);
      }
};

BOTAN_REGISTER_SERIALIZED_TEST("pkcs11", "pkcs11-rsa", PKCS11_RSA_Tests);
   #endif

/***************************** PKCS11 ECDSA *****************************/

   #if defined(BOTAN_HAS_ECC_GROUP) && (defined(BOTAN_HAS_ECDSA) || defined(BOTAN_HAS_ECDH))
std::vector<uint8_t> encode_ec_point_in_octet_str(const Botan::EC_Point& point) {
   std::vector<uint8_t> enc;
   DER_Encoder(enc).encode(point.encode(EC_Point_Format::Uncompressed), ASN1_Type::OctetString);
   return enc;
}
   #endif

   #if defined(BOTAN_HAS_ECDSA)

Test::Result test_ecdsa_privkey_import() {
   Test::Result result("PKCS11 import ECDSA private key");

   TestSession test_session(true);

   auto rng = Test::new_rng(__func__);

   // create ecdsa private key
   ECDSA_PrivateKey priv_key(*rng, EC_Group::from_name("secp256r1"));
   result.confirm("Key self test OK", priv_key.check_key(*rng, true));

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
   pk.set_public_point(priv_key.public_point());
   result.confirm("P11 key self test OK", pk.check_key(*rng, false));

   pk.destroy();
   return result;
}

Test::Result test_ecdsa_privkey_export() {
   Test::Result result("PKCS11 export ECDSA private key");

   TestSession test_session(true);

   auto rng = Test::new_rng(__func__);

   // create private key
   ECDSA_PrivateKey priv_key(*rng, EC_Group::from_name("secp256r1"));

   result.confirm("Check ECDSA key", priv_key.check_key(*rng, true));
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
   pk.set_public_point(priv_key.public_point());
   result.confirm("Check PK11 key", pk.check_key(*rng, false));

   ECDSA_PrivateKey exported = pk.export_key();
   result.test_success("ECDSA private key export was successful");
   result.confirm("Check exported key valid", exported.check_key(*rng, true));
   result.test_eq("Check exported key contents", exported.private_key_bits(), priv_key.private_key_bits());

   pk.destroy();
   return result;
}

Test::Result test_ecdsa_pubkey_import() {
   Test::Result result("PKCS11 import ECDSA public key");

   TestSession test_session(true);

   auto rng = Test::new_rng(__func__);

   // create ecdsa private key
   ECDSA_PrivateKey priv_key(*rng, EC_Group::from_name("secp256r1"));

   const auto enc_point = encode_ec_point_in_octet_str(priv_key.public_point());

   // import to card
   EC_PublicKeyImportProperties props(priv_key.DER_domain(), enc_point);
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

Test::Result test_ecdsa_pubkey_export() {
   Test::Result result("PKCS11 export ECDSA public key");

   TestSession test_session(true);

   auto rng = Test::new_rng(__func__);

   // create public key from private key
   ECDSA_PrivateKey priv_key(*rng, EC_Group::from_name("secp256r1"));

   const auto enc_point = encode_ec_point_in_octet_str(priv_key.public_point());

   // import to card
   EC_PublicKeyImportProperties props(priv_key.DER_domain(), enc_point);
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

Test::Result test_ecdsa_generate_private_key() {
   Test::Result result("PKCS11 generate ECDSA private key");
   TestSession test_session(true);

   EC_PrivateKeyGenerationProperties props;
   props.set_token(true);
   props.set_private(true);
   props.set_sign(true);

   PKCS11_ECDSA_PrivateKey pk(
      test_session.session(), EC_Group::from_name("secp256r1").DER_encode(EC_Group_Encoding::NamedCurve), props);
   result.test_success("ECDSA private key generation was successful");

   pk.destroy();

   return result;
}

PKCS11_ECDSA_KeyPair generate_ecdsa_keypair(const TestSession& test_session,
                                            const std::string& curve,
                                            EC_Group_Encoding ec_dompar_enc) {
   EC_PublicKeyGenerationProperties pub_props(EC_Group::from_name(curve).DER_encode(ec_dompar_enc));
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

Test::Result test_ecdsa_generate_keypair() {
   Test::Result result("PKCS11 generate ECDSA key pair");
   TestSession test_session(true);
   std::vector<std::string> curves;

   curves.push_back("secp256r1");
   curves.push_back("brainpool512r1");

   for(auto& curve : curves) {
      PKCS11_ECDSA_KeyPair keypair = generate_ecdsa_keypair(test_session, curve, EC_Group_Encoding::NamedCurve);

      keypair.first.destroy();
      keypair.second.destroy();
   }
   result.test_success("ECDSA key pair generation was successful");

   return result;
}

Test::Result test_ecdsa_sign_verify_core(EC_Group_Encoding ec_dompar_enc, const std::string& test_name) {
   Test::Result result(test_name);
   TestSession test_session(true);
   std::vector<std::string> curves;

   curves.push_back("secp256r1");
   curves.push_back("brainpool512r1");

   Slot& slot = test_session.slot();
   SlotInfo info = slot.get_slot_info();
   std::string manufacturer(reinterpret_cast<char*>(info.manufacturerID));

   auto rng = Test::new_rng(__func__);

   for(auto& curve : curves) {
      // generate key pair
      PKCS11_ECDSA_KeyPair keypair = generate_ecdsa_keypair(test_session, curve, ec_dompar_enc);

      std::vector<uint8_t> plaintext(20, 0x01);

      auto sign_and_verify = [&](const std::string& emsa, const Botan::Signature_Format format, bool check_soft) {
         Botan::PK_Signer signer(keypair.second, *rng, emsa, format);
         auto signature = signer.sign_message(plaintext, *rng);

         Botan::PK_Verifier token_verifier(keypair.first, emsa, format);
         bool ecdsa_ok = token_verifier.verify_message(plaintext, signature);

         result.test_eq("ECDSA PKCS11 sign and verify: " + emsa, ecdsa_ok, true);

         // test against software implementation if available
         if(check_soft) {
            Botan::PK_Verifier soft_verifier(keypair.first, emsa, format);
            bool soft_ecdsa_ok = soft_verifier.verify_message(plaintext, signature);

            result.test_eq("ECDSA PKCS11 verify (in software): " + emsa, soft_ecdsa_ok, true);
         }
      };

      // SoftHSMv2 until now only supports "Raw"
      if(manufacturer.find("SoftHSM project") == std::string::npos) {
         sign_and_verify("SHA-256", Botan::Signature_Format::Standard, true);
         sign_and_verify("SHA-256", Botan::Signature_Format::DerSequence, true);
      }

      #if defined(BOTAN_HAS_EMSA_RAW)
      sign_and_verify("Raw", Botan::Signature_Format::Standard, true);
      #else
      sign_and_verify("Raw", Botan::Signature_Format::Standard, false);
      #endif

      keypair.first.destroy();
      keypair.second.destroy();
   }

   return result;
}

Test::Result test_ecdsa_sign_verify() {
   // pass the curve OID to the PKCS#11 library
   return test_ecdsa_sign_verify_core(EC_Group_Encoding::NamedCurve, "PKCS11 ECDSA sign and verify");
}

Test::Result test_ecdsa_curve_import() {
   // pass the curve parameters to the PKCS#11 library and perform sign/verify to test them
   return test_ecdsa_sign_verify_core(EC_Group_Encoding::Explicit, "PKCS11 ECDSA sign and verify with imported curve");
}

class PKCS11_ECDSA_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<std::pair<std::string, std::function<Test::Result()>>> fns = {
            {STRING_AND_FUNCTION(test_ecdsa_privkey_import)},
            {STRING_AND_FUNCTION(test_ecdsa_privkey_export)},
            {STRING_AND_FUNCTION(test_ecdsa_pubkey_import)},
            {STRING_AND_FUNCTION(test_ecdsa_pubkey_export)},
            {STRING_AND_FUNCTION(test_ecdsa_generate_private_key)},
            {STRING_AND_FUNCTION(test_ecdsa_generate_keypair)},
            {STRING_AND_FUNCTION(test_ecdsa_sign_verify)},
            {STRING_AND_FUNCTION(test_ecdsa_curve_import)}};

         return run_pkcs11_tests("PKCS11 ECDSA", fns);
      }
};

BOTAN_REGISTER_SERIALIZED_TEST("pkcs11", "pkcs11-ecdsa", PKCS11_ECDSA_Tests);

   #endif

   #if defined(BOTAN_HAS_ECDH)

/***************************** PKCS11 ECDH *****************************/

Test::Result test_ecdh_privkey_import() {
   Test::Result result("PKCS11 import ECDH private key");

   TestSession test_session(true);

   auto rng = Test::new_rng(__func__);

   // create ecdh private key
   ECDH_PrivateKey priv_key(*rng, EC_Group::from_name("secp256r1"));

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

Test::Result test_ecdh_privkey_export() {
   Test::Result result("PKCS11 export ECDH private key");

   TestSession test_session(true);

   auto rng = Test::new_rng(__func__);

   // create private key
   ECDH_PrivateKey priv_key(*rng, EC_Group::from_name("secp256r1"));

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

Test::Result test_ecdh_pubkey_import() {
   Test::Result result("PKCS11 import ECDH public key");

   TestSession test_session(true);

   auto rng = Test::new_rng(__func__);

   // create ECDH private key
   ECDH_PrivateKey priv_key(*rng, EC_Group::from_name("secp256r1"));

   const auto enc_point = encode_ec_point_in_octet_str(priv_key.public_point());

   // import to card
   EC_PublicKeyImportProperties props(priv_key.DER_domain(), enc_point);
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

Test::Result test_ecdh_pubkey_export() {
   Test::Result result("PKCS11 export ECDH public key");

   TestSession test_session(true);

   auto rng = Test::new_rng(__func__);

   // create public key from private key
   ECDH_PrivateKey priv_key(*rng, EC_Group::from_name("secp256r1"));

   const auto enc_point = encode_ec_point_in_octet_str(priv_key.public_point());

   // import to card
   EC_PublicKeyImportProperties props(priv_key.DER_domain(), enc_point);
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

Test::Result test_ecdh_generate_private_key() {
   Test::Result result("PKCS11 generate ECDH private key");
   TestSession test_session(true);

   EC_PrivateKeyGenerationProperties props;
   props.set_token(true);
   props.set_private(true);
   props.set_derive(true);

   PKCS11_ECDH_PrivateKey pk(
      test_session.session(), EC_Group::from_name("secp256r1").DER_encode(EC_Group_Encoding::NamedCurve), props);
   result.test_success("ECDH private key generation was successful");

   pk.destroy();

   return result;
}

PKCS11_ECDH_KeyPair generate_ecdh_keypair(const TestSession& test_session, const std::string& label) {
   EC_PublicKeyGenerationProperties pub_props(
      EC_Group::from_name("secp256r1").DER_encode(EC_Group_Encoding::NamedCurve));
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

Test::Result test_ecdh_generate_keypair() {
   Test::Result result("PKCS11 generate ECDH key pair");
   TestSession test_session(true);

   PKCS11_ECDH_KeyPair keypair = generate_ecdh_keypair(test_session, "Botan test ECDH key1");
   result.test_success("ECDH key pair generation was successful");

   keypair.first.destroy();
   keypair.second.destroy();

   return result;
}

Test::Result test_ecdh_derive() {
   Test::Result result("PKCS11 ECDH derive");
   TestSession test_session(true);

   PKCS11_ECDH_KeyPair keypair = generate_ecdh_keypair(test_session, "Botan test ECDH key1");
   PKCS11_ECDH_KeyPair keypair2 = generate_ecdh_keypair(test_session, "Botan test ECDH key2");

   auto rng = Test::new_rng(__func__);

   // SoftHSMv2 only supports CKD_NULL KDF at the moment
   Botan::PK_Key_Agreement ka(keypair.second, *rng, "Raw");
   Botan::PK_Key_Agreement kb(keypair2.second, *rng, "Raw");

   Botan::SymmetricKey alice_key =
      ka.derive_key(32, keypair2.first.public_point().encode(EC_Point_Format::Uncompressed));
   Botan::SymmetricKey bob_key = kb.derive_key(32, keypair.first.public_point().encode(EC_Point_Format::Uncompressed));

   bool eq = alice_key == bob_key;
   result.test_eq("same secret key derived", eq, true);

   keypair.first.destroy();
   keypair.second.destroy();
   keypair2.first.destroy();
   keypair2.second.destroy();

   return result;
}

class PKCS11_ECDH_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<std::pair<std::string, std::function<Test::Result()>>> fns = {
            {STRING_AND_FUNCTION(test_ecdh_privkey_import)},
            {STRING_AND_FUNCTION(test_ecdh_privkey_export)},
            {STRING_AND_FUNCTION(test_ecdh_pubkey_import)},
            {STRING_AND_FUNCTION(test_ecdh_pubkey_export)},
            {STRING_AND_FUNCTION(test_ecdh_generate_private_key)},
            {STRING_AND_FUNCTION(test_ecdh_generate_keypair)},
            {STRING_AND_FUNCTION(test_ecdh_derive)}};

         return run_pkcs11_tests("PKCS11 ECDH", fns);
      }
};

BOTAN_REGISTER_SERIALIZED_TEST("pkcs11", "pkcs11-ecdh", PKCS11_ECDH_Tests);

   #endif

/***************************** PKCS11 RNG *****************************/

Test::Result test_rng_generate_random() {
   Test::Result result("PKCS11 RNG generate random");
   TestSession test_session(true);

   PKCS11_RNG p11_rng(test_session.session());
   result.confirm("RNG already seeded", p11_rng.is_seeded());

   std::vector<uint8_t> random(20);
   p11_rng.randomize(random.data(), random.size());
   result.test_ne("random data generated", random, std::vector<uint8_t>(20));

   return result;
}

Test::Result test_rng_add_entropy() {
   Test::Result result("PKCS11 RNG add entropy random");
   TestSession test_session(true);

   PKCS11_RNG p11_rng(test_session.session());

   result.confirm("RNG already seeded", p11_rng.is_seeded());
   p11_rng.clear();
   result.confirm("RNG ignores call to clear", p11_rng.is_seeded());

   result.test_eq("RNG ignores calls to reseed",
                  p11_rng.reseed(Botan::Entropy_Sources::global_sources(), 256, std::chrono::milliseconds(300)),
                  0);

   auto rng = Test::new_rng(__func__);
   auto random = rng->random_vec(20);
   p11_rng.add_entropy(random.data(), random.size());
   result.test_success("entropy added");

   return result;
}

   #if defined(BOTAN_HAS_HMAC_DRBG) && defined(BOTAN_HAS_SHA2_64)

Test::Result test_pkcs11_hmac_drbg() {
   Test::Result result("PKCS11 HMAC_DRBG using PKCS11_RNG");
   TestSession test_session(true);

   PKCS11_RNG p11_rng(test_session.session());
   HMAC_DRBG drbg(MessageAuthenticationCode::create("HMAC(SHA-512)"), p11_rng);
   // result.test_success("HMAC_DRBG(HMAC(SHA512)) instantiated with PKCS11_RNG");

   result.test_eq("HMAC_DRBG is not seeded yet.", drbg.is_seeded(), false);
   secure_vector<uint8_t> rnd = drbg.random_vec(64);
   result.test_eq("HMAC_DRBG is seeded now", drbg.is_seeded(), true);

   std::string personalization_string = "Botan PKCS#11 Tests";
   std::vector<uint8_t> personalization_data(personalization_string.begin(), personalization_string.end());
   drbg.add_entropy(personalization_data.data(), personalization_data.size());

   auto rnd_vec = drbg.random_vec(256);
   result.test_ne("HMAC_DRBG generated a random vector", rnd_vec, std::vector<uint8_t>(256));

   return result;
}
   #endif

class PKCS11_RNG_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<std::pair<std::string, std::function<Test::Result()>>> fns = {
   #if defined(BOTAN_HAS_HMAC_DRBG) && defined(BOTAN_HAS_SHA2_64)
            {STRING_AND_FUNCTION(test_pkcs11_hmac_drbg)},
   #endif
            {STRING_AND_FUNCTION(test_rng_generate_random)},
            {STRING_AND_FUNCTION(test_rng_add_entropy)}
         };

         return run_pkcs11_tests("PKCS11 RNG", fns);
      }
};

BOTAN_REGISTER_SERIALIZED_TEST("pkcs11", "pkcs11-rng", PKCS11_RNG_Tests);

/***************************** PKCS11 token management *****************************/

Test::Result test_set_pin() {
   Test::Result result("PKCS11 set pin");

   Module module(Test::pkcs11_lib());
   std::vector<SlotId> slot_vec = Slot::get_available_slots(module, true);
   Slot slot(module, slot_vec.at(0));

   PKCS11::set_pin(slot, SO_PIN(), TEST_PIN());
   result.test_success("PIN set with SO_PIN to TEST_PIN");

   PKCS11::set_pin(slot, SO_PIN(), PIN());
   result.test_success("PIN changed back with SO_PIN");

   return result;
}

Test::Result test_initialize() {
   Test::Result result("PKCS11 initialize token");

   Module module(Test::pkcs11_lib());
   std::vector<SlotId> slot_vec = Slot::get_available_slots(module, true);
   Slot slot(module, slot_vec.at(0));

   PKCS11::initialize_token(slot, "Botan PKCS#11 tests", SO_PIN(), PIN());
   result.test_success("token initialized");

   return result;
}

Test::Result test_change_pin() {
   Test::Result result("PKCS11 change pin");

   Module module(Test::pkcs11_lib());
   std::vector<SlotId> slot_vec = Slot::get_available_slots(module, true);
   Slot slot(module, slot_vec.at(0));

   PKCS11::change_pin(slot, PIN(), TEST_PIN());
   result.test_success("PIN changed with PIN to TEST_PIN");

   PKCS11::change_pin(slot, TEST_PIN(), PIN());
   result.test_success("PIN changed back with TEST_PIN to PIN");

   return result;
}

Test::Result test_change_so_pin() {
   Test::Result result("PKCS11 change so_pin");

   Module module(Test::pkcs11_lib());
   std::vector<SlotId> slot_vec = Slot::get_available_slots(module, true);
   Slot slot(module, slot_vec.at(0));

   PKCS11::change_so_pin(slot, SO_PIN(), TEST_SO_PIN());
   result.test_success("SO_PIN changed with SO_PIN to TEST_SO_PIN");

   PKCS11::change_so_pin(slot, TEST_SO_PIN(), SO_PIN());
   result.test_success("SO_PIN changed back with TEST_SO_PIN to SO_PIN");

   return result;
}

class PKCS11_Token_Management_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<std::pair<std::string, std::function<Test::Result()>>> fns = {
            {STRING_AND_FUNCTION(test_set_pin)},
            {STRING_AND_FUNCTION(test_initialize)},
            {STRING_AND_FUNCTION(test_change_pin)},
            {STRING_AND_FUNCTION(test_change_so_pin)}};

         return run_pkcs11_tests("PKCS11 token management", fns);
      }
};

BOTAN_REGISTER_SERIALIZED_TEST("pkcs11", "pkcs11-manage", PKCS11_Token_Management_Tests);

/***************************** PKCS11 token management *****************************/

   #if defined(BOTAN_HAS_X509_CERTIFICATES)

Test::Result test_x509_import() {
   Test::Result result("PKCS11 X509 cert import");

      #if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
   TestSession test_session(true);

   X509_Certificate root(Test::data_file("x509/nist/test01/end.crt"));
   X509_CertificateProperties props(root);
   props.set_label("Botan PKCS#11 test certificate");
   props.set_private(false);
   props.set_token(true);

   PKCS11_X509_Certificate pkcs11_cert(test_session.session(), props);
   result.test_success("X509 certificate imported");

   PKCS11_X509_Certificate pkcs11_cert2(test_session.session(), pkcs11_cert.handle());
   result.test_eq("X509 certificate by handle", pkcs11_cert == pkcs11_cert2, true);

   pkcs11_cert.destroy();
      #endif

   return result;
}

class PKCS11_X509_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<std::pair<std::string, std::function<Test::Result()>>> fns = {
            {STRING_AND_FUNCTION(test_x509_import)}};

         return run_pkcs11_tests("PKCS11 X509", fns);
      }
};

BOTAN_REGISTER_SERIALIZED_TEST("pkcs11", "pkcs11-x509", PKCS11_X509_Tests);

   #endif

}  // namespace

#endif

}  // namespace Botan_Tests
