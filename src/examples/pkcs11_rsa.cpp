#include <botan/auto_rng.h>
#include <botan/p11.h>
#include <botan/p11_rsa.h>
#include <botan/p11_types.h>
#include <botan/pubkey.h>
#include <botan/rsa.h>

#include <vector>

int main() {
   Botan::PKCS11::Module module("C:\\pkcs11-middleware\\library.dll");
   // open write session to first slot with connected token
   std::vector<Botan::PKCS11::SlotId> slots = Botan::PKCS11::Slot::get_available_slots(module, true);
   Botan::PKCS11::Slot slot(module, slots.at(0));
   Botan::PKCS11::Session session(slot, false);

   Botan::PKCS11::secure_string pin = {'1', '2', '3', '4', '5', '6'};
   session.login(Botan::PKCS11::UserType::User, pin);

   /************ import RSA private key *************/

   // create private key in software
   Botan::AutoSeeded_RNG rng;
   Botan::RSA_PrivateKey priv_key_sw(rng, 2048);

   // set the private key import properties
   Botan::PKCS11::RSA_PrivateKeyImportProperties priv_import_props(priv_key_sw.get_n(), priv_key_sw.get_d());

   priv_import_props.set_pub_exponent(priv_key_sw.get_e());
   priv_import_props.set_prime_1(priv_key_sw.get_p());
   priv_import_props.set_prime_2(priv_key_sw.get_q());
   priv_import_props.set_coefficient(priv_key_sw.get_c());
   priv_import_props.set_exponent_1(priv_key_sw.get_d1());
   priv_import_props.set_exponent_2(priv_key_sw.get_d2());

   priv_import_props.set_token(true);
   priv_import_props.set_private(true);
   priv_import_props.set_decrypt(true);
   priv_import_props.set_sign(true);

   // import
   Botan::PKCS11::PKCS11_RSA_PrivateKey priv_key(session, priv_import_props);

   /************ export PKCS#11 RSA private key *************/
   Botan::RSA_PrivateKey exported = priv_key.export_key();

   /************ import RSA public key *************/

   // set the public key import properties
   Botan::PKCS11::RSA_PublicKeyImportProperties pub_import_props(priv_key.get_n(), priv_key.get_e());
   pub_import_props.set_token(true);
   pub_import_props.set_encrypt(true);
   pub_import_props.set_private(false);

   // import
   Botan::PKCS11::PKCS11_RSA_PublicKey public_key(session, pub_import_props);

   /************ generate RSA private key *************/

   Botan::PKCS11::RSA_PrivateKeyGenerationProperties priv_generate_props;
   priv_generate_props.set_token(true);
   priv_generate_props.set_private(true);
   priv_generate_props.set_sign(true);
   priv_generate_props.set_decrypt(true);
   priv_generate_props.set_label("BOTAN_TEST_RSA_PRIV_KEY");

   Botan::PKCS11::PKCS11_RSA_PrivateKey private_key2(session, 2048, priv_generate_props);

   /************ generate RSA key pair *************/

   Botan::PKCS11::RSA_PublicKeyGenerationProperties pub_generate_props(2048UL);
   pub_generate_props.set_pub_exponent();
   pub_generate_props.set_label("BOTAN_TEST_RSA_PUB_KEY");
   pub_generate_props.set_token(true);
   pub_generate_props.set_encrypt(true);
   pub_generate_props.set_verify(true);
   pub_generate_props.set_private(false);

   Botan::PKCS11::PKCS11_RSA_KeyPair rsa_keypair =
      Botan::PKCS11::generate_rsa_keypair(session, pub_generate_props, priv_generate_props);

   /************ RSA encrypt *************/

   Botan::secure_vector<uint8_t> plaintext = {0x00, 0x01, 0x02, 0x03};
   Botan::PK_Encryptor_EME encryptor(rsa_keypair.first, rng, "Raw");
   auto ciphertext = encryptor.encrypt(plaintext, rng);

   /************ RSA decrypt *************/

   Botan::PK_Decryptor_EME decryptor(rsa_keypair.second, rng, "Raw");
   plaintext = decryptor.decrypt(ciphertext);

   /************ RSA sign *************/

   Botan::PK_Signer signer(
      rsa_keypair.second, rng, Botan::PK_Signature_Options().with_hash("SHA-256").with_padding("PSS"));
   auto signature = signer.sign_message(plaintext, rng);

   /************ RSA verify *************/

   Botan::PK_Verifier verifier(rsa_keypair.first,
                               Botan::PK_Signature_Options().with_hash("SHA-256").with_padding("PSS"));
   auto ok = verifier.verify_message(plaintext, signature);

   return ok ? 0 : 1;
}
