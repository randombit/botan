#include <botan/asn1_obj.h>
#include <botan/auto_rng.h>
#include <botan/der_enc.h>
#include <botan/ec_group.h>
#include <botan/ecdsa.h>
#include <botan/p11.h>
#include <botan/p11_ecc_key.h>
#include <botan/p11_ecdsa.h>
#include <botan/p11_types.h>
#include <botan/pubkey.h>

#include <string>
#include <vector>

int main() {
   Botan::PKCS11::Module module("C:\\pkcs11-middleware\\library.dll");
   // open write session to first slot with connected token
   std::vector<Botan::PKCS11::SlotId> slots = Botan::PKCS11::Slot::get_available_slots(module, true);
   Botan::PKCS11::Slot slot(module, slots.at(0));
   Botan::PKCS11::Session session(slot, false);

   Botan::PKCS11::secure_string pin = {'1', '2', '3', '4', '5', '6'};
   session.login(Botan::PKCS11::UserType::User, pin);

   /************ import ECDSA private key *************/

   // create private key in software
   Botan::AutoSeeded_RNG rng;

   Botan::ECDSA_PrivateKey priv_key_sw(rng, Botan::EC_Group::from_name("secp256r1"));

   // set the private key import properties
   Botan::PKCS11::EC_PrivateKeyImportProperties priv_import_props(priv_key_sw.DER_domain(),
                                                                  priv_key_sw.private_value());

   priv_import_props.set_token(true);
   priv_import_props.set_private(true);
   priv_import_props.set_sign(true);
   priv_import_props.set_extractable(true);

   // label
   std::string label = "test ECDSA key";
   priv_import_props.set_label(label);

   // import to card
   Botan::PKCS11::PKCS11_ECDSA_PrivateKey priv_key(session, priv_import_props);

   /************ export PKCS#11 ECDSA private key *************/
   Botan::ECDSA_PrivateKey priv_exported = priv_key.export_key();

   /************ import ECDSA public key *************/

   // import to card
   std::vector<uint8_t> ec_point;
   Botan::DER_Encoder(ec_point).encode(priv_key_sw.raw_public_key_bits(), Botan::ASN1_Type::OctetString);
   Botan::PKCS11::EC_PublicKeyImportProperties pub_import_props(priv_key_sw.DER_domain(), ec_point);

   pub_import_props.set_token(true);
   pub_import_props.set_verify(true);
   pub_import_props.set_private(false);

   // label
   label = "test ECDSA pub key";
   pub_import_props.set_label(label);

   Botan::PKCS11::PKCS11_ECDSA_PublicKey public_key(session, pub_import_props);

   /************ export PKCS#11 ECDSA public key *************/
   Botan::ECDSA_PublicKey pub_exported = public_key.export_key();

   /************ generate PKCS#11 ECDSA private key *************/
   Botan::PKCS11::EC_PrivateKeyGenerationProperties priv_generate_props;
   priv_generate_props.set_token(true);
   priv_generate_props.set_private(true);
   priv_generate_props.set_sign(true);

   Botan::PKCS11::PKCS11_ECDSA_PrivateKey pk(
      session, Botan::EC_Group::from_name("secp256r1").DER_encode(), priv_generate_props);

   /************ generate PKCS#11 ECDSA key pair *************/

   Botan::PKCS11::EC_PublicKeyGenerationProperties pub_generate_props(
      Botan::EC_Group::from_name("secp256r1").DER_encode());

   pub_generate_props.set_label("BOTAN_TEST_ECDSA_PUB_KEY");
   pub_generate_props.set_token(true);
   pub_generate_props.set_verify(true);
   pub_generate_props.set_private(false);
   pub_generate_props.set_modifiable(true);

   Botan::PKCS11::PKCS11_ECDSA_KeyPair key_pair =
      Botan::PKCS11::generate_ecdsa_keypair(session, pub_generate_props, priv_generate_props);

   /************ PKCS#11 ECDSA sign and verify *************/

   std::vector<uint8_t> plaintext(20, 0x01);

   Botan::PK_Signer signer(key_pair.second, rng, "Raw", Botan::Signature_Format::Standard, "pkcs11");
   auto signature = signer.sign_message(plaintext, rng);

   Botan::PK_Verifier token_verifier(key_pair.first, "Raw", Botan::Signature_Format::Standard, "pkcs11");
   bool ecdsa_ok = token_verifier.verify_message(plaintext, signature);

   return ecdsa_ok ? 0 : 1;
}
