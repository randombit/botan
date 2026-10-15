#include <botan/hpke.h>
#include <botan/system_rng.h>

#include <iostream>
#include <string_view>

namespace {

std::vector<uint8_t> as_bytes(std::string_view s) {
   return std::vector<uint8_t>(s.begin(), s.end());
}

}  // namespace

int main() {
   Botan::System_RNG rng;

   const Botan::HPKE::Suite suite(
      Botan::HPKE::KEM_Code::DHKEM_X25519, Botan::HPKE::KDF_Code::HKDF_SHA256, Botan::HPKE::AEAD_Code::AES_128_GCM);

   // The recipient generates a key pair and publishes the serialized
   // public key, for example in a DNS record or a key package
   const auto recipient_key = Botan::HPKE::Private_Key::generate(suite.kem(), rng);
   const std::vector<uint8_t> published_key = recipient_key.public_key().serialize();

   // Both sides must agree on the application context ("info")
   const auto info = as_bytes("doc example v1");

   // Sender: parse the published key and set up an encryption context.
   // The encapsulated key is transmitted along with the ciphertexts.
   const auto pk = Botan::HPKE::Public_Key::deserialize(suite.kem(), published_key);
   auto sender = Botan::HPKE::Sender_Context::setup_base(suite, pk, rng, info);

   const auto aad = as_bytes("message header");
   const auto ctext1 = sender.seal(aad, as_bytes("hello"));
   const auto ctext2 = sender.seal({}, as_bytes("world"));

   // Recipient: decapsulate the shared secret and open the messages,
   // in the order they were sealed
   auto recipient =
      Botan::HPKE::Recipient_Context::setup_base(suite, recipient_key, sender.encapsulated_key(), rng, info);

   const auto ptext1 = recipient.open(aad, ctext1);
   const auto ptext2 = recipient.open({}, ctext2);

   std::cout << std::string(ptext1.begin(), ptext1.end()) << " " << std::string(ptext2.begin(), ptext2.end()) << "\n";

   // Both contexts can also export shared secrets for use elsewhere
   // in the application
   const auto sender_export = sender.export_secret(as_bytes("session key"), 32);
   const auto recipient_export = recipient.export_secret(as_bytes("session key"), 32);

   if(sender_export != recipient_export) {
      std::cerr << "Exported secrets differ\n";
      return 1;
   }

   return 0;
}
