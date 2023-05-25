#include <botan/auto_rng.h>
#include <botan/hmac_drbg.h>
#include <botan/mac.h>
#include <botan/p11.h>
#include <botan/p11_randomgenerator.h>
#include <botan/p11_types.h>

#include <vector>

int main() {
   Botan::PKCS11::Module module("C:\\pkcs11-middleware\\library.dll");
   // open write session to first slot with connected token
   std::vector<Botan::PKCS11::SlotId> slots = Botan::PKCS11::Slot::get_available_slots(module, true);
   Botan::PKCS11::Slot slot(module, slots.at(0));
   Botan::PKCS11::Session session(slot, false);

   Botan::PKCS11::PKCS11_RNG p11_rng(session);

   /************ generate random data *************/
   std::vector<uint8_t> random(20);
   p11_rng.randomize(random.data(), random.size());

   /************ add entropy *************/
   Botan::AutoSeeded_RNG auto_rng;
   auto auto_rng_random = auto_rng.random_vec(20);
   p11_rng.add_entropy(auto_rng_random.data(), auto_rng_random.size());

   /************ use PKCS#11 RNG to seed HMAC_DRBG *************/
   Botan::HMAC_DRBG drbg(Botan::MessageAuthenticationCode::create("HMAC(SHA-512)"), p11_rng);
   drbg.randomize(random.data(), random.size());

   return 0;
}
