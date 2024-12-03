#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/mac.h>

#include <assert.h>

namespace {

std::string compute_mac(std::string_view msg, std::span<const uint8_t> key) {
   auto hmac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");

   hmac->set_key(key);
   hmac->update(msg);

   return Botan::hex_encode(hmac->final());
}

}  // namespace

int main() {
   Botan::AutoSeeded_RNG rng;

   const auto key = rng.random_vec(32);  // 256 bit random key

   // "Message" != "Mussage" so tags will also not match
   std::string tag1 = compute_mac("Message", key);
   std::string tag2 = compute_mac("Mussage", key);
   assert(tag1 != tag2);

   // Recomputing with original input message results in identical tag
   std::string tag3 = compute_mac("Message", key);
   assert(tag1 == tag3);

   return 0;
}
