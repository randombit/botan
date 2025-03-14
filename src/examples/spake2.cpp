#include <botan/auto_rng.h>
#include <botan/spake2.h>

#include <functional>
#include <iostream>

std::span<const uint8_t> as_span(std::string_view s) {
   return {reinterpret_cast<const uint8_t*>(s.data()), s.size()};
}

int main() {
   // Peers A and B have to agree on all of those, including
   // the association of A and B to the individual identities.
   const auto A_id = as_span("Jack");
   const auto B_id = as_span("René");
   const auto context = as_span("botan example");
   const std::string_view password = "top!secret";
   const std::string_view hash = "SHA-256";
   const auto group = Botan::EC_Group::from_name("secp256r1");

   const auto params = Botan::SPAKE2::Parameters(group, password, A_id, B_id, context, hash);
   auto rng = Botan::AutoSeeded_RNG();

   Botan::SPAKE2::Context jack_ctx(Botan::SPAKE2::PeerId::PeerA, params, rng);
   // First Jack creates a message and sends it to René
   const auto jacks_message = jack_ctx.generate_message();

   Botan::SPAKE2::Context rene_ctx(Botan::SPAKE2::PeerId::PeerB, params, rng);
   // Then René receives the messsage and creates his message to Jack
   const auto renes_message = rene_ctx.generate_message();

   // Already René knows what the shared secret will be
   const auto shared_secret_rene = rene_ctx.process_message(jacks_message);

   // Eventually Jack receives the reply and calculates the shared secret
   const auto shared_secret_jack = jack_ctx.process_message(renes_message);

   if(shared_secret_jack == shared_secret_rene) {
      std::cout << "agreed sucessfully\n";
   } else {
      std::cerr << "whoopsie\n";
   }

   return 0;
}
