#include <botan/auto_rng.h>
#include <botan/spake2p.h>
#include <iostream>

int main() {
   const auto as_span = [](std::string_view s) -> std::span<const uint8_t> {
      return {reinterpret_cast<const uint8_t*>(s.data()), s.size()};
   };

   // Both peers must agree on the system parameters, the identities, and
   // the context string
   const auto params = Botan::SPAKE2p::SystemParameters::rfc9383_p256_sha256();
   const auto prover_id = as_span("client");
   const auto verifier_id = as_span("server");
   const auto context = as_span("botan spake2+ example");

   const std::string_view password = "top!secret";

   Botan::AutoSeeded_RNG rng;

   // Registration, performed once: the prover derives its secret from the
   // password, and gives the registration record (along with the salt) to
   // the verifier. The verifier stores the record; it never sees the
   // password itself.
   const auto salt = rng.random_vec(16);
   const auto secret = Botan::SPAKE2p::ProverSecret::from_password(params, password, prover_id, verifier_id, salt);
   const auto record = secret.registration_record(rng);

   // The online phase, performed for each session:
   Botan::SPAKE2p::ProverContext prover(params, secret, prover_id, verifier_id, context);
   Botan::SPAKE2p::VerifierContext verifier(params, record, prover_id, verifier_id, context);

   // First the prover generates its key share and sends it to the verifier
   const auto prover_share = prover.generate_message(rng);

   // The verifier consumes the prover's share and responds with its own key
   // share plus a key confirmation message
   const auto verifier_msg = verifier.process_message(prover_share, rng);

   // The prover consumes the verifier's message, checking the verifier's key
   // confirmation (an exception is thrown if it is invalid), and responds
   // with its own key confirmation
   const auto prover_confirm = prover.process_message(verifier_msg, rng);

   // Finally the verifier checks the prover's key confirmation
   verifier.verify_confirmation(prover_confirm);

   // Now both sides share a secret key
   if(prover.shared_secret() == verifier.shared_secret()) {
      std::cout << "Key exchange worked\n";
      return 0;
   } else {
      // This should never happen, as long as verify_confirmation succeeded
      std::cout << "Something went wrong\n";
      return 1;
   }
}
