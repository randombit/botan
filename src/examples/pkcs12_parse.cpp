#include <botan/exceptn.h>
#include <botan/hex.h>
#include <botan/pk_keys.h>
#include <botan/pkcs12.h>
#include <botan/pkix_types.h>
#include <botan/x509cert.h>

#include <iostream>
#include <iterator>
#include <vector>

int main() {
   // Read a hex-encoded PFX from stdin.
   const std::string hex_input((std::istreambuf_iterator<char>(std::cin)), std::istreambuf_iterator<char>());
   const auto pfx_bytes = Botan::hex_decode(hex_input);

   try {
      const Botan::PKCS12 bundle(pfx_bytes, "secret");

      if(!bundle.private_keys().empty()) {
         const auto& key = bundle.private_keys().front();
         std::cout << "Key: " << key->algo_name() << " (" << key->key_length() << " bits)\n";
      }

      if(const auto ee = bundle.end_entity_certificate()) {
         std::cout << "End-entity: " << ee->subject_dn().to_string() << '\n'
                   << "Fingerprint (SHA-256): " << ee->fingerprint("SHA-256") << '\n';
      }

      for(const auto& ca : bundle.ca_certificates()) {
         std::cout << "CA: " << ca.subject_dn().to_string() << '\n';
      }

      if(bundle.friendly_name()) {
         std::cout << "Friendly name: " << *bundle.friendly_name() << '\n';
      }
   } catch(const Botan::Invalid_Authentication_Tag&) {
      std::cerr << "Wrong password or corrupted MAC\n";
      return 1;
   } catch(const Botan::Decoding_Error& e) {
      std::cerr << "Malformed or unsupported PFX file: " << e.what() << '\n';
      return 2;
   }
   return 0;
}
