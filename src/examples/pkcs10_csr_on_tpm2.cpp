#include <iostream>

#include <botan/build.h>

#if defined(BOTAN_HAS_TPM2)

   #include <botan/auto_rng.h>
   #include <botan/hex.h>

   #include <botan/pkcs10.h>
   #include <botan/pkix_types.h>
   #include <botan/x509_ext.h>
   #include <botan/x509_key.h>

   #include <botan/tpm2_context.h>
   #include <botan/tpm2_rng.h>
   #include <botan/tpm2_rsa.h>
   #include <botan/tpm2_session.h>

std::span<const uint8_t> as_byteview(std::string_view str) {
   return {reinterpret_cast<const uint8_t*>(str.data()), str.size()};
}

int main() {
   // This TCTI configuration is just an example, adjust as needed!
   constexpr auto tcti_nameconf = "tabrmd:bus_name=net.randombit.botan.tabrmd,bus_type=session";
   constexpr auto private_key_auth = "notguessable";
   constexpr size_t key_length = 2048;

   // Set up connection to TPM
   auto ctx = Botan::TPM2::Context::create(std::string(tcti_nameconf));

   // Create a TPM-backed RNG
   auto tpm_rng = Botan::TPM2::RandomNumberGenerator(ctx);

   if(ctx->supports_botan_crypto_backend()) {
      ctx->use_botan_crypto_backend([&] {
         // We need an RNG that is functionally independent from the TPM, to use
         // in the crypto backend. Also, it is crucial not to use the TPM-backed
         // RNG as the underlying source for the software RNG. This could lead
         // to TPM command sequence errors when the software RNG decides to
         // transparently pull new entropy from the TPM while another TPM
         // command is being processed in the crypto backend.
         //
         // Nevertheless, periodic reseeds from the TPM-backed RNG as shown
         // below is fine, as this serializes the TPM commands properly. In this
         // example we leave it at a single up-front reseed.
         auto software_rng = std::make_shared<Botan::AutoSeeded_RNG>();
         software_rng->reseed_from_rng(tpm_rng);
         return software_rng;
      }());
      std::cout << "Botan crypto backend enabled\n";
   }

   // Create an encrypted and "authenticated" session to the TPM using the SRK
   // This assumes that the SRK is a persistent object, that is accessible
   // without authentication.
   auto storage_root_key = ctx->storage_root_key({}, {});
   auto session = Botan::TPM2::Session::authenticated_session(ctx, *storage_root_key);

   // Create a private key and persist it into the TPM
   auto cert_private_key = Botan::TPM2::RSA_PrivateKey::create_unrestricted_transient(
      ctx, session, as_byteview(private_key_auth), *storage_root_key, key_length);
   const auto persistent_handle = ctx->persist(*cert_private_key, session, as_byteview(private_key_auth));
   std::cout << "New private key created\n";
   std::cout << "  Persistent handle: 0x" << std::hex << persistent_handle << '\n';

   // To access the key in the future, load it from the TPM as seen below.
   // For now, we still have the key in memory and can use it directly.
   //
   //   auto loaded_private_key =
   //      Botan::TPM2::PrivateKey::load_persistent(ctx,
   //                                               persistent_handle,
   //                                               as_byteview(private_key_auth),
   //                                               session);

   // Create a Certificate Signing Request (CSR)
   const Botan::X509_DN dn({
      {"X520.CommonName", "TPM-hosted test"},
      {"X520.Country", "DE"},
      {"X520.Organization", "Rohde & Schwarz"},
      {"X520.OrganizationalUnit", "GB11"},
   });

   // Set up relevant extensions
   Botan::Extensions extensions;
   extensions.add_new(std::make_unique<Botan::Cert_Extension::Basic_Constraints>(false /* not a CA */));
   extensions.add_new(std::make_unique<Botan::Cert_Extension::Key_Usage>(
      Botan::Key_Constraints(Botan::Key_Constraints::DigitalSignature | Botan::Key_Constraints::KeyEncipherment)));
   extensions.add_new(std::make_unique<Botan::Cert_Extension::Extended_Key_Usage>(
      std::vector{Botan::OID::from_name("PKIX.ServerAuth").value()}));
   extensions.add_new(std::make_unique<Botan::Cert_Extension::Subject_Alternative_Name>([] {
      Botan::AlternativeName alt_name;
      alt_name.add_dns("rohde-schwarz.com");
      alt_name.add_email("rene.meusel@rohde-schwarz.com");
      return alt_name;
   }()));
   extensions.add_new(
      std::make_unique<Botan::Cert_Extension::Subject_Key_ID>(cert_private_key->public_key_bits(), "SHA-256"));

   // All done, create the CSR
   auto csr = Botan::PKCS10_Request::create(*cert_private_key, dn, extensions, "SHA-256", tpm_rng, "PSS(SHA-256)");

   // Print results
   std::cout << '\n';
   std::cout << "New Certificate Signing Request:\n";
   std::cout << csr.PEM_encode() << '\n';

   return 0;
}

#else

int main() {
   std::cerr << "TPM2 support not enabled in this build\n";
   return 1;
}

#endif
