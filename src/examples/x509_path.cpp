#include <botan/certstor_system.h>
#include <botan/x509cert.h>
#include <botan/x509path.h>

int main() {
   // Create a certificate store and add a locally trusted CA certificate
   Botan::Certificate_Store_In_Memory customStore;
   customStore.add_certificate(Botan::X509_Certificate("root.crt"));

   // Additionally trust all system-specific CA certificates
   Botan::System_Certificate_Store systemStore;
   std::vector<Botan::Certificate_Store*> trusted_roots{&customStore, &systemStore};

   // Load the end entity certificate and two untrusted intermediate CAs from file
   std::vector<Botan::X509_Certificate> end_certs;
   end_certs.emplace_back(Botan::X509_Certificate("ee.crt"));    // The end-entity certificate, must come first
   end_certs.emplace_back(Botan::X509_Certificate("int2.crt"));  // intermediate 2
   end_certs.emplace_back(Botan::X509_Certificate("int1.crt"));  // intermediate 1

   // Optional: Set up restrictions, e.g. min. key strength, maximum age of OCSP responses
   Botan::Path_Validation_Restrictions restrictions;

   // Optional: Specify usage type, compared against the key usage in end_certs[0]
   Botan::Usage_Type usage = Botan::Usage_Type::UNSPECIFIED;

   // Optional: Specify hostname, if not empty, compared against the DNS name in end_certs[0]
   std::string hostname;

   Botan::Path_Validation_Result validationResult =
      Botan::x509_path_validate(end_certs, restrictions, trusted_roots, hostname, usage);

   if(!validationResult.successful_validation()) {
      // call validationResult.result() to get the overall status code
      return -1;
   }

   return 0;  // Verification succeeded
}
