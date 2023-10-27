#include <botan/x509cert.h>
#include <botan/x509path.h>

int main() {
   // Create a certificate store and add the trusted CA certificate
   Botan::Certificate_Store_In_Memory store;
   store.add_certificate(Botan::X509_Certificate("ca.crt"));

   // Load the end entity certificate from file
   Botan::X509_Certificate end_entity("ee.crt");  // The end-entity certificate

   // Optional: Set up restrictions, e.g. min. key strength, maximum age of OCSP responses
   Botan::Path_Validation_Restrictions restrictions;

   // Optional: Specify usage type, compared against the key usage in endEntityCert
   Botan::Usage_Type usage = Botan::Usage_Type::UNSPECIFIED;

   // Optional: Specify hostname, if not empty, compared against the DNS name in endEntityCert
   std::string hostname = "";

   Botan::Path_Validation_Result validationResult =
      Botan::x509_path_validate(end_entity, restrictions, store, hostname, usage);

   if(!validationResult.successful_validation()) {
      // call validationResult.result() to get the overall status code
      return -1;
   }

   return 0;  // Verification succeeded
}
