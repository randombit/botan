#include <botan/p11_x509.h>
#include <botan/pkix_types.h>
#include <botan/x509cert.h>

int main()
   {
   // load existing certificate
   Botan::X509_Certificate root( "test.crt" );

   // set props
   Botan::PKCS11::X509_CertificateProperties props(
      root.subject_dn().DER_encode(), root.BER_encode());

   props.set_label( "Botan PKCS#11 test certificate" );
   props.set_private( false );
   props.set_token( true );

   // import
   Botan::PKCS11::PKCS11_X509_Certificate pkcs11_cert( session, props );

   // load by handle
   Botan::PKCS11::PKCS11_X509_Certificate pkcs11_cert2( session, pkcs11_cert.handle() );
   }
