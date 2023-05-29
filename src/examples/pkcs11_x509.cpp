#include <botan/p11.h>
#include <botan/p11_types.h>
#include <botan/p11_x509.h>
#include <botan/pkix_types.h>
#include <botan/x509cert.h>

#include <vector>

int main() {
   Botan::PKCS11::Module module("C:\\pkcs11-middleware\\library.dll");
   // open write session to first slot with connected token
   std::vector<Botan::PKCS11::SlotId> slots = Botan::PKCS11::Slot::get_available_slots(module, true);
   Botan::PKCS11::Slot slot(module, slots.at(0));
   Botan::PKCS11::Session session(slot, false);

   // load existing certificate
   Botan::X509_Certificate root("test.crt");

   // set props
   Botan::PKCS11::X509_CertificateProperties props(root.subject_dn().DER_encode(), root.BER_encode());

   props.set_label("Botan PKCS#11 test certificate");
   props.set_private(false);
   props.set_token(true);

   // import
   Botan::PKCS11::PKCS11_X509_Certificate pkcs11_cert(session, props);

   // load by handle
   Botan::PKCS11::PKCS11_X509_Certificate pkcs11_cert2(session, pkcs11_cert.handle());

   return 0;
}
