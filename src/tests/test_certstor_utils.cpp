/*
* (C) 1999-2021 Jack Lloyd
* (C) 2019,2021 René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "test_certstor_utils.h"

#if defined(BOTAN_HAS_X509_CERTIFICATES)

   #include <botan/ber_dec.h>
   #include <botan/hex.h>

namespace Botan_Tests {

Botan::X509_DN read_dn(const std::string& hex) {
   Botan::X509_DN dn;
   Botan::BER_Decoder decoder(Botan::hex_decode(hex));
   dn.decode_from(decoder);
   return dn;
}

Botan::X509_DN get_dn() {
   // ASN.1 encoded subject DN of "ISRG Root X1"
   // This certificate is in the standard "System Roots" of any macOS setup,
   // serves as the trust root of botan.randombit.net and expires on
   // Monday, 4. June 2035 at 13:04:38 Central European Summer Time
   return read_dn(
      "304F310B300906035504061302555331293027060355040A1320496E74657"
      "26E65742053656375726974792052657365617263682047726F7570311530"
      "130603550403130C4953524720526F6F74205831");
}

Botan::X509_DN get_utf8_dn() {
   // ASN.1 encoded subject DN of "D-TRUST Root Class 3 CA 2 EV 2009"
   // This DN contains UTF8-encoded strings
   // expires on 05. November 2029 at 8:50:46 UTC
   return read_dn(
      "3050310B300906035504061302444531153013060355040A0C0C442D54727"
      "5737420476D6248312A302806035504030C21442D545255535420526F6F74"
      "20436C617373203320434120322045562032303039");
}

std::vector<uint8_t> get_key_id() {
   // this is the same as the public key SHA1 of "ISRG Root X1"
   return Botan::hex_decode("79B459E67BB6E5E40173800888C81A58F6E99B6E");
}

std::string get_subject_cn() {
   return "ISRG Root X1";
}

std::vector<uint8_t> get_pubkey_sha1_of_cert_with_different_key_id() {
   // see https://github.com/randombit/botan/issues/2779 for details
   //
   // SHA-1(Public Key) of:   SecureTrust CA
   // Valid Until:            Dec 31 19:40:55 2029 GMT
   // Subject Key Identifier: 4232b616fa04fdfe5d4b7ac3fdf74c401d5a43af
   return Botan::hex_decode("ca4edd5b273529d9f6eec3e553efa4c019961daf");
}

Botan::X509_DN get_dn_of_cert_with_different_key_id() {
   // This is the DN of the 'SecureTrust CA' whose SHA-1(pubkey) differs
   // from its Subject Key Identifier
   return read_dn(
      "3048310b30090603550406130255533120301e060355040a131753656375"
      "7265547275737420436f72706f726174696f6e311730150603550403130e"
      "5365637572655472757374204341");
}

Botan::X509_DN get_unknown_dn() {
   // thats a D-Trust "Test Certificate". It should be fairly likely that
   // _nobody_ will _ever_ have that in their system keychain
   // CN: D-TRUST Limited Basic Test PU CA 1-4 2016
   return read_dn(
      "305b310b300906035504061302444531153013060355040a0c0c442d5472"
      "75737420476d62483135303306035504030c2c442d5452555354204c696d"
      "6974656420426173696320526f6f74205465737420505520434120312032"
      "303135");
}

Botan::X509_DN get_skewed_dn() {
   // This DN contains ASN.1 PrintableString fields that are not 'normalized'
   // according to Apple's idea of a normalized PrintableString field:
   //   (1) It has leading and trailing white space
   //   (2) It contains multiple spaces between 'words'
   //
   // This skewed DN was fabricated using the program below and the DN-info of
   // "ISRG Root X1" which expires on Monday, 4. June 2035 at 13:04:38 CEST
   //
   // ```C++
   // #include <iostream>
   //
   // #include <botan/pkix_types.h>
   // #include <botan/der_enc.h>
   // #include <botan/hex.h>
   //
   // using namespace Botan;
   //
   // int main()
   //    {
   //    X509_DN dn{};
   //
   //    dn.add_attribute(OID{2,5,4,6}, ASN1_String("US", ASN1_Type::PrintableString));
   //    dn.add_attribute(OID{2,5,4,10}, ASN1_String("Internet Security  Research Group  ", ASN1_Type::PrintableString));
   //    dn.add_attribute(OID{2,5,4,3}, ASN1_String("  ISRG Root  X1", ASN1_Type::PrintableString));
   //
   //    DER_Encoder enc;
   //    dn.encode_into(enc);
   //
   //    std::cout << hex_encode(enc.get_contents()) << std::endl;
   //    }
   // ```

   return read_dn(
      "3055310B3009060355040613025553312C302A060355040A1323496E74657"
      "26E6574205365637572697479202052657365617263682047726F75702020"
      "311830160603550403130F20204953524720526F6F7420205831");
}

std::vector<uint8_t> get_unknown_key_id() {
   // this is the same as the public key SHA1
   return Botan::hex_decode("785c0b67b536eeacbb2b27cf9123301abe7ab09a");
}
}  // namespace Botan_Tests

#endif
