/*
* (C) 1999-2021 Jack Lloyd
* (C) 2019,2021 René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "test_certstor_utils.h"

#if defined(BOTAN_HAS_X509_CERTIFICATES)

   #include <botan/assert.h>
   #include <botan/ber_dec.h>
   #include <botan/hex.h>
   #include <algorithm>

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
   const auto alts = get_utf8_dn_alternatives();
   const auto dtrust = std::find_if(
      alts.begin(), alts.end(), [](const auto& alt) { return alt.first == "D-TRUST Root Class 3 CA 2 EV 2009"; });
   BOTAN_ASSERT_NOMSG(dtrust != alts.end());
   return dtrust->second;
}

std::vector<std::pair<std::string, Botan::X509_DN>> get_utf8_dn_alternatives() {
   // ASN.1 encoded subject DNs that contain an UTF8-encoded CommonName
   return {
      // expires on 12 February 2041 at 18:14:03 UTC
      {"SSL.com TLS ECC Root CA 2022",
       read_dn("304E310B300906035504061302555331183016060355040A0C0F53534C204"
               "36F72706F726174696F6E3125302306035504030C1C53534C2E636F6D2054"
               "4C532045434320526F6F742043412032303232")},

      // expires on 05 November 2029 at 8:50:46 UTC
      {"D-TRUST Root Class 3 CA 2 EV 2009",
       read_dn("3050310B300906035504061302444531153013060355040A0C0C442D54727"
               "5737420476D6248312A302806035504030C21442D545255535420526F6F74"
               "20436C617373203320434120322045562032303039")},

      // expires on 19 May 2046 at 02:10:19 UTC
      {"TrustAsia Global Root CA G3",
       read_dn("305A310B300906035504061302434E31253023060355040A0C1C547275737"
               "44173696120546563686E6F6C6F676965732C20496E632E31243022060355"
               "04030C1B54727573744173696120476C6F62616C20526F6F74204341204733")},

      // expires on 1 October at 23:59:59 2033 UTC
      {"T-TeleSec GlobalRoot Class 2",
       read_dn("308182310B3009060355040613024445312B3029060355040A0C22542D5379"
               "7374656D7320456E746572707269736520536572766963657320476D624831"
               "1F301D060355040B0C16542D53797374656D732054727573742043656E7465"
               "723125302306035504030C1C542D54656C6553656320476C6F62616C526F6F"
               "7420436C6173732032")},

      // expires on 17 April 2041 at 09:26:22 UTC
      {"Atos TrustedRoot Root CA ECC TLS 2021",
       read_dn("304C312E302C06035504030C2541746F732054727573746564526F6F742052"
               "6F6F742043412045434320544C532032303231310D300B060355040A0C0441"
               "746F73310B3009060355040613024445")},
   };
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
