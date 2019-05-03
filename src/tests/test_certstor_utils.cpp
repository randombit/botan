/*
* (C) 1999-2019 Jack Lloyd
* (C) 2019      René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "test_certstor_utils.h"

#if defined(BOTAN_HAS_X509_CERTIFICATES)

#include <botan/ber_dec.h>
#include <botan/hex.h>

namespace Botan_Tests {

Botan::X509_DN read_dn(const std::string hex)
   {
   Botan::X509_DN dn;
   Botan::BER_Decoder decoder(Botan::hex_decode(hex));
   dn.decode_from(decoder);
   return dn;
   }

Botan::X509_DN get_dn()
   {
   // ASN.1 encoded subject DN of "DST Root CA X3"
   // This certificate is in the standard "System Roots" of any macOS setup,
   // serves as the trust root of botan.randombit.net and expires on
   // Thursday, 30. September 2021 at 16:01:15 Central European Summer Time
   return read_dn("303f31243022060355040a131b4469676974616c205369676e6174757265"
                  "20547275737420436f2e311730150603550403130e44535420526f6f7420"
                  "4341205833");
   }

Botan::X509_DN get_utf8_dn()
   {
   // ASN.1 encoded subject DN of "D-TRUST Root Class 3 CA 2 EV 2009"
   // This DN contains UTF8-encoded strings
   // expires on 05. November 2029 at 8:50:46 UTC
   return read_dn("3050310B300906035504061302444531153013060355040A0C0C442D54727"
                  "5737420476D6248312A302806035504030C21442D545255535420526F6F74"
                  "20436C617373203320434120322045562032303039");
   }

std::vector<uint8_t> get_key_id()
   {
   // this is the same as the public key SHA1
   return Botan::hex_decode("c4a7b1a47b2c71fadbe14b9075ffc41560858910");
   }

Botan::X509_DN get_unknown_dn()
   {
   // thats a D-Trust "Test Certificate". It should be fairly likely that
   // _nobody_ will _ever_ have that in their system keychain
   // CN: D-TRUST Limited Basic Test PU CA 1-4 2016
   return read_dn("305b310b300906035504061302444531153013060355040a0c0c442d5472"
                  "75737420476d62483135303306035504030c2c442d5452555354204c696d"
                  "6974656420426173696320526f6f74205465737420505520434120312032"
                  "303135");
   }

Botan::X509_DN get_skewed_dn()
   {
   // This DN contains ASN.1 PrintableString fields that are not 'normalized'
   // according to Apple's idea of a normalized PrintableString field:
   //   (1) It has leading and trailing white space
   //   (2) It contains multiple spaces between 'words'
   return read_dn("304b312a3028060355040a132120204469676974616c2020205369676e61"
                  "7475726520547275737420436f2e2020311d301b06035504031314202044"
                  "5354202020526f6f742043412058332020");
   }

std::vector<uint8_t> get_unknown_key_id()
   {
   // this is the same as the public key SHA1
   return Botan::hex_decode("785c0b67b536eeacbb2b27cf9123301abe7ab09a");
   }
}

#endif
