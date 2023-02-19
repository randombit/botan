/*
* (C) 1999-2007,2016 Jack Lloyd
* (C) 2016 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pkix_enums.h>
#include <botan/pk_keys.h>
#include <botan/internal/parsing.h>
#include <vector>

namespace Botan {

std::string Key_Constraints::to_string() const
   {
   if(this->m_value == Key_Constraints::None)
      return "no_constraints";

   std::vector<std::string> str;

   if(this->m_value & Key_Constraints::DigitalSignature)
      str.push_back("digital_signature");

   if(this->m_value & Key_Constraints::NonRepudiation)
      str.push_back("non_repudiation");

   if(this->m_value & Key_Constraints::KeyEncipherment)
      str.push_back("key_encipherment");

   if(this->m_value & Key_Constraints::DataEncipherment)
      str.push_back("data_encipherment");

   if(this->m_value & Key_Constraints::KeyAgreement)
      str.push_back("key_agreement");

   if(this->m_value & Key_Constraints::KeyCertSign)
      str.push_back("key_cert_sign");

   if(this->m_value & Key_Constraints::CrlSign)
      str.push_back("crl_sign");

   if(this->m_value & Key_Constraints::EncipherOnly)
      str.push_back("encipher_only");

   if(this->m_value & Key_Constraints::DecipherOnly)
      str.push_back("decipher_only");

   // Not 0 (checked at start) but nothing matched above!
   if(str.empty())
      return "other_unknown_constraints";

   return string_join(str, ',');
   }

/*
* Make sure the given key constraints are permitted for the given key type
*/
bool Key_Constraints::compatible_with(const Public_Key& pub_key) const
   {
   const std::string name = pub_key.algo_name();

   const bool can_agree = (name == "DH" || name == "ECDH" || name.starts_with("Kyber-"));
   const bool can_encrypt = (name == "RSA" || name == "ElGamal" || name.starts_with("Kyber-"));

   const bool can_sign =
      (name == "RSA" || name == "DSA" ||
       name == "ECDSA" || name == "ECGDSA" || name == "ECKCDSA" || name == "Ed25519" ||
       name == "GOST-34.10" || name == "GOST-34.10-2012-256" || name == "GOST-34.10-2012-512" ||
       name.starts_with("Dilithium-"));

   uint32_t permitted = 0;

   if(can_agree)
      {
      permitted |= Key_Constraints::KeyAgreement |
         Key_Constraints::EncipherOnly |
         Key_Constraints::DecipherOnly;
      }

   if(can_encrypt)
      {
      permitted |= Key_Constraints::KeyEncipherment |
         Key_Constraints::DataEncipherment;
      }

   if(can_sign)
      {
      permitted |= Key_Constraints::DigitalSignature |
         Key_Constraints::NonRepudiation |
         Key_Constraints::KeyCertSign |
         Key_Constraints::CrlSign;
      }

   if((m_value & permitted) != m_value)
      {
      return false;
      }

   return true;
   }

}
