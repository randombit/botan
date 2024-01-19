/*
 * Classic McEliece Parameters
 * (C) 2024 Jack Lloyd
 *     2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_CMCE_PARAMETER_SET_H_
#define BOTAN_CMCE_PARAMETER_SET_H_

#include <botan/asn1_obj.h>

namespace Botan {

/**
 * All Classic McEliece parameter sets defined in the NIST Round 4
 * submission and the Classic McEliece ISO Draft.
 *
 * Instances are defined in the following format:
 * mceliece{n}{t}{[pc]}{[f]}
 *
 * Instance with 'pc' use plaintext confirmation as defined in the ISO Draft.
 * Instance with 'f' use matrix reduction with the semi-systematic form.
 */
class BOTAN_PUBLIC_API(3, 4) Classic_McEliece_Parameter_Set {
   public:
      enum class Code {
         mceliece348864,   // NIST
         mceliece348864f,  // NIST

         mceliece460896,   // NIST
         mceliece460896f,  // NIST

         mceliece6688128,     // ISO + NIST
         mceliece6688128f,    // ISO + NIST
         mceliece6688128pc,   // ISO
         mceliece6688128pcf,  // ISO

         mceliece6960119,     // ISO + NIST
         mceliece6960119f,    // ISO + NIST
         mceliece6960119pc,   // ISO
         mceliece6960119pcf,  // ISO

         mceliece8192128,     // ISO + NIST
         mceliece8192128f,    // ISO + NIST
         mceliece8192128pc,   // ISO
         mceliece8192128pcf,  // ISO
      };

      using enum Code;

      Classic_McEliece_Parameter_Set(Code code) : m_code(code) {}

      /**
       * @brief Get the parameter set for a given parameter set name.
       */
      static Classic_McEliece_Parameter_Set from_string(std::string_view param_name);

      /**
       * @brief Get the parameter set name for a given parameter set.
       */
      std::string to_string() const;

      /**
       * @brief Get the parameter set for a given OID.
       */
      static Classic_McEliece_Parameter_Set from_oid(const OID& oid);

      /**
       * @brief Get the code for a given parameter set.
       */
      Code code() const { return m_code; }

      bool operator==(const Classic_McEliece_Parameter_Set& other) const { return m_code == other.m_code; }

   private:
      const Code m_code;
};

}  // namespace Botan

#endif  //  BOTAN_CMCE_PARAMETER_SET_H_
