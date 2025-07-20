/*
* (C) 2017 Fabian Weissberg, Rohde & Schwarz Cybersecurity
*     2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pkix_types.h>

#include <botan/asn1_obj.h>
#include <botan/internal/x509_utils.h>

namespace Botan {

//static
size_t X509_DN::lookup_ub(const OID& oid) {
   /*
   * See RFC 5280 Appendix A.1 starting with comment "-- Upper Bounds"
   */

   // NOLINTBEGIN(*-branch-clone)
   if(auto iso_dn = is_sub_element_of(oid, {2, 5, 4})) {
      switch(*iso_dn) {
         case 3:
            // X520.CommonName
            return 64;
         case 4:
            // X520.Surname
            return 40;
         case 5:
            // X520.SerialNumber
            return 64;
         case 6:
            // X520.Country
            return 3;
         case 7:
            // X520.Locality
            return 128;
         case 8:
            // X520.State
            return 128;
         case 9:
            // X520.StreetAddress
            return 128;
         case 10:
            // X520.Organization
            return 64;
         case 11:
            // X520.OrganizationalUnit
            return 64;
         case 12:
            // X520.Title
            return 64;
         case 42:
            // X520.GivenName
            return 16;
         case 43:
            // X520.Initials
            return 5;
         case 44:
            // X520.GenerationalQualifier
            return 3;
         case 46:
            // X520.DNQualifier
            return 64;
         case 65:
            // X520.Pseudonym
            return 128;
         default:
            return 0;
      }
   }

   // NOLINTEND(*-branch-clone)

   return 0;
}

}  // namespace Botan
