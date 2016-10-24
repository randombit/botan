/*
* SRP-6a File Handling
* (C) 2011 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SRP6A_FILES_H__
#define BOTAN_SRP6A_FILES_H__

#include <botan/bigint.h>
#include <iosfwd>
#include <string>
#include <map>

namespace Botan {

/**
* A GnuTLS compatible SRP6 authenticator file
*/
class BOTAN_DLL SRP6_Authenticator_File
   {
   public:

      /**
      * @param input will be read and processed as SRP authenticator file
      */
      explicit SRP6_Authenticator_File(std::istream& input);

      /**
      * Looks up a user in the authenticator file.
      * @param username user to look up
      * @param v set to the host's password verifier
      * @param salt set to the user's salt value
      * @param group_id set to the user's group value
      * @return whether a user exists in the authenticator file
      */
      bool lookup_user(const std::string& username,
                       BigInt& v,
                       std::vector<byte>& salt,
                       std::string& group_id) const;
   private:
      struct SRP6_Data
         {
         SRP6_Data() {}

         SRP6_Data(const BigInt& v_,
                   const std::vector<byte>& salt_,
                   const std::string& group_id_) :
            v(v_), salt(salt_), group_id(group_id_) {}

         // public member variable:
         BigInt v;

         // public member variable:
         std::vector<byte> salt;

         // public member variable:
         std::string group_id;
         };

      std::map<std::string, SRP6_Data> m_entries;
   };

}

#endif
