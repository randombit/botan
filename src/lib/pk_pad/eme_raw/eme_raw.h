/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_EME_RAW_H__
#define BOTAN_EME_RAW_H__

#include <botan/eme.h>
#include <botan/kdf.h>
#include <botan/hash.h>

namespace Botan {

class BOTAN_DLL EME_Raw : public EME
   {
   public:
      size_t maximum_input_size(size_t i) const;

      EME_Raw() {}
   private:
      secure_vector<byte> pad(const byte[], size_t, size_t,
                             RandomNumberGenerator&) const;

      secure_vector<byte> unpad(const byte[], size_t, size_t) const;
   };

}

#endif
