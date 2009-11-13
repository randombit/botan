/*
* RTSS (threshold secret sharing)
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_RTSS_H__
#define BOTAN_RTSS_H__

#include <botan/secmem.h>
#include <botan/hash.h>
#include <botan/rng.h>
#include <vector>

namespace Botan {

class RTSS_Share
   {
   public:
      /**
      * @arg M the number of shares needed to reconstruct
      * @arg N the number of shares generated
      * @arg secret the secret to split
      * @arg secret_len the length of the secret
      * @arg identifier the 16 byte share identifier
      * @arg rng the random number generator to use
      */
      static std::vector<RTSS_Share>
         split(byte M, byte N,
               const byte secret[], u16bit secret_len,
               const byte identifier[16],
               RandomNumberGenerator& rng);

      /**
      * @arg shares the list of shares
      */
      static SecureVector<byte>
        reconstruct(const std::vector<RTSS_Share>& shares);

      RTSS_Share() {}
      RTSS_Share(const std::string&);

      std::string to_string() const;
      byte share_id() const;

      u32bit size() const { return contents.size(); }
      bool initialized() const { return contents.size(); }
   private:
      SecureVector<byte> contents;
   };

}

#endif
