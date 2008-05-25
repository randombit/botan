/***********************************
*                                  *
* BSI variant of EMSA1 Source File *
* (C) 2008 FlexSecure GmbH     	   *
*          Falko Strenzke      	   *
*          strenzke@flexsecure 	   *
*                                  *
***********************************/

#include <botan/emsa.h>
#include <assert.h>
namespace Botan
  {

    /*************************************************
    * EMSA1 Encode Operation                         *
    *************************************************/
    SecureVector<byte> EMSA1_BSI::encoding_of(const MemoryRegion<byte>& msg,
        u32bit output_bits)
    {
      if (msg.size() != hash->OUTPUT_LENGTH)
        {

          throw Encoding_Error("EMSA1_BSI::encoding_of: Invalid size for input");
        }
      if (8*msg.size() <= output_bits)
        {
          return msg;
        }
      else
        {
          throw Encoding_Error("EMSA1_BSI::encoding_of: maximum key input size exceeded");
        }
      assert(false); // cannot reach here
    }

/*************************************************
* EMSA1_BSI Constructor                          *
*************************************************/
EMSA1_BSI::EMSA1_BSI(const std::string& hash_name) :
   EMSA1(hash_name)
   {
   }

  }
