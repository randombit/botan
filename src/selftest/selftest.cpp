/*
* Startup Self Tests
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/selftest.h>
#include <botan/filters.h>
#include <botan/ecb.h>
#include <botan/cbc.h>
#include <botan/cfb.h>
#include <botan/ofb.h>
#include <botan/ctr.h>
#include <botan/hmac.h>

namespace Botan {

namespace {

/*
* Perform a Known Answer Test
*/
void do_kat(const std::string& in, const std::string& out,
            const std::string& algo_name, Filter* filter)
   {
   if(out.length())
      {
      Pipe pipe(new Hex_Decoder, filter, new Hex_Encoder);
      pipe.process_msg(in);

      if(out != pipe.read_all_as_string())
         throw Self_Test_Failure(algo_name + " startup test");
      }
   }

/*
* Perform a KAT for a cipher
*/
void cipher_kat(const BlockCipher* proto,
                const std::string& key_str,
                const std::string& iv_str,
                const std::string& in,
                const std::string& ecb_out,
                const std::string& cbc_out,
                const std::string& cfb_out,
                const std::string& ofb_out,
                const std::string& ctr_out)
   {
   SymmetricKey key(key_str);
   InitializationVector iv(iv_str);

   std::string name = proto->name();

   do_kat(in, ecb_out, name + "/ECB",
          new ECB_Encryption(proto->clone(), new Null_Padding, key));
   do_kat(ecb_out, in, name + "/ECB",
          new ECB_Decryption(proto->clone(), new Null_Padding, key));

   do_kat(in, cbc_out, name + "/CBC",
          new CBC_Encryption(proto->clone(), new Null_Padding, key, iv));
   do_kat(cbc_out, in, name + "/CBC",
          new CBC_Decryption(proto->clone(), new Null_Padding, key, iv));

   do_kat(in, cfb_out, name + "/CFB",
          new CFB_Encryption(proto->clone(), key, iv));
   do_kat(cfb_out, in, name + "/CFB",
          new CFB_Decryption(proto->clone(), key, iv));

   do_kat(in, ofb_out, name + "/OFB", new OFB(proto->clone(), key, iv));

   do_kat(in, ctr_out, name + "/CTR-BE",
          new CTR_BE(proto->clone(), key, iv));
   }

}

/*
* Perform Self Tests
*/
bool passes_self_tests(Algorithm_Factory& af)
  {
  try
     {
     if(const BlockCipher* proto = af.prototype_block_cipher("DES"))
        {
        cipher_kat(proto,
                "0123456789ABCDEF", "1234567890ABCDEF",
                "4E6F77206973207468652074696D6520666F7220616C6C20",
                "3FA40E8A984D48156A271787AB8883F9893D51EC4B563B53",
                "E5C7CDDE872BF27C43E934008C389C0F683788499A7C05F6",
                "F3096249C7F46E51A69E839B1A92F78403467133898EA622",
                "F3096249C7F46E5135F24A242EEB3D3F3D6D5BE3255AF8C3",
                "F3096249C7F46E51163A8CA0FFC94C27FA2F80F480B86F75");
        }

     if(const BlockCipher* proto = af.prototype_block_cipher("TripleDES"))
        {
        cipher_kat(proto,
                "385D7189A5C3D485E1370AA5D408082B5CCCCB5E19F2D90E",
                "C141B5FCCD28DC8A",
                "6E1BD7C6120947A464A6AAB293A0F89A563D8D40D3461B68",
                "64EAAD4ACBB9CEAD6C7615E7C7E4792FE587D91F20C7D2F4",
                "6235A461AFD312973E3B4F7AA7D23E34E03371F8E8C376C9",
                "E26BA806A59B0330DE40CA38E77A3E494BE2B212F6DD624B",
                "E26BA806A59B03307DE2BCC25A08BA40A8BA335F5D604C62",
                "E26BA806A59B03303C62C2EFF32D3ACDD5D5F35EBCC53371");
        }

     if(const BlockCipher* proto = af.prototype_block_cipher("AES"))
        {
        cipher_kat(proto,
                   "2B7E151628AED2A6ABF7158809CF4F3C",
                   "000102030405060708090A0B0C0D0E0F",
                   "6BC1BEE22E409F96E93D7E117393172A"
                   "AE2D8A571E03AC9C9EB76FAC45AF8E51",
                   "3AD77BB40D7A3660A89ECAF32466EF97"
                   "F5D3D58503B9699DE785895A96FDBAAF",
                   "7649ABAC8119B246CEE98E9B12E9197D"
                   "5086CB9B507219EE95DB113A917678B2",
                   "3B3FD92EB72DAD20333449F8E83CFB4A"
                   "C8A64537A0B3A93FCDE3CDAD9F1CE58B",
                   "3B3FD92EB72DAD20333449F8E83CFB4A"
                   "7789508D16918F03F53C52DAC54ED825",
                   "3B3FD92EB72DAD20333449F8E83CFB4A"
                   "010C041999E03F36448624483E582D0E");
        }

     if(const HashFunction* proto = af.prototype_hash_function("SHA-1"))
        {
        do_kat("", "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
               proto->name(), new Hash_Filter(proto->clone()));

        do_kat("616263", "A9993E364706816ABA3E25717850C26C9CD0D89D",
               proto->name(), new Hash_Filter(proto->clone()));

        do_kat("6162636462636465636465666465666765666768666768696768696A"
               "68696A6B696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071",
               "84983E441C3BD26EBAAE4AA1F95129E5E54670F1",
               proto->name(), new Hash_Filter(proto->clone()));

        do_kat("4869205468657265",
               "B617318655057264E28BC0B6FB378C8EF146BE00",
               "HMAC(" + proto->name() + ")",
               new MAC_Filter(new HMAC(proto->clone()),
                              SymmetricKey("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B")));
        }

     if(const HashFunction* proto = af.prototype_hash_function("SHA-256"))
        {
        do_kat("",
                 "E3B0C44298FC1C149AFBF4C8996FB924"
                 "27AE41E4649B934CA495991B7852B855",
                 proto->name(), new Hash_Filter(proto->clone()));

        do_kat("616263",
                 "BA7816BF8F01CFEA414140DE5DAE2223"
                 "B00361A396177A9CB410FF61F20015AD",
                 proto->name(), new Hash_Filter(proto->clone()));

        do_kat("6162636462636465636465666465666765666768666768696768696A"
               "68696A6B696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071",
               "248D6A61D20638B8E5C026930C3E6039"
               "A33CE45964FF2167F6ECEDD419DB06C1",
               proto->name(), new Hash_Filter(proto->clone()));

        do_kat("4869205468657265",
               "198A607EB44BFBC69903A0F1CF2BBDC5"
               "BA0AA3F3D9AE3C1C7A3B1696A0B68CF7",
               "HMAC(" + proto->name() + ")",
               new MAC_Filter(new HMAC(proto->clone()),
                              SymmetricKey("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B"
                                           "0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B")));
        }
  }
  catch(std::exception)
     {
     return false;
     }

  return true;
  }

}
