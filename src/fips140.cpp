/*************************************************
* FIPS-140 Self Tests Source File                *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/fips140.h>
#include <botan/lookup.h>

namespace Botan {

namespace FIPS140 {

namespace {

/*************************************************
* Perform a Known Answer Test                    *
*************************************************/
void do_kat(const std::string& in, const std::string& out,
            const std::string& algo_name, Filter* filter)
   {
   if(out.length())
      {
      Pipe pipe(new Hex_Decoder, filter, new Hex_Encoder);
      pipe.process_msg(in);

      if(out != pipe.read_all_as_string())
         throw Self_Test_Failure("FIPS-140 " + algo_name + " test");
      }
   }

/*************************************************
* Perform a KAT for a cipher                     *
*************************************************/
void cipher_kat(const std::string& in, const std::string& out,
                  const std::string& key, const std::string& iv,
                  const std::string& cipher)
   {
   do_kat(in, out, cipher, get_cipher(cipher, key, iv, ENCRYPTION));
   do_kat(out, in, cipher, get_cipher(cipher, key, iv, DECRYPTION));
   }

/*************************************************
* Perform a KAT for a cipher                     *
*************************************************/
void cipher_kat(const std::string& cipher, const std::string& key,
                  const std::string& iv, const std::string& in,
                  const std::string& ecb_out, const std::string& cbc_out,
                  const std::string& cfb_out, const std::string& ofb_out,
                  const std::string& ctr_out)
   {
   if(!have_block_cipher(cipher))
      return;

   cipher_kat(in, ecb_out, key, "", cipher + "/ECB");
   cipher_kat(in, cbc_out, key, iv, cipher + "/CBC/NoPadding");
   cipher_kat(in, cfb_out, key, iv, cipher + "/CFB");
   cipher_kat(in, ofb_out, key, iv, cipher + "/OFB");
   cipher_kat(in, ctr_out, key, iv, cipher + "/CTR-BE");
   }

/*************************************************
* Perform a KAT for a hash                       *
*************************************************/
void hash_kat(const std::string& hash, const std::string& in,
                const std::string& out)
   {
   if(!have_hash(hash))
      return;
   do_kat(in, out, hash, new Hash_Filter(hash));
   }

/*************************************************
* Perform a KAT for a MAC                        *
*************************************************/
void mac_kat(const std::string& mac, const std::string& in,
               const std::string& out, const std::string& key)
   {
   if(!have_mac(mac))
      return;
   do_kat(in, out, mac, new MAC_Filter(mac, key));
   }

}

/*************************************************
* Perform FIPS 140 Self Tests                    *
*************************************************/
bool passes_self_tests()
  {
  try {
     cipher_kat("DES", "0123456789ABCDEF", "1234567890ABCDEF",
                "4E6F77206973207468652074696D6520666F7220616C6C20",
                "3FA40E8A984D48156A271787AB8883F9893D51EC4B563B53",
                "E5C7CDDE872BF27C43E934008C389C0F683788499A7C05F6",
                "F3096249C7F46E51A69E839B1A92F78403467133898EA622",
                "F3096249C7F46E5135F24A242EEB3D3F3D6D5BE3255AF8C3",
                "F3096249C7F46E51163A8CA0FFC94C27FA2F80F480B86F75");

     cipher_kat("TripleDES",
                "385D7189A5C3D485E1370AA5D408082B5CCCCB5E19F2D90E",
                "C141B5FCCD28DC8A",
                "6E1BD7C6120947A464A6AAB293A0F89A563D8D40D3461B68",
                "64EAAD4ACBB9CEAD6C7615E7C7E4792FE587D91F20C7D2F4",
                "6235A461AFD312973E3B4F7AA7D23E34E03371F8E8C376C9",
                "E26BA806A59B0330DE40CA38E77A3E494BE2B212F6DD624B",
                "E26BA806A59B03307DE2BCC25A08BA40A8BA335F5D604C62",
                "E26BA806A59B03303C62C2EFF32D3ACDD5D5F35EBCC53371");

     cipher_kat("Skipjack", "1555E5531C3A169B2D65", "6EC9795701F49864",
                "00AFA48E9621E52E8CBDA312660184EDDB1F33D9DACDA8DA",
                "DBEC73562EFCAEB56204EB8AE9557EBF77473FBB52D17CD1",
                "0C7B0B74E21F99B8F2C8DF37879F6C044967F42A796DCA8B",
                "79FDDA9724E36CC2E023E9A5C717A8A8A7FDA465CADCBF63",
                "79FDDA9724E36CC26CACBD83C1ABC06EAF5B249BE5B1E040",
                "79FDDA9724E36CC211B0AEC607B95A96BCDA318440B82F49");

     cipher_kat("AES",
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

     hash_kat("SHA-1", "", "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");
     hash_kat("SHA-1", "616263", "A9993E364706816ABA3E25717850C26C9CD0D89D");
     hash_kat("SHA-1",
              "6162636462636465636465666465666765666768666768696768696A"
              "68696A6B696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071",
              "84983E441C3BD26EBAAE4AA1F95129E5E54670F1");

     mac_kat("HMAC(SHA-1)", "4869205468657265",
             "B617318655057264E28BC0B6FB378C8EF146BE00",
             "0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B");

     mac_kat("X9.19-MAC",
             "31311C3931383237333634351C1C35383134333237361C1C3B3132333435"
             "36373839303132333435363D3939313231303030303F1C30303031323530"
             "301C393738363533343132343837363932331C", "C209CCB78EE1B606",
             "0123456789ABCDEFFEDCBA9876543210");
  }
  catch(std::exception)
     {
     return false;
     }

  return true;
  }

}

}
