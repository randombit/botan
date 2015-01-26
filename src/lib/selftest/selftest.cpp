/*
* Startup Self Tests
* (C) 1999-2007,2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/selftest.h>
#include <botan/filters.h>
#include <botan/aead_filt.h>
#include <botan/hex.h>
#include <botan/internal/core_engine.h>
#include <botan/internal/stl_util.h>

namespace Botan {

namespace {

/*
* Perform a Known Answer Test
*/
std::string test_filter_kat(Filter* filter,
                            const std::string& input,
                            const std::string& expected)
   {
   try
      {
      Pipe pipe(new Hex_Decoder, filter, new Hex_Encoder);
      pipe.process_msg(input);

      const std::string got = pipe.read_all_as_string();

      const bool same = (got == expected);

      if(same)
         return "passed";
      else
         return (std::string("got ") + got + " expected " + expected);
      }
   catch(std::exception& e)
      {
      return std::string("exception ") + e.what();
      }
   }

}

/*
* Run a set of KATs
*/
std::map<std::string, std::string>
algorithm_kat_detailed(const SCAN_Name& algo_name,
                       const std::map<std::string, std::string>& vars,
                       Algorithm_Factory& af)
   {
   const std::string& algo = algo_name.algo_name_and_args();

   std::vector<std::string> providers = af.providers_of(algo);
   std::map<std::string, std::string> all_results;

   if(providers.empty()) // no providers, nothing to do
      return all_results;

   const std::string input = search_map(vars, std::string("input"));
   const std::string output = search_map(vars, std::string("output"));

   SymmetricKey key(search_map(vars, std::string("key")));
   InitializationVector iv(search_map(vars, std::string("iv")));

   for(size_t i = 0; i != providers.size(); ++i)
      {
      const std::string provider = providers[i];

      if(const HashFunction* proto =
            af.prototype_hash_function(algo, provider))
         {
         Filter* filt = new Hash_Filter(proto->clone());
         all_results[provider] = test_filter_kat(filt, input, output);
         }
      else if(const MessageAuthenticationCode* proto =
                 af.prototype_mac(algo, provider))
         {
         Keyed_Filter* filt = new MAC_Filter(proto->clone(), key);
         all_results[provider] = test_filter_kat(filt, input, output);
         }
      else if(const StreamCipher* proto =
                 af.prototype_stream_cipher(algo, provider))
         {
         Keyed_Filter* filt = new StreamCipher_Filter(proto->clone());
         filt->set_key(key);
         filt->set_iv(iv);

         all_results[provider] = test_filter_kat(filt, input, output);
         }
      else if(const BlockCipher* proto =
                 af.prototype_block_cipher(algo, provider))
         {
         std::unique_ptr<Keyed_Filter> enc(get_cipher_mode(proto, ENCRYPTION,
                                                           algo_name.cipher_mode(),
                                                           algo_name.cipher_mode_pad()));

         std::unique_ptr<Keyed_Filter> dec(get_cipher_mode(proto, DECRYPTION,
                                                           algo_name.cipher_mode(),
                                                           algo_name.cipher_mode_pad()));

         if(!enc || !dec)
            continue;

         enc->set_key(key);

         if(enc->valid_iv_length(iv.length()))
            enc->set_iv(iv);
         else if(!enc->valid_iv_length(0))
            throw Invalid_IV_Length(algo, iv.length());

         dec->set_key(key);

         if(dec->valid_iv_length(iv.length()))
            dec->set_iv(iv);
         else if(!dec->valid_iv_length(0))
            throw Invalid_IV_Length(algo, iv.length());

         const std::vector<byte> ad = hex_decode(search_map(vars, std::string("ad")));

         if(!ad.empty())
            {
            if(AEAD_Filter* enc_aead = dynamic_cast<AEAD_Filter*>(enc.get()))
               {
               enc_aead->set_associated_data(ad.data(), ad.size());

               if(AEAD_Filter* dec_aead = dynamic_cast<AEAD_Filter*>(dec.get()))
                  dec_aead->set_associated_data(ad.data(), ad.size());
               }
            }

         all_results[provider + " (encrypt)"] = test_filter_kat(enc.release(), input, output);
         all_results[provider + " (decrypt)"] = test_filter_kat(dec.release(), output, input);
         }
      }

   return all_results;
   }

std::map<std::string, bool>
algorithm_kat(const SCAN_Name& algo_name,
              const std::map<std::string, std::string>& vars,
              Algorithm_Factory& af)
   {
   const auto result = algorithm_kat_detailed(algo_name, vars, af);

   std::map<std::string, bool> pass_or_fail;

   for(auto i : result)
      pass_or_fail[i.first] = (i.second == "passed");

   return pass_or_fail;
   }

namespace {

void verify_results(const std::string& algo,
                    const std::map<std::string, std::string>& results)
   {
   for(auto i = results.begin(); i != results.end(); ++i)
      {
      if(i->second != "passed")
         throw Self_Test_Failure(algo + " self-test failed (" + i->second + ")" +
                                 " with provider " + i->first);
      }
   }

void hash_test(Algorithm_Factory& af,
               const std::string& name,
               const std::string& in,
               const std::string& out)
   {
   std::map<std::string, std::string> vars;
   vars["input"] = in;
   vars["output"] = out;

   verify_results(name, algorithm_kat_detailed(name, vars, af));
   }

void mac_test(Algorithm_Factory& af,
              const std::string& name,
              const std::string& in,
              const std::string& out,
              const std::string& key)
   {
   std::map<std::string, std::string> vars;
   vars["input"] = in;
   vars["output"] = out;
   vars["key"] = key;

   verify_results(name, algorithm_kat_detailed(name, vars, af));
   }

/*
* Perform a KAT for a cipher
*/
void cipher_kat(Algorithm_Factory& af,
                const std::string& algo,
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

   std::map<std::string, std::string> vars;
   vars["key"] = key_str;
   vars["iv"] = iv_str;
   vars["input"] = in;

   std::map<std::string, bool> results;

   vars["output"] = ecb_out;
   verify_results(algo + "/ECB", algorithm_kat_detailed(algo + "/ECB", vars, af));

   vars["output"] = cbc_out;
   verify_results(algo + "/CBC",
                  algorithm_kat_detailed(algo + "/CBC/NoPadding", vars, af));

   vars["output"] = cfb_out;
   verify_results(algo + "/CFB", algorithm_kat_detailed(algo + "/CFB", vars, af));

   vars["output"] = ofb_out;
   verify_results(algo + "/OFB", algorithm_kat_detailed(algo + "/OFB", vars, af));

   vars["output"] = ctr_out;
   verify_results(algo + "/CTR", algorithm_kat_detailed(algo + "/CTR-BE", vars, af));
   }

}

/*
* Perform Self Tests
*/
bool passes_self_tests(Algorithm_Factory& af)
   {
   try
      {
      confirm_startup_self_tests(af);
      }
   catch(Self_Test_Failure)
      {
      return false;
      }

   return true;
   }

/*
* Perform Self Tests
*/
void confirm_startup_self_tests(Algorithm_Factory& af)
  {
  cipher_kat(af, "AES-128",
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

  hash_test(af, "SHA-1",
            "", "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709");

  hash_test(af, "SHA-1",
            "616263", "A9993E364706816ABA3E25717850C26C9CD0D89D");

  hash_test(af, "SHA-1",
            "6162636462636465636465666465666765666768666768696768696A"
            "68696A6B696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071",
            "84983E441C3BD26EBAAE4AA1F95129E5E54670F1");

  mac_test(af, "HMAC(SHA-1)",
           "4869205468657265",
           "B617318655057264E28BC0B6FB378C8EF146BE00",
           "0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B");

  hash_test(af, "SHA-256",
            "",
            "E3B0C44298FC1C149AFBF4C8996FB924"
            "27AE41E4649B934CA495991B7852B855");

  hash_test(af, "SHA-256",
            "616263",
            "BA7816BF8F01CFEA414140DE5DAE2223"
            "B00361A396177A9CB410FF61F20015AD");

  hash_test(af, "SHA-256",
            "6162636462636465636465666465666765666768666768696768696A"
            "68696A6B696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071",
            "248D6A61D20638B8E5C026930C3E6039"
            "A33CE45964FF2167F6ECEDD419DB06C1");

  mac_test(af, "HMAC(SHA-256)",
           "4869205468657265",
           "198A607EB44BFBC69903A0F1CF2BBDC5"
           "BA0AA3F3D9AE3C1C7A3B1696A0B68CF7",
           "0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B"
           "0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B");
  }

}
