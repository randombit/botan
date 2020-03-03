/*
* Cipher Modes via CommonCrypto
* (C) 2018 Jose Pereira
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/commoncrypto.h>
#include <botan/internal/commoncrypto_utils.h>
#include <botan/cipher_mode.h>
#include <botan/parsing.h>
#include <botan/internal/rounding.h>
#include <botan/scan_name.h>

namespace Botan {

std::string CommonCrypto_Error::ccryptorstatus_to_string(CCCryptorStatus status)
   {
   switch(status)
      {
      case kCCSuccess:
         return "Success";
      case kCCParamError:
         return "ParamError";
      case kCCBufferTooSmall:
         return "BufferTooSmall";
      case kCCMemoryFailure:
         return "MemoryFailure";
      case kCCAlignmentError:
         return "AlignmentError";
      case kCCDecodeError:
         return "DecodeError";
      case kCCUnimplemented:
         return "Unimplemented";
      case kCCOverflow:
         return "Overflow";
      case kCCRNGFailure:
         return "RNGFailure";
      case kCCUnspecifiedError:
         return "UnspecifiedError";
      case kCCCallSequenceError:
         return "CallSequenceError";
      case kCCKeySizeError:
         return "KeySizeError";
      default:
         return "Unknown";
      }
   };


CommonCryptor_Opts commoncrypto_opts_from_algo_name(const std::string& algo_name)
   {
   CommonCryptor_Opts opts;

   if(algo_name.compare(0, 3, "AES") == 0)
      {
      opts.algo = kCCAlgorithmAES;
      opts.block_size = kCCBlockSizeAES128;
      if(algo_name == "AES-128")
         {
         opts.key_spec = Key_Length_Specification(kCCKeySizeAES128);
         }
      else if(algo_name == "AES-192")
         {
         opts.key_spec = Key_Length_Specification(kCCKeySizeAES192);
         }
      else if(algo_name == "AES-256")
         {
         opts.key_spec = Key_Length_Specification(kCCKeySizeAES256);
         }
      else
         {
         throw CommonCrypto_Error("Unknown AES algorithm");
         }
      }
   else if(algo_name == "DES")
      {
      opts.algo = kCCAlgorithmDES;
      opts.block_size = kCCBlockSizeDES;
      opts.key_spec = Key_Length_Specification(kCCKeySizeDES);
      }
   else if(algo_name == "TripleDES")
      {
      opts.algo = kCCAlgorithm3DES;
      opts.block_size = kCCBlockSize3DES;
      opts.key_spec = Key_Length_Specification(16, kCCKeySize3DES, 8);
      }
   else if(algo_name == "Blowfish")
      {
      opts.algo = kCCAlgorithmBlowfish;
      opts.block_size = kCCBlockSizeBlowfish;
      opts.key_spec = Key_Length_Specification(1, kCCKeySizeMaxBlowfish, 1);
      }
   else if(algo_name == "CAST-128")
      {
      opts.algo = kCCAlgorithmCAST;
      opts.block_size = kCCBlockSizeCAST;
      // Botan's base implementation of CAST does not support shorter keys
      // so we limit its minimum key size to 11 here.
      opts.key_spec = Key_Length_Specification(11, kCCKeySizeMaxCAST, 1);
      }
   else
      {
      throw CommonCrypto_Error("Unsupported cipher");
      }

   return opts;
   }


CommonCryptor_Opts commoncrypto_opts_from_algo(const std::string& algo)
   {
   SCAN_Name spec(algo);

   std::string algo_name = spec.algo_name();
   std::string cipher_mode = spec.cipher_mode();
   std::string cipher_mode_padding = spec.cipher_mode_pad();

   CommonCryptor_Opts opts = commoncrypto_opts_from_algo_name(algo_name);

   //TODO add CFB and XTS support
   if(cipher_mode.empty() || cipher_mode == "ECB")
      {
      opts.mode = kCCModeECB;
      }
   else if(cipher_mode == "CBC")
      {
      opts.mode = kCCModeCBC;
      }
   else if(cipher_mode == "CTR")
      {
      opts.mode = kCCModeCTR;
      }
   else if(cipher_mode == "OFB")
      {
      opts.mode = kCCModeOFB;
      }
   else
      {
      throw CommonCrypto_Error("Unsupported cipher mode!");
      }

   if(cipher_mode_padding == "NoPadding")
      {
      opts.padding = ccNoPadding;
      }
   /*
   else if(cipher_mode_padding.empty() || cipher_mode_padding == "PKCS7")
      {
      opts.padding = ccPKCS7Padding;
      }
   */
   else
      {
      throw CommonCrypto_Error("Unsupported cipher mode padding!");
      }

   return opts;
   }


void commoncrypto_adjust_key_size(const uint8_t key[], size_t length,
                                  const CommonCryptor_Opts& opts, secure_vector<uint8_t>& full_key)
   {

   if(opts.algo == kCCAlgorithmBlowfish && length < 8)
      {
      size_t repeat;
      switch(length)
         {
         case 1:
            repeat = 8;
            break;
         case 2:
            repeat = 4;
            break;
         case 3:
            repeat = 3;
            break;
         default:
            repeat = 2;
            break;
         }

      full_key.resize(length * repeat);
      for(size_t i = 0; i < repeat; i++)
         {
         copy_mem(full_key.data() + i * length, key, length);
         }
      }
   else if(opts.algo == kCCAlgorithm3DES && length == 16)
      {
      full_key += std::make_pair(key, 8);
      }
   }
}
