
#include "tests.h"
#include <iostream>

#if defined(BOTAN_HAS_AEAD_OCB)
#include <botan/ocb.h>
#include <botan/hex.h>
#include <botan/sha2_32.h>
#include <botan/aes.h>
#include <botan/loadstor.h>
#include <botan/libstate.h>

using namespace Botan;

namespace {

std::vector<byte> ocb_encrypt(OCB_Encryption& enc,
                              OCB_Decryption& dec,
                              const std::vector<byte>& nonce,
                              const std::vector<byte>& pt,
                              const std::vector<byte>& ad)
   {
   enc.set_associated_data(&ad[0], ad.size());

   enc.start(&nonce[0], nonce.size());

   secure_vector<byte> buf(pt.begin(), pt.end());
   enc.finish(buf, 0);

   try
      {
      secure_vector<byte> ct = buf;

      dec.set_associated_data(&ad[0], ad.size());

      dec.start(&nonce[0], nonce.size());

      dec.finish(ct, 0);

      if(ct != pt)
         std::cout << "OCB failed to decrypt correctly\n";
      }
   catch(std::exception& e)
      {
      std::cout << "OCB round trip error - " << e.what() << "\n";
      }

   return unlock(buf);
   }

size_t test_ocb_long(Algorithm_Factory& af,
                     size_t keylen, size_t taglen,
                     const std::string &expected)
   {
   // Test from RFC 7253 Appendix A

   const std::string algo = "AES-" + std::to_string(keylen);

   OCB_Encryption enc(af.make_block_cipher(algo), taglen / 8);

   OCB_Decryption dec(af.make_block_cipher(algo), taglen / 8);

   std::vector<byte> key(keylen/8);
   key[keylen/8-1] = taglen;

   enc.set_key(key);
   dec.set_key(key);

   const std::vector<byte> empty;
   std::vector<byte> N(12);
   std::vector<byte> C;

   for(size_t i = 0; i != 128; ++i)
      {
      const std::vector<byte> S(i);

      store_be(static_cast<u32bit>(3*i+1), &N[8]);
      C += ocb_encrypt(enc, dec, N, S, S);
      store_be(static_cast<u32bit>(3*i+2), &N[8]);
      C += ocb_encrypt(enc, dec, N, S, empty);
      store_be(static_cast<u32bit>(3*i+3), &N[8]);
      C += ocb_encrypt(enc, dec, N, empty, S);
      }

   store_be(static_cast<u32bit>(385), &N[8]);
   const std::vector<byte> cipher = ocb_encrypt(enc, dec, N, empty, C);

   const std::string cipher_hex = hex_encode(cipher);

   if(cipher_hex != expected)
      {
      std::cout << "OCB " << algo << " long test mistmatch "
                << cipher_hex << " != " << expected << "\n";
      return 1;
      }

   return 0;
   }

}
#endif

size_t test_ocb()
   {
   size_t fails = 0;

#if defined(BOTAN_HAS_AEAD_OCB)
   Algorithm_Factory& af = global_state().algorithm_factory();

   fails += test_ocb_long(af, 128, 128, "67E944D23256C5E0B6C61FA22FDF1EA2");
   fails += test_ocb_long(af, 192, 128, "F673F2C3E7174AAE7BAE986CA9F29E17");
   fails += test_ocb_long(af, 256, 128, "D90EB8E9C977C88B79DD793D7FFA161C");
   fails += test_ocb_long(af, 128, 96, "77A3D8E73589158D25D01209");
   fails += test_ocb_long(af, 192, 96, "05D56EAD2752C86BE6932C5E");
   fails += test_ocb_long(af, 256, 96, "5458359AC23B0CBA9E6330DD");
   fails += test_ocb_long(af, 128, 64, "192C9B7BD90BA06A");
   fails += test_ocb_long(af, 192, 64, "0066BC6E0EF34E24");
   fails += test_ocb_long(af, 256, 64, "7D4EA5D445501CBE");
   test_report("OCB long", 9, fails);
#endif

   return fails;
   }
