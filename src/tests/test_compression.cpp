#include "tests.h"

#if defined(BOTAN_HAS_COMPRESSION)

#include <botan/compression.h>
#include <botan/hex.h>
#include <iostream>

namespace {

using namespace Botan;

// Returns # of bytes of compressed message
size_t run_compression(Compressor_Transform& c, Transform& d,
                       const secure_vector<byte>& msg)
   {
   secure_vector<byte> compressed = msg;

   c.start();
   c.finish(compressed);

   const size_t c_size = compressed.size();

   secure_vector<byte> decompressed = compressed;
   d.start();
   d.finish(decompressed);

   if(msg != decompressed)
      {
      std::cout << hex_encode(msg) << " compressed to " << hex_encode(compressed)
                << " but did not roundtrip - " << hex_encode(decompressed) << std::endl;
      }

   return c_size;
   }

}

size_t test_compression()
   {
   using namespace Botan;

   size_t fails = 0, tests = 0;

   for(auto&& algo : { "zlib", "deflate", "gzip", "bz2", "lzma" })
      {
      try
         {
         std::unique_ptr<Compressor_Transform> c1(make_compressor(algo, 1));
         std::unique_ptr<Compressor_Transform> c9(make_compressor(algo, 9));
         std::unique_ptr<Compressor_Transform> d(make_decompressor(algo));

         if(!c1 || !c9 || !d)
            continue;

         ++tests;

         const char* text_str =
            "'Twas brillig, and the slithy toves"
            "Did gyre and gimble in the wabe:"
            "All mimsy were the borogoves,"
            "And the mome raths outgrabe."

            "'Beware the Jabberwock, my son!"
            "The jaws that bite, the claws that catch!"
            "Beware the Jubjub bird, and shun"
            "The frumious Bandersnatch!'"

            "He took his vorpal sword in hand;"
            "Long time the manxome foe he sought—"
            "So rested he by the Tumtum tree"
            "And stood awhile in thought."

            "And, as in uffish thought he stood,"
            "The Jabberwock, with eyes of flame,"
            "Came whiffling through the tulgey wood,"
            "And burbled as it came!"

            "One, two! One, two! And through and through"
            "The vorpal blade went snicker-snack!"
            "He left it dead, and with its head"
            "He went galumphing back."

            "'And hast thou slain the Jabberwock?"
            "Come to my arms, my beamish boy!"
            "O frabjous day! Callooh! Callay!'"
            "He chortled in his joy."

            "’Twas brillig, and the slithy toves"
            "Did gyre and gimble in the wabe:"
            "All mimsy were the borogoves,"
            "And the mome raths outgrabe.";

         const size_t text_len = strlen(text_str);

         const secure_vector<byte> all_zeros(text_len, 0);
         const secure_vector<byte> random_binary = test_rng().random_vec(text_len);

         const byte* textb = reinterpret_cast<const byte*>(text_str);
         const secure_vector<byte> text(textb, textb + text_len);

         const size_t c1_z = run_compression(*c1, *d, all_zeros);
         const size_t c9_z = run_compression(*c9, *d, all_zeros);
         const size_t c1_r = run_compression(*c1, *d, random_binary);
         const size_t c9_r = run_compression(*c9, *d, random_binary);
         const size_t c1_t = run_compression(*c1, *d, text);
         const size_t c9_t = run_compression(*c9, *d, text);

#define BOTAN_TEST_GTE(x, y, msg) if(x < y) { ++fails; std::cout << "FAIL: " << x << " " << y << " " << msg << std::endl; }

         BOTAN_TEST_GTE(c1_z, c9_z, "Level 9 compresses at least as well as level 1");
         BOTAN_TEST_GTE(c1_t, c9_t, "Level 9 compresses at least as well as level 1");
         BOTAN_TEST_GTE(c1_r, c9_r, "Level 9 compresses at least as well as level 1");

         BOTAN_TEST_GTE(c1_t, c1_z/8, "Zeros compress much better than text");
         BOTAN_TEST_GTE(c1_r, c1_t/2, "Text compress better than random");
         }
      catch(std::exception& e)
         {
         std::cout << "Failure testing " << algo << " - " << e.what() << std::endl;
         ++fails;
         }
      }

   test_report("Compression", tests, fails);

   return fails;
   }

#else

SKIP_TEST(compression);

#endif // BOTAN_HAS_COMPRESSION
