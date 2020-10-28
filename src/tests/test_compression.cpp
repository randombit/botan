/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_COMPRESSION)
   #include <botan/compression.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_COMPRESSION)

namespace {

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
   "Long time the manxome foe he sought-"
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

   "'Twas brillig, and the slithy toves"
   "Did gyre and gimble in the wabe:"
   "All mimsy were the borogoves,"
   "And the mome raths outgrabe.";

class Compression_Tests final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;
         const size_t text_len = std::strlen(text_str);

         for(std::string algo : { "zlib", "deflate", "gzip", "bz2", "lzma" })
            {
            try
               {
               Test::Result result(algo + " compression");

               std::unique_ptr<Botan::Compression_Algorithm> c(Botan::make_compressor(algo));
               std::unique_ptr<Botan::Decompression_Algorithm> d(Botan::make_decompressor(algo));

               if(!c || !d)
                  {
                  result.note_missing(algo);
                  continue;
                  }

               result.test_ne("Not the same name", c->name(), d->name());

               const Botan::secure_vector<uint8_t> empty;
               const Botan::secure_vector<uint8_t> all_zeros(text_len, 0);
               const Botan::secure_vector<uint8_t> random_binary = Test::rng().random_vec(text_len);
               const Botan::secure_vector<uint8_t> short_text = { 'f', 'o', 'o', '\n' };

               const uint8_t* textb = reinterpret_cast<const uint8_t*>(text_str);
               const Botan::secure_vector<uint8_t> text(textb, textb + text_len);

               const size_t c1_e = run_compression(result, 1, *c, *d, empty);
               const size_t c9_e = run_compression(result, 9, *c, *d, empty);
               const size_t c1_z = run_compression(result, 1, *c, *d, all_zeros);
               const size_t c9_z = run_compression(result, 9, *c, *d, all_zeros);
               const size_t c1_r = run_compression(result, 1, *c, *d, random_binary);
               const size_t c9_r = run_compression(result, 9, *c, *d, random_binary);
               const size_t c1_t = run_compression(result, 1, *c, *d, text);
               const size_t c9_t = run_compression(result, 9, *c, *d, text);
               const size_t c1_s = run_compression(result, 1, *c, *d, short_text);
               const size_t c9_s = run_compression(result, 9, *c, *d, short_text);

               result.test_gte("Empty input L1 compresses to non-empty output", c1_e, 1);
               result.test_gte("Empty input L9 compresses to non-empty output", c9_e, 1);

               result.test_gte("Level 9 compresses empty at least as well as level 1", c1_e, c9_e);
               result.test_gte("Level 9 compresses zeros at least as well as level 1", c1_z, c9_z);
               result.test_gte("Level 9 compresses random at least as well as level 1", c1_r, c9_r);
               result.test_gte("Level 9 compresses text at least as well as level 1", c1_t, c9_t);
               result.test_gte("Level 9 compresses short text at least as well as level 1", c1_s, c9_s);

               result.test_lt("Zeros compresses much better than text", c1_z / 8, c1_t);
               result.test_lt("Text compresses much better than random", c1_t / 2, c1_r);

               results.emplace_back(result);
               }
            catch(std::exception& e)
               {
               results.emplace_back(Test::Result::Failure("testing " + algo, e.what()));
               }
            }

         return results;
         }

   private:

      // Returns # of bytes of compressed message
      size_t run_compression(Test::Result& result,
                             size_t level,
                             Botan::Compression_Algorithm& c,
                             Botan::Decompression_Algorithm& d,
                             const Botan::secure_vector<uint8_t>& msg)
         {
         Botan::secure_vector<uint8_t> compressed(2*msg.size());

         for(bool with_flush : { true, false })
            {
            try
               {
               compressed = msg;

               c.start(level);
               c.update(compressed, 0, false);

               if(with_flush)
                  {
                  Botan::secure_vector<uint8_t> flush_bits;
                  c.update(flush_bits, 0, true);
                  compressed += flush_bits;
                  }

               Botan::secure_vector<uint8_t> final_bits;
               c.finish(final_bits);
               compressed += final_bits;

               Botan::secure_vector<uint8_t> decompressed = compressed;
               d.start();
               d.update(decompressed);

               Botan::secure_vector<uint8_t> final_outputs;
               d.finish(final_outputs);

               decompressed += final_outputs;

               result.test_eq("compression round tripped", msg, decompressed);
               }
            catch(Botan::Exception& e)
               {
               result.test_failure(e.what());
               }
            }

         return compressed.size();
         }
   };

BOTAN_REGISTER_TEST("compression", "compression", Compression_Tests);

class CompressionCreate_Tests final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         for(std::string algo : { "zlib", "deflate", "gzip", "bz2", "lzma" })
            {
            try
               {
               Test::Result result(algo + " create compression");

               std::unique_ptr<Botan::Compression_Algorithm> c1(Botan::Compression_Algorithm::create(algo));
               std::unique_ptr<Botan::Decompression_Algorithm> d1(Botan::Decompression_Algorithm::create(algo));

               if(!c1 || !d1)
                  {
                  result.note_missing(algo);
                  continue;
                  }
               result.test_ne("Not the same name after create", c1->name(), d1->name());

               std::unique_ptr<Botan::Compression_Algorithm> c2(Botan::Compression_Algorithm::create_or_throw(algo));
               std::unique_ptr<Botan::Decompression_Algorithm> d2(Botan::Decompression_Algorithm::create_or_throw(algo));

               if(!c2 || !d2)
                  {
                  result.note_missing(algo);
                  continue;
                  }
               result.test_ne("Not the same name after create_or_throw", c2->name(), d2->name());

               results.emplace_back(result);
               }
            catch(std::exception& e)
               {
               results.emplace_back(Test::Result::Failure("testing " + algo, e.what()));
               }
            }

            {
            Test::Result result("create invalid compression");
            result.test_throws("lookup error",
                               "Unavailable Compression bogocompress",
                               [&]() { Botan::Compression_Algorithm::create_or_throw("bogocompress"); });
            result.test_throws("lookup error",
                               "Unavailable Decompression bogocompress",
                               [&]() { Botan::Decompression_Algorithm::create_or_throw("bogocompress"); });
            results.emplace_back(result);
            }

         return results;
         }
   };

BOTAN_REGISTER_TEST("compression", "create_compression", CompressionCreate_Tests);

}

#endif

}
