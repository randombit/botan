/*
* (C) 2016 Daniel Neus
*     2016,2017 Jack Lloyd
*     2017 René Korthaus
*     2017 Philippe Lieser
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#define BOTAN_NO_DEPRECATED_WARNINGS

#include "tests.h"

#if defined(BOTAN_HAS_FILTERS)
   #include <botan/secqueue.h>
   #include <botan/pipe.h>
   #include <botan/filters.h>
   #include <botan/data_snk.h>
   #include <botan/cipher_filter.h>
#endif

#if defined(BOTAN_HAS_PIPE_UNIXFD_IO)
   #include <botan/fd_unix.h>
   #include <unistd.h>
#endif

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
   #include <fstream>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_FILTERS)

class Filter_Tests final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         results.push_back(test_secqueue());
         results.push_back(test_data_src_sink());
         results.push_back(test_data_src_sink_flush());
         results.push_back(test_pipe_io());
         results.push_back(test_pipe_fd_io());
         results.push_back(test_pipe_errors());
         results.push_back(test_pipe_hash());
         results.push_back(test_pipe_mac());
         results.push_back(test_pipe_stream());
         results.push_back(test_pipe_cbc());
         results.push_back(test_pipe_cfb());
         results.push_back(test_pipe_compress());
         results.push_back(test_pipe_compress_bzip2());
         results.push_back(test_pipe_codec());
         results.push_back(test_fork());
         results.push_back(test_chain());
         results.push_back(test_threaded_fork());


         return results;
         }

   private:
      Test::Result test_secqueue()
         {
         Test::Result result("SecureQueue");

         try
            {
            Botan::SecureQueue queue_a;
            result.test_eq("queue not attachable", queue_a.attachable(), false);

            std::vector<uint8_t> test_data = {0x24, 0xB2, 0xBF, 0xC2, 0xE6, 0xD4, 0x7E, 0x04, 0x67, 0xB3};
            queue_a.write(test_data.data(), test_data.size());

            result.test_eq("size of SecureQueue is correct", queue_a.size(), test_data.size());
            result.test_eq("0 bytes read so far from SecureQueue", queue_a.get_bytes_read(), 0);

            uint8_t b;
            result.test_eq("check_available", queue_a.check_available(1), true);
            result.test_eq("check_available", queue_a.check_available(50), false);
            size_t bytes_read = queue_a.read_byte(b);
            result.test_eq("1 byte read", bytes_read, 1);

            Botan::secure_vector<uint8_t> produced(b);
            Botan::secure_vector<uint8_t> expected(test_data.at(0));
            result.test_eq("byte read is correct", produced, expected);

            result.test_eq("1 bytes read so far from SecureQueue", queue_a.get_bytes_read(), 1);

            Botan::SecureQueue queue_b;
            queue_a = queue_b;
            result.test_eq("bytes_read is set correctly", queue_a.get_bytes_read(), 0);
            }
         catch(std::exception& e)
            {
            result.test_failure("SecureQueue", e.what());
            }

         return result;
         }

      Test::Result test_data_src_sink()
         {
         Test::Result result("DataSink");

#if defined(BOTAN_HAS_CODEC_FILTERS)
         std::ostringstream oss;

         Botan::Pipe pipe(new Botan::Hex_Decoder, new Botan::DataSink_Stream(oss));

         Botan::DataSource_Memory input_mem("65666768");
         pipe.process_msg(input_mem);

         result.test_eq("output string", oss.str(), "efgh");

         Botan::DataSource_Memory input_mem2("41414141");
         pipe.process_msg(input_mem2);

         result.test_eq("output string", oss.str(), "efghAAAA");

         std::istringstream iss("4343");
         Botan::DataSource_Stream input_strm(iss);
         pipe.process_msg(input_strm);

         result.test_eq("output string", oss.str(), "efghAAAACC");
#endif
         return result;
         }

      Test::Result test_data_src_sink_flush()
         {
         Test::Result result("DataSinkFlush");

#if defined(BOTAN_HAS_CODEC_FILTERS) && defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

         const std::string tmp_name = Test::temp_file_name("botan_test_data_src_sink_flush.tmp");
         if(tmp_name.empty())
            {
            result.test_failure("Failed to create temporary file");
            return result;
            }

         std::ofstream outfile(tmp_name);

         Botan::Pipe pipe(new Botan::Hex_Decoder, new Botan::DataSink_Stream(outfile));

         Botan::DataSource_Memory input_mem("65666768");
         pipe.process_msg(input_mem);

         std::ifstream outfile_read(tmp_name);
         std::stringstream ss;
         ss << outfile_read.rdbuf();
         std::string foo = ss.str();

         result.test_eq("output string", ss.str(), "efgh");

         // ensure files are closed
         outfile.close();
         outfile_read.close();

         if(std::remove(tmp_name.c_str()) != 0)
            {
            result.test_failure("Failed to remove temporary file at conclusion of test");
            }
#endif
         return result;
         }

      Test::Result test_pipe_io()
         {
         Test::Result result("Pipe I/O operators");

#if defined(BOTAN_HAS_CODEC_FILTERS)
         Botan::Pipe pipe(new Botan::Hex_Encoder);

         pipe.process_msg("ABCD");

         std::ostringstream oss;
         oss << pipe;
         result.test_eq("output string", oss.str(), "41424344");

         std::istringstream iss("AAAA");
         pipe.start_msg();
         iss >> pipe;
         pipe.end_msg();

         pipe.set_default_msg(1);
         oss << pipe;
         result.test_eq("output string2", oss.str(), "4142434441414141");
#endif

         return result;
         }

      Test::Result test_pipe_errors()
         {
         Test::Result result("Pipe");

         Botan::Pipe pipe;

         pipe.append(nullptr); // ignored
         pipe.append_filter(nullptr); // ignored
         pipe.prepend(nullptr); // ignored
         pipe.prepend_filter(nullptr); // ignored
         pipe.pop(); // empty pipe, so ignored

         std::unique_ptr<Botan::Filter> queue_filter(new Botan::SecureQueue);

         // can't explicitly insert a queue into the pipe because they are implicit
         result.test_throws("pipe error",
                            "Pipe::append: SecureQueue cannot be used",
                            [&]() { pipe.append(queue_filter.get()); });

         result.test_throws("pipe error",
                            "Pipe::prepend: SecureQueue cannot be used",
                            [&]() { pipe.prepend(queue_filter.get()); });

         pipe.append_filter(new Botan::BitBucket); // succeeds
         pipe.pop();

         pipe.prepend_filter(new Botan::BitBucket); // succeeds
         pipe.pop();

         pipe.start_msg();

         std::unique_ptr<Botan::Filter> filter(new Botan::BitBucket);

         // now inside a message, cannot modify pipe structure

         result.test_throws("pipe error",
                            "Cannot call Pipe::append_filter after start_msg",
                            [&]() { pipe.append_filter(filter.get()); });

         result.test_throws("pipe error",
                            "Cannot call Pipe::prepend_filter after start_msg",
                            [&]() { pipe.prepend_filter(filter.get()); });

         result.test_throws("pipe error",
                            "Cannot append to a Pipe while it is processing",
                            [&]() { pipe.append(filter.get()); });

         result.test_throws("pipe error",
                            "Cannot prepend to a Pipe while it is processing",
                            [&]() { pipe.prepend(filter.get()); });

         result.test_throws("pipe error",
                            "Cannot pop off a Pipe while it is processing",
                            [&]() { pipe.pop(); });

         pipe.end_msg();

         result.test_throws("pipe error",
                            "Cannot call Pipe::append_filter after start_msg",
                            [&]() { pipe.append_filter(filter.get()); });

         result.test_throws("pipe error",
                            "Cannot call Pipe::prepend_filter after start_msg",
                            [&]() { pipe.prepend_filter(filter.get()); });

         result.test_throws("pipe error",
                            "Pipe::read: Invalid message number 100",
                            [&]() { uint8_t b; size_t got = pipe.read(&b, 1, 100); BOTAN_UNUSED(got); });

         pipe.append(nullptr); // ignored
         pipe.prepend(nullptr); // ignored
         pipe.pop(); // empty pipe, so ignored

         return result;
         }

      Test::Result test_pipe_mac()
         {
         Test::Result result("Pipe");

#if defined(BOTAN_HAS_CODEC_FILTERS) && defined(BOTAN_HAS_HMAC) && defined(BOTAN_HAS_SHA2_32)
         const Botan::SymmetricKey key("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");

         Botan::Keyed_Filter* mac_filter = new Botan::MAC_Filter("HMAC(SHA-256)", key, 12);

         mac_filter->set_iv(Botan::InitializationVector()); // ignored

         result.test_throws("Keyed_Filter::set_iv throws if not implemented",
                            "IV length 1 is invalid for HMAC(SHA-256)",
                            [mac_filter]() { mac_filter->set_iv(Botan::InitializationVector("AA")); });

         Botan::Pipe pipe(mac_filter,
                          new Botan::Base64_Encoder);

         pipe.process_msg("Hi");
         pipe.process_msg("Bye");
         pipe.process_msg("Hi");

         result.test_eq("MAC 1", pipe.read_all_as_string(0), "e7NoVbtudgU0QiCZ");
         result.test_eq("MAC 2", pipe.read_all_as_string(1), "LhPnfEG+0rk+Ej6y");
         result.test_eq("MAC 3", pipe.read_all_as_string(2), "e7NoVbtudgU0QiCZ");
#endif
         return result;
         }

      Test::Result test_pipe_hash()
         {
         Test::Result result("Pipe");

#if defined(BOTAN_HAS_SHA2_32)
         // unrelated test of popping a chain
         Botan::Pipe pipe(new Botan::Chain(new Botan::Hash_Filter("SHA-224"), new Botan::Hash_Filter("SHA-224")));
         pipe.pop();

         pipe.append(new Botan::Hash_Filter("SHA-256"));

         result.test_eq("Message count", pipe.message_count(), 0);

         pipe.start_msg();
         uint8_t inb = 0x41;
         pipe.write(&inb, 1);
         pipe.write(std::vector<uint8_t>(6, 0x41));
         pipe.write(inb);
         pipe.end_msg();

         result.test_eq("Message count", pipe.message_count(), 1);
         result.test_eq("Message size", pipe.remaining(), 32);

         std::vector<uint8_t> out(32), last16(16);

         result.test_eq("Bytes read", pipe.get_bytes_read(0), 0);
         result.test_eq("More to read", pipe.end_of_data(), false);
         result.test_eq("Expected read count", pipe.read(&out[0], 5), 5);
         result.test_eq("Bytes read", pipe.get_bytes_read(0), 5);
         result.test_eq("Peek read", pipe.peek(last16.data(), 18, 11), 16);
         result.test_eq("Expected read count", pipe.read(&out[5], 17), 17);
         result.test_eq("Bytes read", pipe.get_bytes_read(0), 22);
         result.test_eq("Remaining", pipe.remaining(), 10);
         result.test_eq("Remaining", pipe.remaining(), 10);
         result.test_eq("Expected read count", pipe.read(&out[22], 12), 10);
         result.test_eq("Expected read count", pipe.read(&out[0], 1), 0); // no more output
         result.test_eq("Bytes read", pipe.get_bytes_read(0), 32);
         result.test_eq("No more to read", pipe.end_of_data(), true);

         result.test_eq("Expected output", out, "C34AB6ABB7B2BB595BC25C3B388C872FD1D575819A8F55CC689510285E212385");
         result.test_eq("Expected last16", last16, "D1D575819A8F55CC689510285E212385");

         pipe.reset();

#if defined(BOTAN_HAS_CRC32)
         pipe.prepend(new Botan::Hash_Filter("CRC32"));
         pipe.append(new Botan::Hash_Filter("CRC32"));
         pipe.process_msg(std::vector<uint8_t>(1024, 0));
         result.test_eq("Expected CRC32d", pipe.read_all(1), "99841F60");
#endif
#endif
         return result;
         }

      Test::Result test_pipe_cfb()
         {
         Test::Result result("Pipe CFB");

#if defined(BOTAN_HAS_BLOWFISH) && defined(BOTAN_HAS_MODE_CFB) && defined(BOTAN_HAS_CODEC_FILTERS)

         // Generated with Botan 1.10

         const Botan::InitializationVector iv("AABBCCDDEEFF0123");
         const Botan::SymmetricKey key("AABBCCDDEEFF0123");

         const uint8_t msg_bits[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

         const std::string cfb_expected[] = {
            "A4",
            "BEA4",
            "06AD98",
            "E4AFC5AC",
            "A9B531559C",
            "38B60DA66445",
            "194F5E93199839",
            "093B6381D2E5D806",
            "B44FA624226EECF027",
            "80B8DC3332A835AC11A8",
            "2C0E910A1E5C38344CC5BB",
            "3CB6180AE2E189342F681023",
            "DE0F4B10C7D9CADDB5A9078199",
            "FAE18B0ED873F234CCD6E1555B2D",
            "7195FFE735B0A95065BA244C77A11F",
         };

         Botan::Keyed_Filter* cfb_enc = Botan::get_cipher("Blowfish/CFB", key, iv, Botan::ENCRYPTION);
         Botan::Pipe enc_pipe(cfb_enc, new Botan::Hex_Encoder);

         Botan::Keyed_Filter* cfb_dec = Botan::get_cipher("Blowfish/CFB", key, Botan::DECRYPTION);
         cfb_dec->set_iv(iv);
         Botan::Pipe dec_pipe(new Botan::Hex_Decoder, cfb_dec, new Botan::Hex_Encoder);

         for(size_t i = 1; i != sizeof(msg_bits); ++i)
            {
            enc_pipe.start_msg();
            enc_pipe.write(msg_bits, i);
            enc_pipe.end_msg();

            dec_pipe.process_msg(cfb_expected[i-1]);
            }

         result.test_eq("enc pipe msg count", enc_pipe.message_count(), sizeof(msg_bits) - 1);
         result.test_eq("dec pipe msg count", dec_pipe.message_count(), sizeof(msg_bits) - 1);

         for(size_t i = 0; i != enc_pipe.message_count(); ++i)
            {
            result.test_eq("encrypt", enc_pipe.read_all_as_string(i), cfb_expected[i]);
            }

         for(size_t i = 0; i != dec_pipe.message_count(); ++i)
            {
            result.test_eq("decrypt", dec_pipe.read_all_as_string(i),
                           Botan::hex_encode(msg_bits, i+1));
            }
#endif

         return result;
         }

      Test::Result test_pipe_cbc()
         {
         Test::Result result("Pipe CBC");

#if defined(BOTAN_HAS_AES) && defined(BOTAN_HAS_MODE_CBC) && defined(BOTAN_HAS_CIPHER_MODE_PADDING)
         Botan::Cipher_Mode_Filter* cipher =
            new Botan::Cipher_Mode_Filter(Botan::Cipher_Mode::create("AES-128/CBC/PKCS7", Botan::ENCRYPTION));

         result.test_eq("Cipher filter name", cipher->name(), "AES-128/CBC/PKCS7");

         result.test_eq("Cipher filter nonce size", cipher->valid_iv_length(16), true);
         result.test_eq("Cipher filter nonce size", cipher->valid_iv_length(17), false);

         result.test_eq("Cipher key length max", cipher->key_spec().maximum_keylength(), 16);
         result.test_eq("Cipher key length min", cipher->key_spec().minimum_keylength(), 16);

         // takes ownership of cipher
         Botan::Pipe pipe(cipher);

         cipher->set_key(Botan::SymmetricKey("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
         cipher->set_iv(Botan::InitializationVector("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));

         pipe.process_msg("Don't use plain CBC mode");

         result.test_eq("Message count", pipe.message_count(), 1);
         result.test_eq("Bytes read", pipe.get_bytes_read(), 0);
         auto ciphertext = pipe.read_all();
         result.test_eq("Bytes read after", pipe.get_bytes_read(), ciphertext.size());

         result.test_eq("Ciphertext", ciphertext, "9BDD7300E0CB61CA71FFF957A71605DB 6836159C36781246A1ADF50982757F4B");

         pipe.process_msg("IV carryover");
         auto ciphertext2 = pipe.read_all(1);
         pipe.process_msg("IV carryover2");
         auto ciphertext3 = pipe.read_all(2);

         // These values tested against PyCrypto
         result.test_eq("Ciphertext2", ciphertext2, "AA8D682958A4A044735DAC502B274DB2");
         result.test_eq("Ciphertext3", ciphertext3, "1241B9976F73051BCF809525D6E86C25");

         Botan::Cipher_Mode_Filter* dec_cipher =
            new Botan::Cipher_Mode_Filter(Botan::Cipher_Mode::create("AES-128/CBC/PKCS7", Botan::DECRYPTION));
         pipe.append(dec_cipher);
         dec_cipher->set_key(Botan::SymmetricKey("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
         dec_cipher->set_iv(Botan::InitializationVector("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB"));

         // reset the IV on the encryption filter
         cipher->set_iv(Botan::InitializationVector("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB"));

         const std::vector<uint8_t> zeros_in(1024);
         Botan::DataSource_Memory src(zeros_in);
         pipe.start_msg();
         pipe.write(src);
         pipe.end_msg();

         pipe.set_default_msg(3);
         result.test_eq("Bytes read", pipe.get_bytes_read(), 0);
         Botan::secure_vector<uint8_t> zeros_out = pipe.read_all();
         result.test_eq("Bytes read", pipe.get_bytes_read(), zeros_out.size());

         result.test_eq("Cipher roundtrip", zeros_in, zeros_out);
#endif
         return result;
         }

      Test::Result test_pipe_compress()
         {
         Test::Result result("Pipe compress zlib");

#if defined(BOTAN_HAS_ZLIB)

         std::unique_ptr<Botan::Compression_Filter> comp_f(new Botan::Compression_Filter("zlib", 9));

         result.test_eq("Compressor filter name", comp_f->name(), "Zlib_Compression");
         Botan::Pipe pipe(comp_f.release());

         const std::string input_str = "Hello there HELLO there I said is this thing on?";

         pipe.start_msg();
         pipe.write(input_str);
         pipe.end_msg();

         auto compr = pipe.read_all(0);
         // Can't do equality check on compression because output may differ
         result.test_lt("Compressed is shorter", compr.size(), input_str.size());

         std::unique_ptr<Botan::Decompression_Filter> decomp_f(new Botan::Decompression_Filter("zlib"));
         result.test_eq("Decompressor name", decomp_f->name(), "Zlib_Decompression");
         pipe.append(decomp_f.release());
         pipe.pop(); // remove compressor

         pipe.process_msg(compr);

         std::string decomp = pipe.read_all_as_string(1);
         result.test_eq("Decompressed ok", decomp, input_str);
#endif

         return result;
         }

      Test::Result test_pipe_compress_bzip2()
         {
         Test::Result result("Pipe compress bzip2");

#if defined(BOTAN_HAS_BZIP2)

         std::unique_ptr<Botan::Compression_Filter> comp_f(new Botan::Compression_Filter("bzip2", 9));

         result.test_eq("Compressor filter name", comp_f->name(), "Bzip2_Compression");
         Botan::Pipe pipe(comp_f.release());

         const std::string input_str = "foo\n";

         pipe.start_msg();
         pipe.write(input_str);
         pipe.end_msg();

         auto compr = pipe.read_all(0);
         // Here the output is actually longer than the input as input is so short

         std::unique_ptr<Botan::Decompression_Filter> decomp_f(new Botan::Decompression_Filter("bzip2"));
         result.test_eq("Decompressor name", decomp_f->name(), "Bzip2_Decompression");
         pipe.append(decomp_f.release());
         pipe.pop(); // remove compressor

         pipe.process_msg(compr);

         std::string decomp = pipe.read_all_as_string(1);
         result.test_eq("Decompressed ok", decomp, input_str);
#endif

         return result;
         }

      Test::Result test_pipe_codec()
         {
         Test::Result result("Pipe");

#if defined(BOTAN_HAS_CODEC_FILTERS)
         Botan::Pipe pipe(new Botan::Base64_Encoder);

         result.test_eq("Message count", pipe.message_count(), 0);

         pipe.process_msg("ABCDX");

         result.test_eq("Message count", pipe.message_count(), 1);
         result.test_eq("Message size", pipe.remaining(), 8);

         std::string output = pipe.read_all_as_string(0);
         result.test_eq("Message size", pipe.remaining(0), 0);
         result.test_eq("Output round tripped", output, "QUJDRFg=");

         pipe.append(new Botan::Base64_Decoder);
         pipe.process_msg("FOOBAZ");

         result.test_eq("base64 roundtrip", pipe.read_all_as_string(1), "FOOBAZ");

         pipe.pop();
         pipe.pop();

         // Pipe is empty of filters, should still pass through
         pipe.process_msg("surprise plaintext");

         pipe.set_default_msg(2);
         result.test_eq("Message 2", pipe.read_all_as_string(), "surprise plaintext");

         pipe.append(new Botan::Hex_Decoder);

         pipe.process_msg("F331F00D");
         Botan::secure_vector<uint8_t> bin = pipe.read_all(3);
         result.test_eq("hex decoded", bin, "F331F00D");

         pipe.append(new Botan::Hex_Encoder);
         pipe.process_msg("F331F00D");
         result.test_eq("hex roundtrip", pipe.read_all_as_string(4), "F331F00D");

         // Now tests with line wrapping enabled

         pipe.reset();
         pipe.append(new Botan::Hex_Decoder);
         pipe.append(new Botan::Base64_Encoder(/*break_lines=*/true,
                     /*line_length=*/4,
                     /*trailing_newline=*/true));

         pipe.process_msg("6dab1eeb8a2eb69bad");
         result.test_eq("base64 with linebreaks and trailing newline", pipe.read_all_as_string(5), "base\n64ou\ntput\n\n");

         pipe.reset();
         pipe.append(new Botan::Hex_Decoder);
         pipe.append(new Botan::Base64_Encoder(true, 5, false));
         pipe.process_msg("6dab1eeb8a2eb69bad");
         result.test_eq("base64 with linebreaks", pipe.read_all_as_string(6), "base6\n4outp\nut\n");

         pipe.reset();
         pipe.append(new Botan::Hex_Encoder(true, 13, Botan::Hex_Encoder::Uppercase));
         pipe.process_msg("hex encoding this string");
         result.test_eq("hex uppercase with linebreaks", pipe.read_all_as_string(7),
                        "68657820656E6\n36F64696E6720\n7468697320737\n472696E67\n");

         pipe.reset();
         pipe.append(new Botan::Hex_Encoder(true, 16, Botan::Hex_Encoder::Lowercase));
         pipe.process_msg("hex encoding this string");
         result.test_eq("hex lowercase with linebreaks", pipe.read_all_as_string(8),
                        "68657820656e636f\n64696e6720746869\n7320737472696e67\n");
#endif

         return result;
         }

      Test::Result test_pipe_stream()
         {
         Test::Result result("Pipe CTR");

#if defined(BOTAN_HAS_CTR_BE) && defined(BOTAN_HAS_AES)
         Botan::Keyed_Filter* aes = nullptr;
         const Botan::SymmetricKey some_other_key("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE");
         const Botan::SymmetricKey key("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
         const Botan::InitializationVector iv("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
         Botan::Pipe pipe(aes = new Botan::StreamCipher_Filter("CTR-BE(AES-128)", some_other_key));

         aes->set_key(key);
         aes->set_iv(iv);

         pipe.process_msg("ABCDEF");

         result.test_eq("Message count", pipe.message_count(), 1);
         result.test_eq("Ciphertext", pipe.read_all(), "FDFD6238F7C6");

         pipe.process_msg("ABCDEF");
         result.test_eq("Ciphertext", pipe.read_all(1), "8E72F1153514");
#endif
         return result;
         }

      Test::Result test_fork()
         {
         Test::Result result("Filter Fork");

#if defined(BOTAN_HAS_SHA2_32) && defined(BOTAN_HAS_SHA2_64)
         Botan::Pipe pipe(new Botan::Fork(new Botan::Hash_Filter("SHA-256"),
                                          new Botan::Hash_Filter("SHA-512-256")));

         result.test_eq("Message count", pipe.message_count(), 0);
         pipe.process_msg("OMG");
         result.test_eq("Message count", pipe.message_count(), 2);

         // Test reading out of order
         result.test_eq("Hash 2", pipe.read_all(1), "610480FFA82F24F6926544B976FE387878E3D973C03DFD591C2E9896EFB903E0");
         result.test_eq("Hash 1", pipe.read_all(0), "C00862D1C6C1CF7C1B49388306E7B3C1BB79D8D6EC978B41035B556DBB3797DF");
#endif
         return result;
         }

      Test::Result test_chain()
         {
         Test::Result result("Filter Chain");

#if defined(BOTAN_HAS_CODEC_FILTERS) && defined(BOTAN_HAS_SHA2_32) && defined(BOTAN_HAS_SHA2_64)

         Botan::Filter* filters[2] = {
            new Botan::Hash_Filter("SHA-256"),
            new Botan::Hex_Encoder
         };

         std::unique_ptr<Botan::Chain> chain(new Botan::Chain(filters, 2));

         result.test_eq("Chain has a name", chain->name(), "Chain");

         std::unique_ptr<Botan::Fork> fork(
            new Botan::Fork(
               chain.release(),
               new Botan::Chain(new Botan::Hash_Filter("SHA-512-256", 19), new Botan::Hex_Encoder)
            ));

         result.test_eq("Fork has a name", fork->name(), "Fork");
         Botan::Pipe pipe(fork.release());

         result.test_eq("Message count", pipe.message_count(), 0);
         pipe.process_msg("OMG");
         result.test_eq("Message count", pipe.message_count(), 2);

         result.test_eq("Hash 1", pipe.read_all_as_string(0),
                        "C00862D1C6C1CF7C1B49388306E7B3C1BB79D8D6EC978B41035B556DBB3797DF");
         result.test_eq("Hash 2", pipe.read_all_as_string(1),
                        "610480FFA82F24F6926544B976FE387878E3D9");
#endif

         return result;
         }

      Test::Result test_pipe_fd_io()
         {
         Test::Result result("Pipe file descriptor IO");

#if defined(BOTAN_HAS_PIPE_UNIXFD_IO) && defined(BOTAN_HAS_CODEC_FILTERS)
         int fd[2];
         if(::pipe(fd) != 0)
            return result; // pipe unavailable?

         Botan::Pipe hex_enc(new Botan::Hex_Encoder);
         Botan::Pipe hex_dec(new Botan::Hex_Decoder);

         hex_enc.process_msg("hi chappy");
         fd[1] << hex_enc;
         ::close(fd[1]);

         hex_dec.start_msg();
         fd[0] >> hex_dec;
         hex_dec.end_msg();
         ::close(fd[0]);

         std::string dec = hex_dec.read_all_as_string();

         result.test_eq("IO through Unix pipe works", dec, "hi chappy");
#endif

         return result;
         }

      Test::Result test_threaded_fork()
         {
         Test::Result result("Threaded_Fork");

#if defined(BOTAN_HAS_THREAD_UTILS) && defined(BOTAN_HAS_CODEC_FILTERS) && defined(BOTAN_HAS_SHA2_32)
         Botan::Pipe pipe(new Botan::Threaded_Fork(new Botan::Hex_Encoder, new Botan::Base64_Encoder));

         result.test_eq("Message count", pipe.message_count(), 0);
         pipe.process_msg("woo");
         result.test_eq("Message count", pipe.message_count(), 2);

         // Test reading out of order
         result.test_eq("Hash 2", pipe.read_all_as_string(1), "d29v");
         result.test_eq("Hash 1", pipe.read_all_as_string(0), "776F6F");

         pipe.reset();

         const size_t filter_count = 5;
         Botan::Filter* filters[filter_count];
         for(size_t i = 0; i != filter_count; ++i)
            {
            filters[i] = new Botan::Hash_Filter("SHA-256");
            }

         pipe.append(new Botan::Threaded_Fork(filters, filter_count));

         result.test_eq("Message count before start_msg", pipe.message_count(), 2);

         pipe.start_msg();
         for(size_t i = 0; i != 919; ++i)
            {
            std::vector<uint8_t> input(i + 5, static_cast<uint8_t>(i));
            pipe.write(input);
            }
         pipe.end_msg();

         result.test_eq("Message count after end_msg", pipe.message_count(), 2 + filter_count);
         for(size_t i = 0; i != filter_count; ++i)
            {
            result.test_eq("Output " + std::to_string(i), pipe.read_all(2 + i),
                           "327AD8055223F5926693D8BEA40F7B35BDEEB535647DFB93F464E40EA01939A9");
            }
#endif
         return result;
         }

   };

BOTAN_REGISTER_TEST("filters", "filter", Filter_Tests);

#endif

}
