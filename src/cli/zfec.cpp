/*
* (C) 2021 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_ZFEC) && defined(BOTAN_HAS_SHA2_64)
   #include <botan/hash.h>
   #include <botan/mem_ops.h>
   #include <botan/zfec.h>
   #include <botan/internal/loadstor.h>
   #include <fstream>
   #include <sstream>
#endif

namespace Botan_CLI {

#if defined(BOTAN_HAS_ZFEC) && defined(BOTAN_HAS_SHA2_64)

static const uint32_t FEC_MAGIC = 0xFECC0DEC;
const char* const FEC_SHARE_HASH = "SHA-512-256";

class FEC_Share final {
   public:
      FEC_Share() : m_share(0), m_k(0), m_n(0), m_padding(0), m_bits() {}

      FEC_Share(size_t share, size_t k, size_t n, size_t padding, const uint8_t bits[], size_t len) :
            m_share(share), m_k(k), m_n(n), m_padding(padding), m_bits(bits, bits + len) {}

      size_t share_id() const { return m_share; }

      size_t k() const { return m_k; }

      size_t n() const { return m_n; }

      size_t padding() const { return m_padding; }

      size_t share_size() const { return m_bits.size(); }

      const uint8_t* share_data() const { return m_bits.data(); }

      static FEC_Share deserialize(const uint8_t bits[], size_t len, Botan::HashFunction& hash) {
         const size_t hash_len = hash.output_length();

         if(len < FEC_SHARE_HEADER_LEN + hash_len) {
            throw CLI_Error("FEC share is too short to be valid");
         }

         if(Botan::load_be<uint32_t>(bits, 0) != FEC_MAGIC) {
            throw CLI_Error("FEC share does not have expected magic bytes");
         }

         // verify that reserved bytes are zero
         for(size_t i = 8; i != 12; ++i) {
            if(bits[i] != 0) {
               throw CLI_Error("FEC share has reserved header bytes set");
            }
         }

         size_t share_id = bits[4];
         size_t k = bits[5];
         size_t n = bits[6];
         size_t padding = bits[7];

         if(share_id >= n || k >= n || padding >= k) {
            throw CLI_Error("FEC share has invalid k/n/padding fields");
         }

         hash.update(bits, len - hash_len);
         auto share_hash = hash.final();

         const bool digest_ok = Botan::constant_time_compare(share_hash.data(), &bits[len - hash_len], hash_len);

         if(!digest_ok) {
            throw CLI_Error("FEC share has invalid hash");
         }

         return FEC_Share(
            share_id, k, n, padding, bits + FEC_SHARE_HEADER_LEN, len - (FEC_SHARE_HEADER_LEN + hash_len));
      }

      void serialize_to(Botan::HashFunction& hash, std::ostream& out) const {
         uint8_t header[FEC_SHARE_HEADER_LEN] = {0};

         Botan::store_be(FEC_MAGIC, header);
         header[4] = static_cast<uint8_t>(m_share);
         header[5] = static_cast<uint8_t>(m_k);
         header[6] = static_cast<uint8_t>(m_n);
         header[7] = static_cast<uint8_t>(m_padding);
         // bytes 8..12 left as zero/reserved

         out.write(reinterpret_cast<const char*>(header), sizeof(header));
         out.write(reinterpret_cast<const char*>(m_bits.data()), m_bits.size());

         hash.update(header, sizeof(header));
         hash.update(m_bits);
         auto digest = hash.final();

         out.write(reinterpret_cast<const char*>(digest.data()), digest.size());
      }

   private:
      static const size_t FEC_SHARE_HEADER_LEN = 12;

      size_t m_share;
      size_t m_k;
      size_t m_n;
      size_t m_padding;
      std::vector<uint8_t> m_bits;
};

class FEC_Encode final : public Command {
   public:
      FEC_Encode() : Command("fec_encode --suffix=fec --prefix= --output-dir= k n input") {}

      std::string group() const override { return "fec"; }

      std::string description() const override { return "Forward error encode a file"; }

      void go() override {
         const size_t k = get_arg_sz("k");
         const size_t n = get_arg_sz("n");

         const std::string suffix = get_arg("suffix");
         const std::string prefix = get_arg("prefix");
         const std::string input = get_arg("input");
         const std::string output_dir = get_arg("output-dir");

         Botan::ZFEC fec(k, n);  // checks k/n for validity

         auto hash = Botan::HashFunction::create_or_throw(FEC_SHARE_HASH);

         auto input_data = slurp_file(get_arg("input"));

         // append a hash of the input
         hash->update(input_data);
         const auto hash_of_input = hash->final();
         input_data.insert(input_data.end(), hash_of_input.begin(), hash_of_input.end());

         // add padding 0x00 bytes as needed to round up to k multiple
         size_t padding = 0;
         while(input_data.size() % k != 0) {
            padding += 1;
            input_data.push_back(0x00);
         }

         auto encoder_fn = [&](size_t share, const uint8_t bits[], size_t len) {
            std::ostringstream output_fsname;

            if(!output_dir.empty()) {
               output_fsname << output_dir << "/";
            }

            if(!prefix.empty()) {
               output_fsname << prefix;
            } else {
               output_fsname << input;
            }

            output_fsname << "." << (share + 1) << "_" << n;

            if(!suffix.empty()) {
               output_fsname << "." << suffix;
            }

            std::ofstream output(output_fsname.str(), std::ios::binary);

            FEC_Share fec_share(share, k, n, padding, bits, len);
            fec_share.serialize_to(*hash, output);
         };

         fec.encode(input_data.data(), input_data.size(), encoder_fn);
      }
};

BOTAN_REGISTER_COMMAND("fec_encode", FEC_Encode);

class FEC_Decode final : public Command {
   public:
      FEC_Decode() : Command("fec_decode *shares") {}

      std::string group() const override { return "fec"; }

      std::string description() const override { return "Recover data from FEC shares"; }

      void go() override {
         auto hash = Botan::HashFunction::create_or_throw(FEC_SHARE_HASH);
         const size_t hash_len = hash->output_length();

         std::vector<FEC_Share> shares;

         for(const auto& share_fsname : get_arg_list("shares")) {
            const auto share_bits = slurp_file(share_fsname);

            try {
               auto share = FEC_Share::deserialize(share_bits.data(), share_bits.size(), *hash);
               shares.push_back(share);
            } catch(std::exception& e) {
               error_output() << "Ignoring invalid share '" << share_fsname << "': " << e.what() << "\n";
            }
         }

         if(shares.empty()) {
            error_output() << "Must provide a list of at least k shares\n";
            this->set_return_code(1);
            return;
         }

         size_t k = 0;
         size_t n = 0;
         size_t padding = 0;
         size_t share_size = 0;

         for(const auto& share : shares) {
            if(k == 0 && n == 0 && padding == 0) {
               k = share.k();
               n = share.n();
               padding = share.padding();
               share_size = share.share_size();
            } else {
               if(share.k() != k || share.n() != n || share.padding() != padding || share.share_size() != share_size) {
                  error_output() << "Shares have mismatched k/n/padding/size values\n";
                  this->set_return_code(2);
                  return;
               }
            }
         }

         if(shares.size() < k) {
            error_output() << "At least " << k << " shares are required for recovery\n";
            this->set_return_code(2);
            return;
         }

         Botan::ZFEC fec(k, n);

         std::vector<uint8_t> decoded(share_size * k);

         auto decoder_fn = [&](size_t share, const uint8_t bits[], size_t len) {
            std::memcpy(&decoded[share * share_size], bits, len);
         };

         std::map<size_t, const uint8_t*> share_ptrs;

         for(auto& share : shares) {
            share_ptrs[share.share_id()] = share.share_data();
         }

         fec.decode_shares(share_ptrs, share_size, decoder_fn);

         auto decoded_digest = hash->process(decoded.data(), decoded.size() - (hash_len + padding));

         if(!Botan::constant_time_compare(
               decoded_digest.data(), &decoded[decoded.size() - (hash_len + padding)], hash_len)) {
            throw CLI_Error("Recovered data failed digest check");
         }

         for(size_t i = 0; i != padding; ++i) {
            if(decoded[decoded.size() - padding + i] != 0) {
               throw CLI_Error("Recovered data had non-zero padding bytes");
            }
         }

         output_binary().write(reinterpret_cast<const char*>(decoded.data()), decoded.size() - (hash_len + padding));
      }
};

BOTAN_REGISTER_COMMAND("fec_decode", FEC_Decode);

class FEC_Info final : public Command {
   public:
      FEC_Info() : Command("fec_info share") {}

      std::string group() const override { return "fec"; }

      std::string description() const override { return "Display information about a FEC share"; }

      void go() override {
         auto hash = Botan::HashFunction::create_or_throw(FEC_SHARE_HASH);

         const std::string share_fsname = get_arg("share");
         const auto share_bits = slurp_file(share_fsname);

         try {
            auto share = FEC_Share::deserialize(share_bits.data(), share_bits.size(), *hash);
            output() << "FEC share " << share.share_id() + 1 << "/" << share.n() << " with " << share.k()
                     << " needed for recovery\n";
         } catch(std::exception& e) {
            error_output() << "Invalid share '" << share_fsname << "': " << e.what() << "\n";
         }
      }
};

BOTAN_REGISTER_COMMAND("fec_info", FEC_Info);

#endif

}  // namespace Botan_CLI
