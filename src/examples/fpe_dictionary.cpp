#include <botan/fpe_fe1.h>
#include <botan/hex.h>
#include <algorithm>
#include <fstream>
#include <iostream>

class Dictionary {
   public:
      explicit Dictionary(const std::string& filename) {
         std::ifstream in(filename);

         while(in.good()) {
            std::string word;
            std::getline(in, word);
            m_dict.push_back(word);
         }

         std::sort(m_dict.begin(), m_dict.end());
      }

      size_t rank(const std::string& word) const {
         auto i = std::lower_bound(m_dict.begin(), m_dict.end(), word);

         const size_t r = i - m_dict.begin();

         if(m_dict[r] != word) {
            throw std::runtime_error("The word " + word + " does not appear in the dictionary");
         }

         return r;
      }

      std::string derank(size_t rank) const { return m_dict.at(rank); }

      size_t size() const { return m_dict.size(); }

   private:
      std::vector<std::string> m_dict;
};

int main(int argc, char* argv[]) {
   if(argc <= 4) {
      std::cerr << "Usage: " << argv[0] << " <encrypt|decrypt> <dictionary file> <hex_key> words...\n";
      return 1;
   }

   try {
      const bool encrypt = [=]() {
         const std::string arg1(argv[1]);
         if(arg1 == "encrypt") {
            return true;
         } else if(arg1 == "decrypt") {
            return false;
         } else {
            throw std::invalid_argument("Expected 'encrypt' or 'decrypt' not " + arg1);
         }
      }();
      const Dictionary dict(argv[2]);
      const auto key = Botan::hex_decode(argv[3]);

      Botan::FPE_FE1 fpe(Botan::BigInt::from_u64(dict.size()));
      fpe.set_key(key);

      for(size_t i = 4; argv[i] != nullptr; ++i) {
         /*
         * The tweak ensures that even if the same input is encrypted more than
         * once it produces a different output. The same tweak must be used for
         * decryption.  Commonly this is available, eg a database row id. If not
         * available then the tweak can be set to a constant.
         */
         const uint64_t tweak = static_cast<uint64_t>(i - 4);

         auto z = Botan::BigInt(dict.rank(std::string(argv[i])));
         auto enc_z = encrypt ? fpe.encrypt(z, tweak) : fpe.decrypt(z, tweak);
         auto enc_word = dict.derank(enc_z.word_at(0));
         std::cout << enc_word << " ";
      }
      std::cout << "\n";
      return 0;
   } catch(std::exception& e) {
      std::cout << e.what() << "\n";
      return 2;
   }
}
