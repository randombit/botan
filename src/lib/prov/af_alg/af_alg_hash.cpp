/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/af_alg_hash.h>
#include <botan/internal/af_alg_util.h>
#include <botan/hash.h>
#include <botan/exceptn.h>

namespace Botan {

namespace {

class AF_Alg_Hash final : public HashFunction
   {
   public:
      AF_Alg_Hash(const std::string& lib_name,
                  const std::string& kernel_name,
                  size_t output_size,
                  size_t block_size) :
         m_lib_name(lib_name),
         m_kernel_name(kernel_name),
         m_output_size(output_size),
         m_block_size(block_size),
         m_socket("hash", kernel_name)
         {}

      size_t output_length() const override { return m_output_size; }

      size_t hash_block_size() const override final { return m_block_size; }

      std::string name() const override { return m_lib_name; }

      std::string provider() const override { return "af_alg"; }

      void clear() override
         {
         std::vector<uint8_t> output(m_output_size);
         m_socket.write_data(nullptr, 0, false);
         m_socket.read_data(output.data(), output.size());
         }

      std::unique_ptr<HashFunction> copy_state() const override
         {
         throw Invalid_State("AF_Alg objects cannot be copied");
         }

      HashFunction* clone() const override
         {
         return new AF_Alg_Hash(m_lib_name, m_kernel_name, m_output_size, m_block_size);
         }

      void add_data(const uint8_t buf[], size_t len) override
         {
         m_socket.write_data(buf, len, true);
         }

      void final_result(uint8_t out[]) override
         {
         m_socket.read_data(out, m_output_size);
         }

   private:
      std::string m_lib_name;
      std::string m_kernel_name;
      size_t m_output_size;
      size_t m_block_size;
      AF_Alg_Socket m_socket;
   };

}

std::unique_ptr<HashFunction> create_af_alg_hash(const std::string& name)
   {
   if(name == "MD5")
      return std::unique_ptr<HashFunction>(new AF_Alg_Hash(name, "md5", 16, 64));
   if(name == "SHA-1" || name == "SHA-160")
      return std::unique_ptr<HashFunction>(new AF_Alg_Hash(name, "sha1", 20, 64));
   if(name == "SHA-256")
      return std::unique_ptr<HashFunction>(new AF_Alg_Hash(name, "sha256", 32, 64));
   if(name == "SHA-384")
      return std::unique_ptr<HashFunction>(new AF_Alg_Hash(name, "sha384", 48, 128));
   if(name == "SHA-512")
      return std::unique_ptr<HashFunction>(new AF_Alg_Hash(name, "sha512", 64, 128));

   return nullptr;
   }


}
