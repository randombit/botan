/*************************************************
* OpenSSL ARC4 Source File                       *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/eng_ossl.h>
#include <botan/lookup.h>
#include <botan/parsing.h>
#include <openssl/rc4.h>

namespace Botan {

namespace {

/*************************************************
* OpenSSL ARC4                                   *
*************************************************/
class OpenSSL_ARC4 : public StreamCipher
   {
   public:
      void clear() throw() { std::memset(&state, 0, sizeof(state)); }
      std::string name() const;
      StreamCipher* clone() const { return new OpenSSL_ARC4(SKIP); }
      OpenSSL_ARC4(u32bit s = 0) : StreamCipher(1, 32), SKIP(s) { clear(); }
      ~OpenSSL_ARC4() { clear(); }
   private:
      void cipher(const byte[], byte[], u32bit);
      void key(const byte[], u32bit);

      const u32bit SKIP;
      RC4_KEY state;
   };

/*************************************************
* Return the name of this type                   *
*************************************************/
std::string OpenSSL_ARC4::name() const
   {
   if(SKIP == 0)   return "ARC4";
   if(SKIP == 256) return "MARK-4";
   else            return "RC4_skip(" + to_string(SKIP) + ")";
   }

/*************************************************
* ARC4 Key Schedule                              *
*************************************************/
void OpenSSL_ARC4::key(const byte key[], u32bit length)
   {
   RC4_set_key(&state, length, key);
   byte dummy = 0;
   for(u32bit j = 0; j != SKIP; j++)
      RC4(&state, 1, &dummy, &dummy);
   }

/*************************************************
* ARC4 Encryption                                *
*************************************************/
void OpenSSL_ARC4::cipher(const byte in[], byte out[], u32bit length)
   {
   RC4(&state, length, in, out);
   }

}

/*************************************************
* Look for an algorithm with this name           *
*************************************************/
StreamCipher*
OpenSSL_Engine::find_stream_cipher(const std::string& algo_spec) const
   {
   std::vector<std::string> name = parse_algorithm_name(algo_spec);
   if(name.size() == 0)
      return 0;
   const std::string algo_name = deref_alias(name[0]);

#define HANDLE_TYPE_ONE_U32BIT(NAME, TYPE, DEFAULT) \
   if(algo_name == NAME)                            \
      {                                             \
      if(name.size() == 1)                          \
         return new TYPE(DEFAULT);                  \
      if(name.size() == 2)                          \
         return new TYPE(to_u32bit(name[1]));       \
      throw Invalid_Algorithm_Name(algo_spec);      \
      }

   HANDLE_TYPE_ONE_U32BIT("ARC4", OpenSSL_ARC4, 0);
   HANDLE_TYPE_ONE_U32BIT("RC4_drop", OpenSSL_ARC4, 768);

   return 0;
   }

}
