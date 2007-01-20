/*************************************************
* Base Classes Source File                       *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/base.h>
#include <botan/version.h>
#include <botan/parsing.h>
#include <botan/util.h>
#include <botan/config.h>

namespace Botan {

/*************************************************
* SymmetricAlgorithm Constructor                 *
*************************************************/
SymmetricAlgorithm::SymmetricAlgorithm(u32bit key_min, u32bit key_max,
                                       u32bit key_mod) :
   MAXIMUM_KEYLENGTH(key_max ? key_max : key_min),
   MINIMUM_KEYLENGTH(key_min),
   KEYLENGTH_MULTIPLE(key_mod)
   {
   }

/*************************************************
* Query if the keylength is valid                *
*************************************************/
bool SymmetricAlgorithm::valid_keylength(u32bit length) const
   {
   return ((length >= MINIMUM_KEYLENGTH) &&
           (length <= MAXIMUM_KEYLENGTH) &&
           (length % KEYLENGTH_MULTIPLE == 0));
   }

/*************************************************
* Set the key                                    *
*************************************************/
void SymmetricAlgorithm::set_key(const SymmetricKey& algo_key)
   throw(Invalid_Key_Length)
   {
   set_key(algo_key.begin(), algo_key.length());
   }

/*************************************************
* Set the key                                    *
*************************************************/
void SymmetricAlgorithm::set_key(const byte algo_key[], u32bit length)
   throw(Invalid_Key_Length)
   {
   if(!valid_keylength(length))
      throw Invalid_Key_Length(name(), length);
   key(algo_key, length);
   }

/*************************************************
* BlockCipher Constructor                        *
*************************************************/
BlockCipher::BlockCipher(u32bit block, u32bit key_min, u32bit key_max,
                         u32bit key_mod) :
   SymmetricAlgorithm(key_min, key_max, key_mod),
   BLOCK_SIZE(block)
   {
   }

/*************************************************
* StreamCipher Constructor                       *
*************************************************/
StreamCipher::StreamCipher(u32bit key_min, u32bit key_max, u32bit key_mod,
                           u32bit iv_len) :
   SymmetricAlgorithm(key_min, key_max, key_mod), IV_LENGTH(iv_len)
   {
   }

/*************************************************
* BufferedComputation Constructor                *
*************************************************/
BufferedComputation::BufferedComputation(u32bit olen) : OUTPUT_LENGTH(olen)
   {
   }

/*************************************************
* HashFunction Constructor                       *
*************************************************/
HashFunction::HashFunction(u32bit hlen, u32bit blen) :
   BufferedComputation(hlen), HASH_BLOCK_SIZE(blen)
   {
   }

/*************************************************
* MessageAuthenticationCode Constructor          *
*************************************************/
MessageAuthenticationCode::MessageAuthenticationCode(u32bit mlen,
                                                     u32bit key_min,
                                                     u32bit key_max,
                                                     u32bit key_mod) :
   BufferedComputation(mlen),
   SymmetricAlgorithm(key_min, key_max, key_mod)
   {
   }

/*************************************************
* Default MAC verification operation             *
*************************************************/
bool MessageAuthenticationCode::verify_mac(const byte mac[], u32bit length)
   {
   SecureVector<byte> our_mac = final();
   if(our_mac.size() != length)
      return false;
   for(u32bit j = 0; j != length; ++j)
      if(mac[j] != our_mac[j])
         return false;
   return true;
   }

/*************************************************
* Default StreamCipher Resync Operation          *
*************************************************/
void StreamCipher::resync(const byte[], u32bit length)
   {
   if(length)
      throw Exception("The stream cipher " + name() +
                      " does not support resyncronization");
   }

/*************************************************
* Default StreamCipher Seek Operation            *
*************************************************/
void StreamCipher::seek(u32bit)
   {
   throw Exception("The stream cipher " + name() + " does not support seek()");
   }

/*************************************************
* Hashing/MACing                                 *
*************************************************/
void BufferedComputation::update(const byte in[], u32bit n)
   {
   add_data(in, n);
   }

/*************************************************
* Hashing/MACing                                 *
*************************************************/
void BufferedComputation::update(const MemoryRegion<byte>& in)
   {
   add_data(in, in.size());
   }

/*************************************************
* Hashing/MACing                                 *
*************************************************/
void BufferedComputation::update(const std::string& str)
   {
   update((const byte*)str.c_str(), str.size());
   }

/*************************************************
* Hashing/MACing                                 *
*************************************************/
void BufferedComputation::update(byte in)
   {
   update(&in, 1);
   }

/*************************************************
* Hashing/MACing                                 *
*************************************************/
SecureVector<byte> BufferedComputation::final()
   {
   SecureVector<byte> output(OUTPUT_LENGTH);
   final_result(output);
   return output;
   }

/*************************************************
* Hashing/MACing                                 *
*************************************************/
SecureVector<byte> BufferedComputation::process(const byte in[], u32bit len)
   {
   update(in, len);
   return final();
   }

/*************************************************
* Hashing/MACing                                 *
*************************************************/
SecureVector<byte> BufferedComputation::process(const MemoryRegion<byte>& in)
   {
   update(in, in.size());
   return final();
   }

/*************************************************
* Hashing/MACing                                 *
*************************************************/
SecureVector<byte> BufferedComputation::process(const std::string& in)
   {
   update(in);
   return final();
   }

/*************************************************
* Default fast poll for EntropySources           *
*************************************************/
u32bit EntropySource::fast_poll(byte buf[], u32bit len)
   {
   return slow_poll(buf, len);
   }

/*************************************************
* Add entropy to internal state                  *
*************************************************/
void RandomNumberGenerator::add_entropy(const byte random[], u32bit length)
   {
   add_randomness(random, length);
   }

/*************************************************
* Add entropy to internal state                  *
*************************************************/
u32bit RandomNumberGenerator::add_entropy(EntropySource& source,
                                          bool slow_poll)
   {
   std::string poll_type;
   if(slow_poll)
      poll_type = "rng/slow_poll_request";
   else
      poll_type = "rng/fast_poll_request";

   u32bit poll_for = global_config().option_as_u32bit(poll_type);

   SecureVector<byte> buffer(poll_for ? poll_for : 256);

   u32bit bytes_gathered = 0;

   if(slow_poll)
      bytes_gathered = source.slow_poll(buffer, buffer.size());
   else
      bytes_gathered = source.fast_poll(buffer, buffer.size());

   add_entropy(buffer, bytes_gathered);

   return entropy_estimate(buffer, bytes_gathered);
   }

/*************************************************
* Return the version as a string                 *
*************************************************/
std::string version_string()
   {
   return "Botan " + to_string(version_major()) + "." +
                     to_string(version_minor()) + "." +
                     to_string(version_patch());
   }

/*************************************************
* Return parts of the version as integers        *
*************************************************/
u32bit version_major() { return BOTAN_VERSION_MAJOR; }
u32bit version_minor() { return BOTAN_VERSION_MINOR; }
u32bit version_patch() { return BOTAN_VERSION_PATCH; }

}
