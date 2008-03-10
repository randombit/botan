/*************************************************
* Base Classes Header File                       *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_BASE_H__
#define BOTAN_BASE_H__

#include <botan/exceptn.h>
#include <botan/symkey.h>

namespace Botan {

/*************************************************
* Constants                                      *
*************************************************/
static const u32bit DEFAULT_BUFFERSIZE = BOTAN_DEFAULT_BUFFER_SIZE;

/*************************************************
* Symmetric Algorithm                            *
*************************************************/
class SymmetricAlgorithm
   {
   public:
      const u32bit MAXIMUM_KEYLENGTH, MINIMUM_KEYLENGTH, KEYLENGTH_MULTIPLE;

      virtual std::string name() const = 0;

      void set_key(const SymmetricKey&) throw(Invalid_Key_Length);
      void set_key(const byte[], u32bit) throw(Invalid_Key_Length);
      bool valid_keylength(u32bit) const;
      SymmetricAlgorithm(u32bit, u32bit, u32bit);
      virtual ~SymmetricAlgorithm() {}
   private:
      virtual void key(const byte[], u32bit) = 0;
   };

/*************************************************
* Block Cipher                                   *
*************************************************/
class BlockCipher : public SymmetricAlgorithm
   {
   public:
      const u32bit BLOCK_SIZE;

      void encrypt(const byte in[], byte out[]) const { enc(in, out); }
      void decrypt(const byte in[], byte out[]) const { dec(in, out); }
      void encrypt(byte block[]) const { enc(block, block); }
      void decrypt(byte block[]) const { dec(block, block); }

      virtual BlockCipher* clone() const = 0;
      virtual void clear() throw() {};

      BlockCipher(u32bit, u32bit, u32bit = 0, u32bit = 1);
      virtual ~BlockCipher() {}
   private:
      virtual void enc(const byte[], byte[]) const = 0;
      virtual void dec(const byte[], byte[]) const = 0;
   };

/*************************************************
* Stream Cipher                                  *
*************************************************/
class StreamCipher : public SymmetricAlgorithm
   {
   public:
      const u32bit IV_LENGTH;
      void encrypt(const byte i[], byte o[], u32bit len) { cipher(i, o, len); }
      void decrypt(const byte i[], byte o[], u32bit len) { cipher(i, o, len); }
      void encrypt(byte in[], u32bit len) { cipher(in, in, len); }
      void decrypt(byte in[], u32bit len) { cipher(in, in, len); }

      virtual void resync(const byte[], u32bit);
      virtual void seek(u32bit);

      virtual StreamCipher* clone() const = 0;
      virtual void clear() throw() {};

      StreamCipher(u32bit, u32bit = 0, u32bit = 1, u32bit = 0);
      virtual ~StreamCipher() {}
   private:
      virtual void cipher(const byte[], byte[], u32bit) = 0;
   };

/*************************************************
* Buffered Computation                           *
*************************************************/
class BufferedComputation
   {
   public:
      const u32bit OUTPUT_LENGTH;
      void update(const byte[], u32bit);
      void update(const MemoryRegion<byte>&);
      void update(const std::string&);
      void update(byte);
      void final(byte out[]) { final_result(out); }
      SecureVector<byte> final();
      SecureVector<byte> process(const byte[], u32bit);
      SecureVector<byte> process(const MemoryRegion<byte>&);
      SecureVector<byte> process(const std::string&);
      BufferedComputation(u32bit);
      virtual ~BufferedComputation() {}
   private:
      virtual void add_data(const byte[], u32bit) = 0;
      virtual void final_result(byte[]) = 0;
   };

/*************************************************
* Hash Function                                  *
*************************************************/
class HashFunction : public BufferedComputation
   {
   public:
      const u32bit HASH_BLOCK_SIZE;

      virtual HashFunction* clone() const = 0;
      virtual std::string name() const = 0;
      virtual void clear() throw() {};

      HashFunction(u32bit, u32bit = 0);
      virtual ~HashFunction() {}
   };

/*************************************************
* Message Authentication Code                    *
*************************************************/
class MessageAuthenticationCode : public BufferedComputation,
                                  public SymmetricAlgorithm
   {
   public:
      virtual bool verify_mac(const byte[], u32bit);

      virtual MessageAuthenticationCode* clone() const = 0;
      virtual std::string name() const = 0;
      virtual void clear() throw() {};

      MessageAuthenticationCode(u32bit, u32bit, u32bit = 0, u32bit = 1);
      virtual ~MessageAuthenticationCode() {}
   };

/*************************************************
* Entropy Source                                 *
*************************************************/
class EntropySource
   {
   public:
      virtual u32bit slow_poll(byte[], u32bit) = 0;
      virtual u32bit fast_poll(byte[], u32bit);
      virtual ~EntropySource() {}
   };

/*************************************************
* Random Number Generator                        *
*************************************************/
class RandomNumberGenerator
   {
   public:
      virtual void randomize(byte[], u32bit) throw(PRNG_Unseeded) = 0;
      virtual bool is_seeded() const { return true; }
      virtual void clear() throw() {};

      void add_entropy(const byte[], u32bit);
      u32bit add_entropy(EntropySource&, bool = true);

      virtual ~RandomNumberGenerator() {}
   private:
      virtual void add_randomness(const byte[], u32bit) = 0;
   };

}

#endif
