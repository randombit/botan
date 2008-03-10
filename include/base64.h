/*************************************************
* Base64 Encoder/Decoder Header File             *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_BASE64_H__
#define BOTAN_BASE64_H__

#include <botan/filter.h>
#include <botan/enums.h>

namespace Botan {

/*************************************************
* Base64 Encoder                                 *
*************************************************/
class Base64_Encoder : public Filter
   {
   public:
      static void encode(const byte[3], byte[4]);

      void write(const byte[], u32bit);
      void end_msg();
      Base64_Encoder(bool = false, u32bit = 72, bool = false);
   private:
      void encode_and_send(const byte[], u32bit);
      void do_output(const byte[], u32bit);
      static const byte BIN_TO_BASE64[64];

      const u32bit line_length;
      const bool trailing_newline;
      SecureVector<byte> in, out;
      u32bit position, counter;
   };

/*************************************************
* Base64 Decoder                                 *
*************************************************/
class Base64_Decoder : public Filter
   {
   public:
      static void decode(const byte[4], byte[3]);
      static bool is_valid(byte);

      void write(const byte[], u32bit);
      void end_msg();
      Base64_Decoder(Decoder_Checking = NONE);
   private:
      void decode_and_send(const byte[], u32bit);
      void handle_bad_char(byte);
      static const byte BASE64_TO_BIN[256];

      const Decoder_Checking checking;
      SecureVector<byte> in, out;
      u32bit position;
   };

}

#endif
