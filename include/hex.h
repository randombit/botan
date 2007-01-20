/*************************************************
* Hex Encoder/Decoder Header File                *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_HEX_H__
#define BOTAN_HEX_H__

#include <botan/filter.h>
#include <botan/enums.h>

namespace Botan {

/*************************************************
* Hex Encoder                                    *
*************************************************/
class Hex_Encoder : public Filter
   {
   public:
      enum Case { Uppercase, Lowercase };
      static void encode(byte, byte[2], Case = Uppercase);

      void write(const byte[], u32bit);
      void end_msg();

      Hex_Encoder(Case);
      Hex_Encoder(bool = false, u32bit = 72, Case = Uppercase);
   private:
      void encode_and_send(const byte[], u32bit);
      static const byte BIN_TO_HEX_UPPER[16];
      static const byte BIN_TO_HEX_LOWER[16];

      const Case casing;
      const u32bit line_length;
      SecureVector<byte> in, out;
      u32bit position, counter;
   };

/*************************************************
* Hex Decoder                                    *
*************************************************/
class Hex_Decoder : public Filter
   {
   public:
      static byte decode(const byte[2]);
      static bool is_valid(byte);

      void write(const byte[], u32bit);
      void end_msg();

      Hex_Decoder(Decoder_Checking = NONE);
   private:
      void decode_and_send(const byte[], u32bit);
      void handle_bad_char(byte);
      static const byte HEX_TO_BIN[256];

      const Decoder_Checking checking;
      SecureVector<byte> in, out;
      u32bit position;
   };

}

#endif
