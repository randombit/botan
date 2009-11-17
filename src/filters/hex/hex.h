/*
* Hex Encoder/Decoder
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_HEX_H__
#define BOTAN_HEX_H__

#include <botan/filter.h>

namespace Botan {

/**
* This class represents a hex encoder. It encodes byte arrays to hex strings.
*/
class BOTAN_DLL Hex_Encoder : public Filter
   {
   public:
      /**
      * Whether to use uppercase or lowercase letters for the encoded string.
      */
      enum Case { Uppercase, Lowercase };

      /**
        Encode a single byte into two hex characters
      */
      static void encode(byte in, byte out[2], Case the_case = Uppercase);

      void write(const byte in[], u32bit length);
      void end_msg();

      /**
      * Create a hex encoder.
      * @param the_case the case to use in the encoded strings.
      */
      Hex_Encoder(Case the_case);

      /**
      * Create a hex encoder.
      * @param newlines should newlines be used
      * @param line_length if newlines are used, how long are lines
      * @param the_case the case to use in the encoded strings
      */
      Hex_Encoder(bool newlines = false,
                  u32bit line_length = 72,
                  Case the_case = Uppercase);
   private:
      void encode_and_send(const byte[], u32bit);
      static const byte BIN_TO_HEX_UPPER[16];
      static const byte BIN_TO_HEX_LOWER[16];

      const Case casing;
      const u32bit line_length;
      SecureVector<byte> in, out;
      u32bit position, counter;
   };

/**
* This class represents a hex decoder. It converts hex strings to byte arrays.
*/
class BOTAN_DLL Hex_Decoder : public Filter
   {
   public:
      static byte decode(const byte[2]);
      static bool is_valid(byte);

      void write(const byte[], u32bit);
      void end_msg();

      /**
      * Construct a Hex Decoder using the specified
      * character checking.
      * @param checking the checking to use during decoding.
      */
      Hex_Decoder(Decoder_Checking checking = NONE);
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
