/*
* Base64 Encoder/Decoder
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_BASE64_H__
#define BOTAN_BASE64_H__

#include <botan/filter.h>

namespace Botan {

/**
* This class represents a Base64 encoder.
*/
class BOTAN_DLL Base64_Encoder : public Filter
   {
   public:
      static void encode(const byte in[3], byte out[4]);

      /**
      * Input a part of a message to the encoder.
      * @param input the message to input as a byte array
      * @param length the length of the byte array input
      */
      void write(const byte input[], u32bit length);

      /**
      * Inform the Encoder that the current message shall be closed.
      */
      void end_msg();

      /**
      * Create a base64 encoder.
      * @param breaks whether to use line breaks in the Streamcipheroutput
      * @param length the length of the lines of the output
      * @param t_n whether to use a trailing newline
      */
      Base64_Encoder(bool breaks = false, u32bit length = 72,
                     bool t_n = false);
   private:
      void encode_and_send(const byte[], u32bit);
      void do_output(const byte[], u32bit);
      static const byte BIN_TO_BASE64[64];

      const u32bit line_length;
      const bool trailing_newline;
      SecureVector<byte> in, out;
      u32bit position, counter;
   };

/**
* This object represents a Base64 decoder.
*/
class BOTAN_DLL Base64_Decoder : public Filter
   {
   public:
      static void decode(const byte input[4], byte output[3]);

      static bool is_valid(byte);

      /**
      * Input a part of a message to the decoder.
      * @param input the message to input as a byte array
      * @param length the length of the byte array input
      */
      void write(const byte input[], u32bit length);

      /**
      * Inform the Encoder that the current message shall be closed.
      */
      void end_msg();

      /**
      * Create a base64 encoder.
      * @param checking the type of checking that shall be performed by
      * the decoder
      */
      Base64_Decoder(Decoder_Checking checking = NONE);
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
