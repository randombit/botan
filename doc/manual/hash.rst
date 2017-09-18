Hash Functions and Checksums
=============================
Hash functions are one-way functions, which map data of arbitrary size
to a fixed output length. The class :cpp:class:`HashFunction` is derived from
the base class :cpp:class:`BufferedComputation` and defined in `botan/hash.h`.
A Botan :cpp:class:`BufferedComputation` is split into three stages:

1. Instantiation.
2. Data processing.
3. Finalization.

.. cpp:class:: BufferedComputation

  .. cpp:function:: size_t output_length()

    Return the size of the output of this function.

  .. cpp:function:: void update(const byte* input, size_t length)

  .. cpp:function:: void update(byte input)

  .. cpp:function:: void update(const std::string& input)

    Updates the computation with *input*.

  .. cpp:function:: void final(byte* out)

  .. cpp:function:: secure_vector<byte> final()

    Finalize the calculation and place the result into ``out``.
    For the argument taking an array, exactly ``output_length`` bytes will
    be written. After you call ``final``, the algorithm is reset to
    its initial state, so it may be reused immediately.

    The second method of using final is to call it with no arguments at
    all, as shown in the second prototype. It will return the result
    value in a memory buffer.

    There is also a pair of functions called ``process``. They are a
    combination of a single ``update``, and ``final``. Both versions
    return the final value, rather than placing it an array. Calling
    ``process`` with a single byte value isn't available, mostly because
    it would rarely be useful.

Botan implements the following hash algorithms:

1. Checksums:
    - Adler32
    - CRC24
    - CRC32
#. Cryptographic hash functions:
    - BLAKE2b
    - GOST-34.11
    - Keccak-1600
    - MD4
    - MD5
    - RIPEMD-160
    - SHA-1
    - SHA-2 (SHA-224, SHA-256, SHA-384, SHA-512, SHA-512-256)
    - SHA-3
    - SHAKE (SHAKE-128, SHAKE-256)
    - SM3
    - Skein-512
    - Streebog (Streebog-256, Streebog-512)
    - Tiger
    - Whirlpool
#. Hash Function Combiners
   - Parallel
   - Comb4P

.. note:: Checksums are not suitable for cryptographic use, but can be used for error checking purposes.

Code Example
------------
Assume we want to calculate the SHA-1, Whirlpool and SHA-3 hash digests of the STDIN stream using the Botan library.

.. code-block:: cpp

    #include <botan/hash.h>
    #include <botan/hex.h>
    #include <iostream>
    int main ()
       {
       std::unique_ptr<Botan::HashFunction> hash1(Botan::HashFunction::create("SHA-1"));
       std::unique_ptr<Botan::HashFunction> hash2(Botan::HashFunction::create("Whirlpool"));
       std::unique_ptr<Botan::HashFunction> hash3(Botan::HashFunction::create("SHA-3"));
       std::vector<uint8_t> buf(2048);

       while(std::cin.good())
          {
          //read STDIN to buffer
          std::cin.read(reinterpret_cast<char*>(buf.data()), buf.size());
          size_t readcount = std::cin.gcount();
          //update hash computations with read data
          hash1->update(buf.data(),readcount);
          hash2->update(buf.data(),readcount);
          hash3->update(buf.data(),readcount);
          }
       std::cout << "SHA-1: " << Botan::hex_encode(hash1->final()) << std::endl;
       std::cout << "Whirlpool: " << Botan::hex_encode(hash2->final()) << std::endl;
       std::cout << "SHA-3: " << Botan::hex_encode(hash3->final()) << std::endl;
       return 0;
       }


A Note on Checksums
--------------------

Checksums are very similar to hash functions, and in fact share the
same interface. But there are some significant differences, the major
ones being that the output size is very small (usually in the range of
2 to 4 bytes), and is not cryptographically secure. But for their
intended purpose (error checking), they perform very well. Some
examples of checksums included in Botan are the Adler32 and CRC32
checksums.
