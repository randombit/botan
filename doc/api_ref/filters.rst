
Pipe/Filter Message Processing
========================================

.. note::

    The system described below provides a message processing system with a
    straightforward API. However it makes many extra memory copies and
    allocations than would otherwise be required, and also tends to make
    applications using it somewhat opaque because it is not obvious what this or
    that Pipe& object actually does (type of operation, number of messages
    output (if any!), and so on), whereas using say a HashFunction or AEAD_Mode
    provides a much better idea in the code of what operation is occurring.

    This filter interface is no longer used within the library itself
    (outside a few dusty corners) and will likely not see any further major
    development. However it will remain included because the API is often
    convenient and many applications use it.

Many common uses of cryptography involve processing one or more
streams of data. Botan provides services that make setting up data
flows through various operations, such as compression, encryption, and
base64 encoding. Each of these operations is implemented in what are
called *filters* in Botan. A set of filters are created and placed into
a *pipe*, and information "flows" through the pipe until it reaches
the end, where the output is collected for retrieval. If you're
familiar with the Unix shell environment, this design will sound quite
familiar.

Here is an example that uses a pipe to base64 encode some strings::

  Pipe pipe(new Base64_Encoder); // pipe owns the pointer
  pipe.start_msg();
  pipe.write("message 1");
  pipe.end_msg(); // flushes buffers, increments message number

  // process_msg(x) is start_msg() && write(x) && end_msg()
  pipe.process_msg("message2");

  std::string m1 = pipe.read_all_as_string(0); // "message1"
  std::string m2 = pipe.read_all_as_string(1); // "message2"

Byte streams in the pipe are grouped into messages; blocks of data that
are processed in an identical fashion (ie, with the same sequence of
filter operations). Messages are delimited by calls to ``start_msg``
and ``end_msg``. Each message in a pipe has its own identifier, which
currently is an integer that increments up from zero.

The ``Base64_Encoder`` was allocated using ``new``; but where was it
deallocated?  When a filter object is passed to a ``Pipe``, the pipe
takes ownership of the object, and will deallocate it when it is no
longer needed.

There are two different ways to make use of messages. One is to send
several messages through a ``Pipe`` without changing the ``Pipe``
configuration, so you end up with a sequence of messages; one use of
this would be to send a sequence of identically encrypted UDP packets,
for example (note that the *data* need not be identical; it is just
that each is encrypted, encoded, signed, etc in an identical
fashion). Another is to change the filters that are used in the
``Pipe`` between each message, by adding or removing filters;
functions that let you do this are documented in the Pipe API section.

Botan has about 40 filters that perform different operations on data.
Here's code that uses one of them to encrypt a string with AES::

  AutoSeeded_RNG rng,
  SymmetricKey key(rng, 16); // a random 128-bit key
  InitializationVector iv(rng, 16); // a random 128-bit IV

  // The algorithm we want is specified by a string
  Pipe pipe(get_cipher("AES-128/CBC", key, iv, Cipher_Dir::Encryption));

  pipe.process_msg("secrets");
  pipe.process_msg("more secrets");

  secure_vector<uint8_t> c1 = pipe.read_all(0);

  uint8_t c2[4096] = { 0 };
  size_t got_out = pipe.read(c2, sizeof(c2), 1);
  // use c2[0...got_out]

Note the use of ``AutoSeeded_RNG``, which is a random number
generator. If you want to, you can explicitly set up the random number
generators and entropy sources you want to, however for 99% of cases
``AutoSeeded_RNG`` is preferable.

``Pipe`` also has convenience methods for dealing with ``std::iostream``.
Here is an example of this, using the bzip2 compression filter::

  std::ifstream in("data.bin", std::ios::binary)
  std::ofstream out("data.bin.bz2", std::ios::binary)

  Pipe pipe(new Compression_Filter("bzip2", 9));

  pipe.start_msg();
  in >> pipe;
  pipe.end_msg();
  out << pipe;

However there is a hitch to the code above; the complete contents of
the compressed data will be held in memory until the entire message
has been compressed, at which time the statement ``out << pipe`` is
executed, and the data is freed as it is read from the pipe and
written to the file. But if the file is very large, we might not have
enough physical memory (or even enough virtual memory!) for that to be
practical. So instead of storing the compressed data in the pipe for
reading it out later, we divert it directly to the file::

  std::ifstream in("data.bin", std::ios::binary)
  std::ofstream out("data.bin.bz2", std::ios::binary)

  Pipe pipe(new Compression_Filter("bzip2", 9), new DataSink_Stream(out));

  pipe.start_msg();
  in >> pipe;
  pipe.end_msg();

This is the first code we've seen so far that uses more than one
filter in a pipe. The output of the compressor is sent to the
``DataSink_Stream``. Anything written to a ``DataSink_Stream`` is
written to a file; the filter produces no output. As soon as the
compression algorithm finishes up a block of data, it will send it
along to the sink filter, which will immediately write it to the
stream; if you were to call ``pipe.read_all()`` after
``pipe.end_msg()``, you'd get an empty vector out. This is
particularly useful for cases where you are processing a large amount
of data, as it means you don't have to store everything in memory at
once.

Here's an example using two computational filters::

   AutoSeeded_RNG rng,
   SymmetricKey key(rng, 32);
   InitializationVector iv(rng, 16);

   Pipe encryptor(get_cipher("AES/CBC/PKCS7", key, iv, Cipher_Dir::Encryption),
                  new Base64_Encoder);

   encryptor.start_msg();
   file >> encryptor;
   encryptor.end_msg(); // flush buffers, complete computations
   std::cout << encryptor;

You can read from a pipe while you are still writing to it, which
allows you to bound the amount of memory that is in use at any one
time. A common idiom for this is::

   pipe.start_msg();
   std::vector<uint8_t> buffer(4096); // arbitrary size
   while(infile.good())
      {
      infile.read((char*)&buffer[0], buffer.size());
      const size_t got_from_infile = infile.gcount();
      pipe.write(buffer, got_from_infile);

      if(infile.eof())
         pipe.end_msg();

      while(pipe.remaining() > 0)
         {
         const size_t buffered = pipe.read(buffer, buffer.size());
         outfile.write((const char*)&buffer[0], buffered);
         }
      }
   if(infile.bad() || (infile.fail() && !infile.eof()))
      throw Some_Exception();

Fork
---------------------------------

It is common that you might receive some data and want to perform more
than one operation on it (ie, encrypt it with Serpent and calculate
the SHA-256 hash of the plaintext at the same time). That's where
``Fork`` comes in. ``Fork`` is a filter that takes input and passes it
on to *one or more* filters that are attached to it. ``Fork`` changes
the nature of the pipe system completely: instead of being a linked
list, it becomes a tree or acyclic graph.

Each filter in the fork is given its own output buffer, and thus its
own message. For example, if you had previously written two messages
into a pipe, then you start a new one with a fork that has three
paths of filter's inside it, you add three new messages to the
pipe. The data you put into the pipe is duplicated and sent
into each set of filter and the eventual output is placed into a
dedicated message slot in the pipe.

Messages in the pipe are allocated in a depth-first manner. This is only
interesting if you are using more than one fork in a single pipe.
As an example, consider the following::

   Pipe pipe(new Fork(
                new Fork(
                   new Base64_Encoder,
                   new Fork(
                      NULL,
                      new Base64_Encoder
                      )
                   ),
                new Hex_Encoder
                )
      );

In this case, message 0 will be the output of the first
``Base64_Encoder``, message 1 will be a copy of the input (see below
for how fork interprets NULL pointers), message 2 will be the output
of the second ``Base64_Encoder``, and message 3 will be the output of
the ``Hex_Encoder``. This results in message numbers being allocated
in a top to bottom fashion, when looked at on the screen. However,
note that there could be potential for bugs if this is not
anticipated. For example, if your code is passed a filter, and you
assume it is a "normal" one that only uses one message, your message
offsets would be wrong, leading to some confusion during output.

If Fork's first argument is a null pointer, but a later argument is
not, then Fork will feed a copy of its input directly through. Here's
a case where that is useful::

   // have std::string ciphertext, auth_code, key, iv, mac_key;

   Pipe pipe(new Base64_Decoder,
             get_cipher("AES-128", key, iv, Cipher_Dir::Decryption),
             new Fork(
                0, // this message gets plaintext
                new MAC_Filter("HMAC(SHA-1)", mac_key)
             )
      );

   pipe.process_msg(ciphertext);
   std::string plaintext = pipe.read_all_as_string(0);
   secure_vector<uint8_t> mac = pipe.read_all(1);

   if(mac != auth_code)
      error();

Here we wanted to not only decrypt the message, but send the decrypted
text through an additional computation, in order to compute the
authentication code.

Any filters that are attached to the pipe after the fork are
implicitly attached onto the first branch created by the fork. For
example, let's say you created this pipe::

  Pipe pipe(new Fork(new Hash_Filter("SHA-256"),
                     new Hash_Filter("SHA-512")),
            new Hex_Encoder);

And then called ``start_msg``, inserted some data, then
``end_msg``. Then ``pipe`` would contain two messages. The first one
(message number 0) would contain the SHA-256 sum of the input in hex
encoded form, and the other would contain the SHA-512 sum of the input
in raw binary. In many situations you'll want to perform a sequence of
operations on multiple branches of the fork; in which case, use
the filter described in :ref:`chain`.

There is also a ``Threaded_Fork`` which acts the same as ``Fork``,
except it runs each of the filters in its own thread.

.. _chain:

Chain
---------------------------------

A ``Chain`` filter creates a chain of filters and encapsulates them
inside a single filter (itself). This allows a sequence of filters to
become a single filter, to be passed into or out of a function, or to
a ``Fork`` constructor.

You can call ``Chain``'s constructor with up to four ``Filter``
pointers (they will be added in order), or with an array of filter
pointers and a ``size_t`` that tells ``Chain`` how many filters are in
the array (again, they will be attached in order). Here's the example
from the last section, using chain instead of relying on the implicit
pass through the other version used::

  Pipe pipe(new Fork(
                new Chain(new Hash_Filter("SHA-256"), new Hex_Encoder),
                new Hash_Filter("SHA-512")
                )
           );

Sources and Sinks
----------------------------------------

Data Sources
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A ``DataSource`` is a simple abstraction for a thing that stores
bytes. This type is used heavily in the areas of the API related to
ASN.1 encoding/decoding. The following types are ``DataSource``:
``Pipe``, ``SecureQueue``, and a couple of special purpose ones:
``DataSource_Memory`` and ``DataSource_Stream``.

You can create a ``DataSource_Memory`` with an array of bytes and a
length field. The object will make a copy of the data, so you don't
have to worry about keeping that memory allocated. This is mostly for
internal use, but if it comes in handy, feel free to use it.

A ``DataSource_Stream`` is probably more useful than the memory based
one. Its constructors take either a ``std::istream`` or a
``std::string``. If it's a stream, the data source will use the
``istream`` to satisfy read requests (this is particularly useful to
use with ``std::cin``). If the string version is used, it will attempt
to open up a file with that name and read from it.

Data Sinks
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A ``DataSink`` (in ``data_snk.h``) is a ``Filter`` that takes
arbitrary amounts of input, and produces no output. This means it's
doing something with the data outside the realm of what
``Filter``/``Pipe`` can handle, for example, writing it to a file
(which is what the ``DataSink_Stream`` does). There is no need for
``DataSink``s that write to a ``std::string`` or memory buffer,
because ``Pipe`` can handle that by itself.

Here's a quick example of using a ``DataSink``, which encrypts
``in.txt`` and sends the output to ``out.txt``. There is
no explicit output operation; the writing of ``out.txt`` is
implicit::

   DataSource_Stream in("in.txt");
   Pipe pipe(get_cipher("AES-128/CTR-BE", key, iv),
             new DataSink_Stream("out.txt"));
   pipe.process_msg(in);

A real advantage of this is that even if "in.txt" is large, only as
much memory is needed for internal I/O buffers will be used.

The Pipe API
---------------------------------

Initializing Pipe
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

By default, ``Pipe`` will do nothing at all; any input placed into the
``Pipe`` will be read back unchanged. Obviously, this has limited
utility, and presumably you want to use one or more filters to somehow
process the data. First, you can choose a set of filters to initialize
the ``Pipe`` via the constructor. You can pass it either a set of up
to four filter pointers, or a pre-defined array and a length::

   Pipe pipe1(new Filter1(/*args*/), new Filter2(/*args*/),
              new Filter3(/*args*/), new Filter4(/*args*/));
   Pipe pipe2(new Filter1(/*args*/), new Filter2(/*args*/));

   Filter* filters[5] = {
     new Filter1(/*args*/), new Filter2(/*args*/), new Filter3(/*args*/),
     new Filter4(/*args*/), new Filter5(/*args*/) /* more if desired... */
   };
   Pipe pipe3(filters, 5);

This is by far the most common way to initialize a ``Pipe``. However,
occasionally a more flexible initialization strategy is necessary;
this is supported by 4 member functions. These functions may only be
used while the pipe in question is not in use; that is, either before
calling ``start_msg``, or after ``end_msg`` has been called (and no
new calls to ``start_msg`` have been made yet).

.. cpp:function:: void Pipe::prepend(Filter* filter)

  Calling ``prepend`` will put the passed filter first in the list of
  transformations. For example, if you prepend a filter implementing
  encryption, and the pipe already had a filter that hex encoded the
  input, then the next message processed would be first encrypted,
  and *then* hex encoded.

.. cpp:function:: void Pipe::append(Filter* filter)

  Like ``prepend``, but places the filter at the end of the message
  flow. This doesn't always do what you expect if there is a fork.

.. cpp:function:: void Pipe::pop()

  Removes the first filter in the flow.

.. cpp:function:: void Pipe::reset()

  Removes all the filters that the pipe currently holds - it is reset
  to an empty/no-op state.  Any data that is being retained by the
  pipe is retained after a ``reset``, and ``reset`` does not affect
  message numbers (discussed later).

Giving Data to a Pipe
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Input to a ``Pipe`` is delimited into messages, which can be read from
independently (ie, you can read 5 bytes from one message, and then all of
another message, without either read affecting any other messages).

.. cpp:function:: void Pipe::start_msg()

  Starts a new message; if a message was already running, an exception is
  thrown. After this function returns, you can call ``write``.

.. cpp:function:: void Pipe::write(const uint8_t* input, size_t length)

.. cpp:function:: void Pipe::write(const std::vector<uint8_t>& input)

.. cpp:function:: void Pipe::write(const std::string& input)

.. cpp:function:: void Pipe::write(DataSource& input)

.. cpp:function:: void Pipe::write(uint8_t input)

  All versions of ``write`` write the input into the filter sequence.
  If a message is not currently active, an exception is thrown.

.. cpp:function:: void Pipe::end_msg()

  End the currently active message

Sometimes, you may want to do only a single write per message. In this
case, you can use the ``process_msg`` series of functions, which start
a message, write their argument into the pipe, and then end the
message. In this case you would not make any explicit calls to
``start_msg``/``end_msg``.

Pipes can also be used with the ``>>`` operator, and will accept a
``std::istream``, or on Unix systems with the ``fd_unix`` module, a
Unix file descriptor. In either case, the entire contents of the file
will be read into the pipe.

Getting Output from a Pipe
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Retrieving the processed data from a pipe is a bit more complicated,
for various reasons. The pipe will separate each message into a
separate buffer, and you have to retrieve data from each message
independently. Each of the reader functions has a final parameter that
specifies what message to read from. If this parameter is set to
``Pipe::DEFAULT_MESSAGE``, it will read the current default message
(``DEFAULT_MESSAGE`` is also the default value of this parameter).

Functions in ``Pipe`` related to reading include:

.. cpp:function:: size_t Pipe::read(uint8_t* out, size_t len)

  Reads up to ``len`` bytes into ``out``, and returns the number of
  bytes actually read.

.. cpp:function:: size_t Pipe::peek(uint8_t* out, size_t len)

  Acts exactly like `read`, except the data is not actually read; the
  next read will return the same data.

.. cpp:function:: secure_vector<uint8_t> Pipe::read_all()

  Reads the entire message into a buffer and returns it

.. cpp:function:: std::string Pipe::read_all_as_string()

  Like ``read_all``, but it returns the data as a ``std::string``.
  No encoding is done; if the message contains raw binary, so will
  the string.

.. cpp:function:: size_t Pipe::remaining()

  Returns how many bytes are left in the message

.. cpp:function:: Pipe::message_id Pipe::default_msg()

  Returns the current default message number

.. cpp:function:: Pipe::message_id Pipe::message_count()

  Returns the total number of messages currently in the pipe

.. cpp:function:: Pipe::set_default_msg(Pipe::message_id msgno)

  Sets the default message number (which must be a valid message
  number for that pipe). The ability to set the default message number
  is particularly important in the case of using the file output
  operations (``<<`` with a ``std::ostream`` or Unix file descriptor),
  because there is no way to specify the message explicitly when using
  the output operator.

Pipe I/O for Unix File Descriptors
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This is a minor feature, but it comes in handy sometimes. In all
installations of the library, Botan's ``Pipe`` object overloads the
``<<`` and ``>>`` operators for C++ iostream objects,
which is usually more than sufficient for doing I/O.

However, there are cases where the iostream hierarchy does not map well to
local 'file types', so there is also the ability to do I/O directly with Unix
file descriptors. This is most useful when you want to read from or write to
something like a TCP or Unix-domain socket, or a pipe, since for simple file
access it's usually easier to just use C++'s file streams.

If ``BOTAN_EXT_PIPE_UNIXFD_IO`` is defined, then you can use the
overloaded I/O operators with Unix file descriptors. For an example of this,
check out the ``hash_fd`` example, included in the Botan distribution.

Filter Catalog
---------------------------------

This section documents most of the useful filters included in the
library.

Keyed Filters
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A few sections ago, it was mentioned that ``Pipe`` can process
multiple messages, treating each of them the same. Well, that was a
bit of a lie. There are some algorithms (in particular, block ciphers
not in ECB mode, and all stream ciphers) that change their state as
data is put through them.

Naturally, you might well want to reset the keys or (in the case of
block cipher modes) IVs used by such filters, so multiple messages can
be processed using completely different keys, or new IVs, or new keys
and IVs, or whatever.  And in fact, even for a MAC or an ECB block
cipher, you might well want to change the key used from message to
message.

Enter ``Keyed_Filter``, which acts as an abstract interface for any
filter that is uses keys: block cipher modes, stream ciphers, MACs,
and so on. It has two functions, ``set_key`` and ``set_iv``. Calling
``set_key`` will set (or reset) the key used by the algorithm. Setting
the IV only makes sense in certain algorithms -- a call to ``set_iv``
on an object that doesn't support IVs will cause an exception. You
must call ``set_key`` *before* calling ``set_iv``.

Here's a example::

   Keyed_Filter *aes, *hmac;
   Pipe pipe(new Base64_Decoder,
             // Note the assignments to the cast and hmac variables
             aes = get_cipher("AES-128/CBC", aes_key, iv),
             new Fork(
                0, // Read the section 'Fork' to understand this
                new Chain(
                   hmac = new MAC_Filter("HMAC(SHA-1)", mac_key, 12),
                   new Base64_Encoder
                   )
                )
      );
   pipe.start_msg();
   // use pipe for a while, decrypt some stuff, derive new keys and IVs
   pipe.end_msg();

   aes->set_key(aes_key2);
   aes->set_iv(iv2);
   hmac->set_key(mac_key2);

   pipe.start_msg();
   // use pipe for some other things
   pipe.end_msg();

There are some requirements to using ``Keyed_Filter`` that you must
follow. If you call ``set_key`` or ``set_iv`` on a filter that is
owned by a ``Pipe``, you must do so while the ``Pipe`` is
"unlocked". This refers to the times when no messages are being
processed by ``Pipe`` -- either before ``Pipe``'s ``start_msg`` is
called, or after ``end_msg`` is called (and no new call to
``start_msg`` has happened yet). Doing otherwise will result in
undefined behavior, probably silently getting invalid output.

And remember: if you're resetting both values, reset the key *first*.

Cipher Filters
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Getting a hold of a ``Filter`` implementing a cipher is very
easy. Make sure you're including the header ``lookup.h``, and
then call ``get_cipher``. You will pass the return value
directly into a ``Pipe``. There are a couple different functions
which do varying levels of initialization:

.. cpp:function:: Keyed_Filter* get_cipher(std::string cipher_spec, \
   SymmetricKey key, InitializationVector iv, Cipher_Dir dir)

.. cpp:function:: Keyed_Filter* get_cipher(std::string cipher_spec, \
   SymmetricKey key, Cipher_Dir dir)

The version that doesn't take an IV is useful for things that don't
use them, like block ciphers in ECB mode, or most stream ciphers. If
you specify a cipher spec that does want a IV, and you use the version
that doesn't take one, an exception will be thrown. The ``dir``
argument can be either ``Cipher_Dir::Encryption`` or ``Cipher_Dir::Decryption``.

The cipher_spec is a string that specifies what cipher is to be
used. The general syntax for "cipher_spec" is "STREAM_CIPHER",
"BLOCK_CIPHER/MODE", or "BLOCK_CIPHER/MODE/PADDING". In the case of
stream ciphers, no mode is necessary, so just the name is
sufficient. A block cipher requires a mode of some sort, which can be
"ECB", "CBC", "CFB(n)", "OFB", "CTR-BE", or "EAX(n)". The argument to
CFB mode is how many bits of feedback should be used. If you just use
"CFB" with no argument, it will default to using a feedback equal to
the block size of the cipher. EAX mode also takes an optional bit
argument, which tells EAX how large a tag size to use~--~generally
this is the size of the block size of the cipher, which is the default
if you don't specify any argument.

In the case of the ECB and CBC modes, a padding method can also be
specified. If it is not supplied, ECB defaults to not padding, and CBC
defaults to using PKCS #5/#7 compatible padding. The padding methods
currently available are "NoPadding", "PKCS7", "OneAndZeros", and
"CTS". CTS padding is currently only available for CBC mode, but the
others can also be used in ECB mode.

Some example "cipher_spec arguments are: "AES-128/CBC",
"Blowfish/CTR-BE", "Serpent/XTS", and "AES-256/EAX".

"CTR-BE" refers to counter mode where the counter is incremented as if
it were a big-endian encoded integer. This is compatible with most
other implementations, but it is possible some will use the
incompatible little endian convention. This version would be denoted
as "CTR-LE" if it were supported.

"EAX" is a new cipher mode designed by Wagner, Rogaway, and
Bellare. It is an authenticated cipher mode (that is, no separate
authentication is needed), has provable security, and is free from
patent entanglements. It runs about half as fast as most of the other
cipher modes (like CBC, OFB, or CTR), which is not bad considering you
don't need to use an authentication code.

Hashes and MACs
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Hash functions and MACs don't need anything special when it comes to
filters. Both just take their input and produce no output until
``end_msg`` is called, at which time they complete the hash or MAC and
send that as output.

These filters take a string naming the type to be used. If for some
reason you name something that doesn't exist, an exception will be thrown.

.. cpp:function:: Hash_Filter::Hash_Filter(std::string hash, size_t outlen = 0)

  This constructor creates a filter that hashes its input with
  ``hash``. When ``end_msg`` is called on the owning pipe, the hash is
  completed and the digest is sent on to the next filter in the
  pipeline. The parameter ``outlen`` specifies how many bytes of the
  hash output will be passed along to the next filter when ``end_msg``
  is called. By default, it will pass the entire hash.

  Examples of names for ``Hash_Filter`` are "SHA-1" and "Whirlpool".

.. cpp:function:: MAC_Filter::MAC_Filter(std::string mac, SymmetricKey key, size_t outlen = 0)

  This constructor takes a name for a mac, such as "HMAC(SHA-1)" or
  "CMAC(AES-128)", along with a key to use. The optional ``outlen``
  works the same as in ``Hash_Filter``.

Encoders
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Often you want your data to be in some form of text (for sending over
channels that aren't 8-bit clean, printing it, etc). The filters
``Hex_Encoder`` and ``Base64_Encoder`` will convert arbitrary binary
data into hex or base64 formats. Not surprisingly, you can use
``Hex_Decoder`` and ``Base64_Decoder`` to convert it back into its
original form.

Both of the encoders can take a few options about how the data should
be formatted (all of which have defaults). The first is a ``bool``
which says if the encoder should insert line breaks. This defaults to
false. Line breaks don't matter either way to the decoder, but it
makes the output a bit more appealing to the human eye, and a few
transport mechanisms (notably some email systems) limit the maximum
line length.

The second encoder option is an integer specifying how long such lines
will be (obviously this will be ignored if line-breaking isn't being
used). The default tends to be in the range of 60-80 characters, but
is not specified. If you want a specific value, set it. Otherwise the
default should be fine.

Lastly, ``Hex_Encoder`` takes an argument of type ``Case``, which can
be ``Uppercase`` or ``Lowercase`` (default is ``Uppercase``). This
specifies what case the characters A-F should be output as. The base64
encoder has no such option, because it uses both upper and lower case
letters for its output.

You can find the declarations for these types in ``hex_filt.h`` and
``b64_filt.h``.

Writing New Filters
---------------------------------

The system of filters and pipes was designed in an attempt to make it
as simple as possible to write new filter types. There are four
functions that need to be implemented by a class deriving from
``Filter``:

.. cpp:function:: std::string Filter::name() const

  This should just return a useful decription of the filter object.

.. cpp:function:: void Filter::write(const uint8_t* input, size_t length)

  This function is what is called when a filter receives input for it
  to process. The filter is not required to process the data right
  away; many filters buffer their input before producing any output. A
  filter will usually have ``write`` called many times during its
  lifetime.

.. cpp:function:: void Filter::send(uint8_t* output, size_t length)

  Eventually, a filter will want to produce some output to send along
  to the next filter in the pipeline. It does so by calling ``send``
  with whatever it wants to send along to the next filter. There is
  also a version of ``send`` taking a single byte argument, as a
  convenience.

  .. note::

     Normally a filter does not need to override ``send``, though it
     can for special handling. It does however need to call this
     function whenever it wants to produce output.

.. cpp:function:: void Filter::start_msg()

  Implementing this function is optional. Implement it if your filter
  would like to do some processing or setup at the start of each
  message, such as allocating a data structure.

.. cpp:function:: void Filter::end_msg()

  Implementing this function is optional. It is called when it has
  been requested that filters finish up their computations. The filter
  should finish up with whatever computation it is working on (for
  example, a compressing filter would flush the compressor and
  ``send`` the final block), and empty any buffers in preparation for
  processing a fresh new set of input.

Additionally, if necessary, filters can define a constructor that
takes any needed arguments, and a destructor to deal with deallocating
memory, closing files, etc.

