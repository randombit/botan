Botan CMS alpha1
December 12, 2003

To use this, download a recent version of Botan (1.2.8 or 1.3.7 are best), and
move the source files to src/, the headers to include/ and then run
configure/make as normal. You will then have a CMS encoder/decoder. There are a
couple of testing apps in testing/ which should show the general idea. Lots of
it is unimplemented (which it will tell you by throwing exceptions), but basic
RSA encryption/signatures and a few other things work OK. The encoder is much
more complete than the decoder.

The encoder works by initializing it with some bits, then calling some number
of operations on it (compress(), digest(), encrypt(), etc) which successfully
'envelope' the data. The decoder works exactly the same, except backwards. (Of
course!)

This was supposed to have been finished by now, but it's kind of stalled. I
want CMS support, I just don't really want to code it. So I've been occupying
myself with various distractions. I'll probably finish it *someday*.

If someone out there really wants this soon, and is willing to pay some nominal
consulting fee (we're talking cheap), let me know and we can talk about
it. I think I need some external motivation of some sort to force me to tell
with the mess that is CMS.
