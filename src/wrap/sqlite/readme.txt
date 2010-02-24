Build instructions for Botan SQLite3 codec
---

1. Requires Botan 1.8.8 or later (earlier versions OK if you switch to
   CBC mode from XTS)

2. Download SQLite3 version 3.6.17 or later, get the version "as
   extracted from the source control system", NOT the amalgamation.

3. Apply the patch "sqlite.diff" [*]:
       $ patch -p0 < ../sqlite.diff
       patching file Makefile.in
       patching file src/pager.c

   If the patch to pager.c fails for some reason (ie, changes in
   SQLite3), all that need be done is remove the "static" keyword from
   the functions sqlite3PagerSetCodec and sqlite3PagerGetCodec.

5. Create a folder called "botan" in the SQLite3 src dir and copy
   "codec.cpp", "codec.h", and "codecext.cpp" into it.

6. As desired, edit the constants in codec.h to tweak the encryption
   type to your needs. (Currently, Twofish/XTS with 256 bit key)

7. Run ./configure in the SQLite3 root directory with the
   "--disable-amalgamation" and (if desired) "--disable-shared"
   arguments, and then run make.

And to make sure it all worked...

8. Make the test_sqlite.cpp file:
      $ g++ test_sqlite.cpp -o test_sqlite -lbotan /path/to/libsqlite3.a
9. Run it
      $ ./test_sqlite
10. Look for "All seems good"

