Build instructions for Botan SQLite3 codec
---

1. Requires Botan 1.9.0 or later

2. Download and extract SQLite3 version 3.7.0.1 or later (previous
   versions may work, untested)

3. From the extracted sqlite folder, apply the patch "sqlite3.diff":
       $ patch -p0 < ../sqlite.diff
       patching file Makefile.in
       patching file sqlite3.c

   If the patch to fails for some reason (ie, changes in SQLite3), it
   should be trivial to do it manually.

4. Copy all files inside the "src" directory into the Sqlite3 directory
   (codec.cpp, codec.h, codec_c_interface.h, codecext.c)

5. As desired, edit the constants in codec.h to tweak the encryption
   type to your needs. (Currently, Twofish/XTS with 256 bit key)

6. "./configure" and "make" Sqlite3

And to make sure it all worked...

7. Make the test_sqlite.cpp file:
      $ g++ test_sqlite.cpp -o test_sqlite -lbotan /path/to/libsqlite3.a
8. Run it
      $ ./test_sqlite
9. Look for "All seems good"