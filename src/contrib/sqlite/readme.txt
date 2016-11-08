Build instructions for BotanSqlite3
---

Requirements:
  1. Botan 1.9.0 or later
  2. SQLite3 amalgamation source, version 3.7.12.1 or later (previous versions may work, some will need minor changes)


Building:

1. Extract sqlite3 amalgamation to a directory and add BotanSqlite3 source files

   If desired, codec.h can be modified to tweak the encryption algothrithms and parameters. (Defaults to Twofish/XTS with 256 bit key)

2. Apply the patch "sqlite3.diff":
    $ patch -p0 < sqlite3-amalgamation.patch

   If the patching fails for some reason (ie, changes in SQLite3), it should be trivial to do it manually.

3. Compile the sqlite3 library with Botan encryption support:
    $ gcc -c sqlite3.c -o botansqlite3.o && gcc -c codec.cpp -o codec.o `pkg-config --cflags botan-1.10` && ar rcs libbotansqlite3.a botansqlite3.o codec.o
    
    (replace "botan-1.10" with appropriate version)

Testing:

1. Build the test:
      $ g++ test_sqlite.cpp -o test_sqlite `botan-config-1.10 --libs` ./libbotansqlite3.a
      
      (replace botan-config-1.10 w/ appropriate version)

2. Run the test
      $ ./test_sqlite

3. Look for "All seems good"
