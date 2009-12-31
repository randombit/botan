/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

/*
This is just like the normal hash application, but uses the Unix I/O
system calls instead of C++ iostreams. Previously, this version was
much faster and smaller, but GCC 3.1's libstdc++ seems to have been
improved enough that the difference is now fairly minimal.

Nicely enough, doing the change required changing only about 3 lines
of code.
*/

#include <iostream>
#include <botan/botan.h>

#if !defined(BOTAN_HAS_PIPE_UNIXFD_IO)
  #error "You didn't compile the pipe_unixfd module into Botan"
#endif

#include <fcntl.h>
#include <unistd.h>

int main(int argc, char* argv[])
   {
   if(argc < 3)
      {
      std::cout << "Usage: " << argv[0] << " digest <filenames>" << std::endl;
      return 1;
      }

   Botan::LibraryInitializer init;

   try
      {
      Botan::Pipe pipe(new Botan::Hash_Filter(argv[1]),
                       new Botan::Hex_Encoder);

      int skipped = 0;
      for(int j = 2; argv[j] != 0; j++)
         {
         int file = open(argv[j], O_RDONLY);
         if(file == -1)
            {
            std::cout << "ERROR: could not open " << argv[j] << std::endl;
            skipped++;
            continue;
            }
         pipe.start_msg();
         file >> pipe;
         pipe.end_msg();
         close(file);
         pipe.set_default_msg(j-2-skipped);
         std::cout << pipe << "  " << argv[j] << std::endl;
         }
   }
   catch(Botan::Algorithm_Not_Found)
      {
      std::cout << "Don't know about the hash function \"" << argv[1] << "\""
                << std::endl;
      }
   catch(std::exception& e)
      {
      std::cout << "Exception caught: " << e.what() << std::endl;
      }
   return 0;
   }
