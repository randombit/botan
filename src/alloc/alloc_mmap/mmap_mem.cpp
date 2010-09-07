/*
* Memory Mapping Allocator
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/mmap_mem.h>
#include <vector>
#include <cstring>

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

#ifndef MAP_FAILED
   #define MAP_FAILED -1
#endif

namespace Botan {

namespace {

/*
* MemoryMapping_Allocator Exception
*/
class BOTAN_DLL MemoryMapping_Failed : public Exception
   {
   public:
      MemoryMapping_Failed(const std::string& msg) :
         Exception("MemoryMapping_Allocator: " + msg) {}
   };

}

/*
* Memory Map a File into Memory
*/
void* MemoryMapping_Allocator::alloc_block(u32bit n)
   {
   class TemporaryFile
      {
      public:
         int get_fd() const { return fd; }

         TemporaryFile(const std::string& base)
            {
            const std::string mkstemp_template = base + "XXXXXX";

            std::vector<char> filepath(mkstemp_template.begin(),
                                       mkstemp_template.end());
            filepath.push_back(0); // add terminating NULL

            mode_t old_umask = ::umask(077);
            fd = ::mkstemp(&filepath[0]);
            ::umask(old_umask);

            if(fd == -1)
               throw MemoryMapping_Failed("Temporary file allocation failed");

            if(::unlink(&filepath[0]) != 0)
               throw MemoryMapping_Failed("Could not unlink temporary file");
            }

         ~TemporaryFile()
            {
            /*
            * We can safely close here, because post-mmap the file
            * will continue to exist until the mmap is unmapped from
            * our address space upon deallocation.
            */
            if(fd != -1 && ::close(fd) == -1)
               throw MemoryMapping_Failed("Could not close file");
            }
      private:
         int fd;
      };

   TemporaryFile file("/tmp/botan_");

   if(file.get_fd() == -1)
      throw MemoryMapping_Failed("Could not create file");

   if(::lseek(file.get_fd(), n-1, SEEK_SET) < 0)
      throw MemoryMapping_Failed("Could not seek file");

   if(::write(file.get_fd(), "\0", 1) != 1)
      throw MemoryMapping_Failed("Could not write to file");

#ifndef MAP_NOSYNC
   #define MAP_NOSYNC 0
#endif

   void* ptr = ::mmap(0, n,
                      PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_NOSYNC,
                      file.get_fd(), 0);

   if(ptr == static_cast<void*>(MAP_FAILED))
      throw MemoryMapping_Failed("Could not map file");

   return ptr;
   }

/*
* Remove a Memory Mapping
*/
void MemoryMapping_Allocator::dealloc_block(void* ptr, u32bit n)
   {
   if(ptr == 0)
      return;

   const byte PATTERNS[] = { 0x00, 0xFF, 0xAA, 0x55, 0x73, 0x8C, 0x5F, 0xA0,
                             0x6E, 0x91, 0x30, 0xCF, 0xD3, 0x2C, 0xAC, 0x00 };

   for(u32bit j = 0; j != sizeof(PATTERNS); j++)
      {
      std::memset(ptr, PATTERNS[j], n);

      if(::msync((char*)ptr, n, MS_SYNC))
         throw MemoryMapping_Failed("Sync operation failed");
      }

   if(::munmap((char*)ptr, n))
      throw MemoryMapping_Failed("Could not unmap file");
   }

}
