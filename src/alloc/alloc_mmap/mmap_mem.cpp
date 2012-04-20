/*
* Memory Mapping Allocator
* (C) 1999-2010 Jack Lloyd
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
#include <errno.h>

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
void* MemoryMapping_Allocator::alloc_block(size_t n)
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
            * our address space upon deallocation (or process exit).
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

   std::vector<byte> zeros(4096);

   size_t remaining = n;

   while(remaining)
      {
      const size_t write_try = std::min(zeros.size(), remaining);

      ssize_t wrote_got = ::write(file.get_fd(),
                                  &zeros[0],
                                  write_try);

      if(wrote_got == -1 && errno != EINTR)
         throw MemoryMapping_Failed("Could not write to file");

      remaining -= wrote_got;
      }

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
void MemoryMapping_Allocator::dealloc_block(void* ptr, size_t n)
   {
   if(ptr == 0)
      return;

   const byte PATTERNS[] = { 0x00, 0xF5, 0x5A, 0xAF, 0x00 };

   // The char* casts are for Solaris, args are void* on most other systems

   for(size_t i = 0; i != sizeof(PATTERNS); ++i)
      {
      std::memset(ptr, PATTERNS[i], n);

      if(::msync(static_cast<char*>(ptr), n, MS_SYNC))
         throw MemoryMapping_Failed("Sync operation failed");
      }

   if(::munmap(static_cast<char*>(ptr), n))
      throw MemoryMapping_Failed("Could not unmap file");
   }

}
