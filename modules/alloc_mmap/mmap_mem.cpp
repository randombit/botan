/*************************************************
* Memory Mapping Allocator Source File           *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/mmap_mem.h>
#include <cstring>

#ifndef _XOPEN_SOURCE
  #define _XOPEN_SOURCE 500
#endif

#ifndef _XOPEN_SOURCE_EXTENDED
  #define _XOPEN_SOURCE_EXTENDED 1
#endif

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

/*************************************************
* MemoryMapping_Allocator Exception              *
*************************************************/
class MemoryMapping_Failed : public Exception
   {
   public:
      MemoryMapping_Failed(const std::string& msg) :
         Exception("MemoryMapping_Allocator: " + msg) {}
   };

}

/*************************************************
* Memory Map a File into Memory                  *
*************************************************/
void* MemoryMapping_Allocator::alloc_block(u32bit n)
   {
   class TemporaryFile
      {
      public:
         int get_fd() const { return fd; }
         const std::string path() const { return filepath; }

         TemporaryFile(const std::string& base)
            {
            const std::string path = base + "XXXXXX";

            filepath = new char[path.length() + 1];
            std::strcpy(filepath, path.c_str());

            mode_t old_umask = umask(077);
            fd = mkstemp(filepath);
            umask(old_umask);
            }

         ~TemporaryFile()
            {
            delete[] filepath;
            if(fd != -1 && close(fd) == -1)
               throw MemoryMapping_Failed("Could not close file");
            }
      private:
         int fd;
         char* filepath;
      };

   TemporaryFile file("/tmp/botan_");

   if(file.get_fd() == -1)
      throw MemoryMapping_Failed("Could not create file");

   if(unlink(file.path().c_str()))
      throw MemoryMapping_Failed("Could not unlink file " + file.path());

   lseek(file.get_fd(), n-1, SEEK_SET);
   if(write(file.get_fd(), "\0", 1) != 1)
      throw MemoryMapping_Failed("Could not write to file");

   void* ptr = mmap(0, n, PROT_READ | PROT_WRITE, MAP_SHARED,
                    file.get_fd(), 0);

   if(ptr == (void*)MAP_FAILED)
      throw MemoryMapping_Failed("Could not map file");

   return ptr;
   }

/*************************************************
* Remove a Memory Mapping                        *
*************************************************/
void MemoryMapping_Allocator::dealloc_block(void* ptr, u32bit n)
   {
   if(ptr == 0) return;

   const u32bit OVERWRITE_PASSES = 12;
   const byte PATTERNS[] = { 0x00, 0xFF, 0xAA, 0x55, 0x73, 0x8C, 0x5F, 0xA0,
                             0x6E, 0x91, 0x30, 0xCF, 0xD3, 0x2C, 0xAC, 0x53 };

   for(u32bit j = 0; j != OVERWRITE_PASSES; j++)
      {
      std::memset(ptr, PATTERNS[j % sizeof(PATTERNS)], n);
      if(msync(ptr, n, MS_SYNC))
         throw MemoryMapping_Failed("Sync operation failed");
      }
   std::memset(ptr, 0, n);
   if(msync(ptr, n, MS_SYNC))
      throw MemoryMapping_Failed("Sync operation failed");

   if(munmap(ptr, n))
      throw MemoryMapping_Failed("Could not unmap file");
   }

}
