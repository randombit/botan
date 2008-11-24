/*************************************************
* FTW EntropySource Source File                  *
* (C) 1999-2008 Jack Lloyd                       *
*************************************************/

#include <botan/es_ftw.h>
#include <botan/secmem.h>
#include <botan/xor_buf.h>
#include <cstring>
#include <deque>

#ifndef _POSIX_C_SOURCE
  #define _POSIX_C_SOURCE 199309
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>

namespace Botan {

namespace {

class Directory_Walker : public FTW_EntropySource::File_Descriptor_Source
   {
   public:
      Directory_Walker(const std::string& root) { add_directory(root); }
      ~Directory_Walker();

      int next_fd();
   private:
      void add_directory(const std::string&);

      std::deque<std::pair<DIR*, std::string> > dirs;
   };

void Directory_Walker::add_directory(const std::string& dirname)
   {
   DIR* dir = ::opendir(dirname.c_str());
   if(dir)
      dirs.push_back(std::make_pair(dir, dirname));
   }

Directory_Walker::~Directory_Walker()
   {
   while(dirs.size())
      {
      ::closedir(dirs[0].first);
      dirs.pop_front();
      }
   }

int Directory_Walker::next_fd()
   {
   while(dirs.size())
      {
      std::pair<DIR*, std::string> dirinfo = dirs[0];

      struct dirent* entry = ::readdir(dirinfo.first);

      if(!entry)
         {
         ::closedir(dirinfo.first);
         dirs.pop_front();
         continue;
         }

      const std::string filename = entry->d_name;

      if(filename == "." || filename == "..")
         continue;

      const std::string full_path = dirinfo.second + '/' + filename;

      struct stat stat_buf;
      if(::lstat(full_path.c_str(), &stat_buf) == -1)
         continue;

      if(S_ISDIR(stat_buf.st_mode))
         add_directory(full_path);
      else if(S_ISREG(stat_buf.st_mode))
         {
         int fd = ::open(full_path.c_str(), O_RDONLY | O_NOCTTY);

         if(fd > 0)
            return fd;
         }
      }

   return -1;
   }

}

/**
* FTW_EntropySource Constructor
*/
FTW_EntropySource::FTW_EntropySource(const std::string& p) : path(p)
   {
   dir = 0;
   }

/**
* FTW_EntropySource Destructor
*/
FTW_EntropySource::~FTW_EntropySource()
   {
   delete dir;
   }

u32bit FTW_EntropySource::slow_poll(byte buf[], u32bit length)
   {
   if(!dir)
      dir = new Directory_Walker(path);

   SecureVector<byte> read_buf(4096);

   u32bit bytes_read = 0;
   u32bit buf_i = 0;

   while(bytes_read < length * 32)
      {
      int fd = dir->next_fd();

      if(fd == -1) // re-walk
         {
         delete dir;
         dir = new Directory_Walker(path);
         fd = dir->next_fd();

         if(fd == -1) // still fails (directory not mounted, etc) -> fail
            return 0;
         }

      ssize_t got = ::read(fd, read_buf.begin(), read_buf.size());

      if(got > 0)
         {
         buf_i = xor_into_buf(buf, buf_i, length, read_buf, got);

         // never count any one file for more than 128 bytes
         bytes_read += std::min<u32bit>(got, 128);
         }

      ::close(fd);
      }

   return length;
   }

u32bit FTW_EntropySource::fast_poll(byte[], u32bit)
   {
   return 0; // no op
   }

}
