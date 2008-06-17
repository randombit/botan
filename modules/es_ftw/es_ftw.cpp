/*************************************************
* FTW EntropySource Source File                  *
* (C) 1999-2008 Jack Lloyd                       *
*************************************************/

#include <botan/es_ftw.h>
#include <botan/util.h>
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

class Directory_Walker
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

/*************************************************
* FTW_EntropySource Constructor                  *
*************************************************/
FTW_EntropySource::FTW_EntropySource(const std::string& p) : path(p)
   {
   }

/*************************************************
* FTW Fast Poll                                  *
*************************************************/
void FTW_EntropySource::do_fast_poll()
   {
   poll(32*1024);
   }

/*************************************************
* FTW Slow Poll                                  *
*************************************************/
void FTW_EntropySource::do_slow_poll()
   {
   poll(256*1024);
   }

/*************************************************
* FTW Poll                                       *
*************************************************/
void FTW_EntropySource::poll(u32bit max_read)
   {
   Directory_Walker dir(path);
   u32bit read_so_far = 0;

   while(read_so_far < max_read)
      {
      int fd = dir.next_fd();

      if(fd == -1)
         break;

      SecureVector<byte> read_buf(1024);
      ssize_t got = ::read(fd, read_buf.begin(), read_buf.size());

      if(got > 0)
         {
         add_bytes(read_buf, got);
         read_so_far += got;
         }

      ::close(fd);
      }
   }

}
