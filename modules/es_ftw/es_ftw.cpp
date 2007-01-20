/*************************************************
* FTW EntropySource Source File                  *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/es_ftw.h>
#include <botan/util.h>
#include <fstream>
#include <cstring>
#include <vector>

#ifndef _POSIX_C_SOURCE
  #define _POSIX_C_SOURCE 199309
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>

namespace Botan {

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
   files_read = 0;
   max_read = 32;
   gather_from_dir(path);
   }

/*************************************************
* FTW Slow Poll                                  *
*************************************************/
void FTW_EntropySource::do_slow_poll()
   {
   files_read = 0;
   max_read = 256;
   gather_from_dir(path);
   }

/*************************************************
* Gather Entropy From Directory Tree             *
*************************************************/
void FTW_EntropySource::gather_from_dir(const std::string& dirname)
   {
   if(dirname == "" || files_read >= max_read)
      return;

   DIR* dir = opendir(dirname.c_str());
   if(dir == 0)
      return;

   std::vector<std::string> subdirs;

   dirent* entry = readdir(dir);
   while(entry && (files_read < max_read))
      {
      if((std::strcmp(entry->d_name, ".") == 0) ||
         (std::strcmp(entry->d_name, "..") == 0))
         { entry = readdir(dir); continue; }

      const std::string filename = dirname + '/' + entry->d_name;

      struct stat stat_buf;
      if(lstat(filename.c_str(), &stat_buf) == -1)
         { entry = readdir(dir); continue; }

      if(S_ISREG(stat_buf.st_mode))
         gather_from_file(filename);
      else if(S_ISDIR(stat_buf.st_mode))
         subdirs.push_back(filename);
      entry = readdir(dir);
      }
   closedir(dir);

   for(u32bit j = 0; j != subdirs.size(); j++)
      gather_from_dir(subdirs[j]);
   }

/*************************************************
* Gather Entropy From A File                     *
*************************************************/
void FTW_EntropySource::gather_from_file(const std::string& filename)
   {
   int fd = ::open(filename.c_str(), O_RDONLY | O_NOCTTY);
   if(fd == -1)
      return;

   SecureVector<byte> read_buf(1024);
   ssize_t got = ::read(fd, (byte*)read_buf.begin(), read_buf.size());
   close(fd);

   if(got > 0)
      {
      add_bytes(read_buf, got);
      files_read++;
      }
   }

}
