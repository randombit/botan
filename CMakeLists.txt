project(Botan)
cmake_minimum_required(VERSION 2.8)

# Configure for use with CMake
#
#   ./configure.py --with-bzip2 --with-zlib --enable-modules="dyn_load"
#

macro(use_cxx11)
  if (CMAKE_VERSION VERSION_LESS "3.1")
    if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
      set (CMAKE_CXX_FLAGS "--std=gnu++11 ${CMAKE_CXX_FLAGS}")
    endif ()
  else ()
    set (CMAKE_CXX_STANDARD 11)
  endif ()
endmacro(use_cxx11)

use_cxx11()

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -O2 -g")
    set(CMAKE_CXX_FLAGS "-O0 -g ${CMAKE_CXX_FLAGS} -Wall -Wextra -Wformat=2 -Wlogical-op -Wmissing-include-dirs -Wnon-virtual-dtor -Woverloaded-virtual -Wswitch-default -Wuninitialized")
endif()

# libbotan
add_subdirectory("src/lib")

# cmd
add_subdirectory("src/cmd")

# tests
add_subdirectory("src/tests")

add_dependencies(Botan-tests botan)
