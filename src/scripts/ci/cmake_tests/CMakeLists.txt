cmake_minimum_required(VERSION 3.24)

project(Botan_CMake_Tests CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED On)
set(CMAKE_CXX_EXTENSIONS Off)

if(NOT BOTAN_DISABLED_MODULE)
  message(FATAL_ERROR "Set -DBOTAN_DISABLED_MODULE=??? to define an existing but disabled module for testing.")
endif()

message(STATUS "Assuming that Botan module '${BOTAN_DISABLED_MODULE}' is not available in this build.")

# test #1: find any Botan version and link dynamically
find_package(Botan REQUIRED)
if(NOT Botan_FOUND)
  message(FATAL_ERROR "Test #1 failed: Failed to find Botan with any version")
endif()

if(TARGET Botan::Botan)
  add_executable(botan_version_test main.cpp)
  target_link_libraries(botan_version_test Botan::Botan)

  if(WIN32)
    add_custom_command(TARGET botan_version_test POST_BUILD
                       COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_RUNTIME_DLLS:botan_version_test> $<TARGET_FILE_DIR:botan_version_test>
                       COMMAND_EXPAND_LISTS)
  endif()

  add_test(NAME "Using shared library"
           COMMAND botan_version_test
           PASS_REGULAR_EXPRESSION "${Botan_VERSION}")
endif()

unset(Botan_FOUND)

# test #2: link statically
find_package(Botan REQUIRED)
if(TARGET Botan::Botan-static)
  add_executable(botan_version_test_static main.cpp)
  target_link_libraries(botan_version_test_static Botan::Botan-static)

  add_test(NAME "Using static library"
           COMMAND botan_version_test_static
           PASS_REGULAR_EXPRESSION "${Botan_VERSION}")
endif()

unset(Botan_FOUND)

# test #3: find Botan version installed by version number
find_package(Botan ${Botan_VERSION} REQUIRED)
if(NOT Botan_FOUND)
  message(FATAL_ERROR "Failed to find Botan with version ${Botan_VERSION}")
endif()

unset(Botan_FOUND)

# test #4: find Botan with specific modules
find_package(Botan ${Botan_VERSION} COMPONENTS ecdsa rsa REQUIRED)
if(NOT Botan_ecdsa_FOUND OR NOT Botan_rsa_FOUND)
  message(FATAL_ERROR "Package did not specify that the (optional) components were found: ecdsa, rsa")
endif()

if(NOT Botan_FOUND)
  message(FATAL_ERROR "Failed to find Botan with version ${Botan_VERSION} containing modules: ecdsa, rsa")
endif()

unset(Botan_FOUND)

# test #5: fail if required module is not included
find_package(Botan ${Botan_VERSION} COMPONENTS ${BOTAN_DISABLED_MODULE} QUIET)
if(Botan_FOUND)
  message(FATAL_ERROR "Found Botan with version ${Botan_VERSION}: Found module ${BOTAN_DISABLED_MODULE} but expected it to be absent")
endif()

unset(Botan_FOUND)

# test #6: do not fail if optional module is not included
find_package(Botan ${Botan_VERSION} OPTIONAL_COMPONENTS ${BOTAN_DISABLED_MODULE} REQUIRED)
if(NOT Botan_FOUND)
  message(FATAL_ERROR "Failed to find Botan with version ${Botan_VERSION}, despite missing optional modules: ${BOTAN_DISABLED_MODULE}")
endif()
if(NOT DEFINED Botan_${BOTAN_DISABLED_MODULE}_FOUND OR ${Botan_${BOTAN_DISABLED_MODULE}_FOUND})
  message(FATAL_ERROR "Failed to notify that the optional component was not found")
endif()

unset(Botan_FOUND)

# test #7: fail with some specific (but unavailable) component and fall-back to generic
find_package(Botan ${Botan_VERSION} COMPONENTS nonexistent unobtainium QUIET)
if(NOT Botan_FOUND)
  # try again without requiring specific components
  find_package(Botan ${Botan_VERSION})
else()
  message(FATAL_ERROR "Found Botan regardless of the non-existent component requirement")
endif()
if(NOT Botan_FOUND)
  message(FATAL_ERROR "Failed to find generic Botan as a second attempt")
endif()

unset(Botan_FOUND)

# test #8: try to find a future version
math(EXPR Botan_FUTURE_MAJOR_VERSION "${Botan_VERSION_MAJOR} + 1")
find_package(Botan ${Botan_FUTURE_MAJOR_VERSION} QUIET)
if(Botan_FOUND)
  message(FATAL_ERROR "Found a future major version that doesn't exist yet: ${Botan_FUTURE_MAJOR_VERSION}")
endif()

unset(Botan_FOUND)

# test #9: try to find an older version (that is not compatible with the installed one)
math(EXPR Botan_PAST_MAJOR_VERSION "${Botan_VERSION_MAJOR} - 1")
find_package(Botan ${Botan_PAST_MAJOR_VERSION} QUIET)
if(Botan_FOUND)
  message(FATAL_ERROR "Found a legacy major version that doesn't exist yet: ${Botan_PAST_MAJOR_VERSION}")
endif()

unset(Botan_FOUND)

# test #10: try to find Botan with a different case-sensitive spelling
find_package(botan COMPONENTS rsa REQUIRED)
if(NOT botan_FOUND)
  message(FATAL_ERROR "Failed to find Botan with a different case-spelling")
endif()
if(NOT botan_rsa_FOUND)
  message(FATAL_ERROR "Failed to find Botan component with a different case-spelling")
endif()

unset(Botan_FOUND)
unset(botan_FOUND)

enable_testing()
