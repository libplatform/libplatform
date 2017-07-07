cmake_minimum_required(VERSION 3.0)

set(CMAKE_CXX_FLAGS "-nostdlib -nodefaultlibs -fno-exceptions -fPIC")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -ggdb -O0")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -O3")

set(CMAKE_C_COMPILER "clang-4.0")
set(CMAKE_CXX_COMPILER "clang++-4.0")

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED YES)

project(platform)

# figure out what platform we are on
set(PLATFORM "")
if(APPLE)
  set(PLATFORM "macOS")
elseif(UNIX AND NOT APPLE)
  set(PLATFORM "Linux")
endif()
set(BITSIZE 32)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(BITSIZE 64)
endif()

set(PLATFORM_SRCS
  libplatform/platform/types.h
  libplatform/platform/platform.h
  libplatform/src/platform.cc
  libplatform/src/platform_internal.h
  libplatform/src/win64.cc
  libplatform/src/apple64.cc
  libplatform/src/linux64.cc
  )

enable_language(ASM)

if(PLATFORM STREQUAL Linux AND BITSIZE EQUAL 64)
  message(STATUS "Targeting Linux-64 kernel")  
  add_definitions("-DABI_AMD64 -DLINUX64")
elseif(PLATFORM STREQUAL macOS AND BITSIZE EQUAL 64)
  message(STATUS "Targeting Linux-64 kernel")
  enable_language(ASM)
  add_definitions("-DABI_AMD64 -DAPPLE64")
else()
  message(FATAL_ERROR "No platform implementation for ${PLATFORM}-${BITSIZE}")
endif()

set(CRT_SRCS
  libplatform/src/crt.cc
  libplatform/src/crt.S
  )

set(C_SRCS
  libc/c/libc.h
  libc/src/libc.cc
  )

include_directories("libc")
include_directories("libplatform")

add_library(platform SHARED ${PLATFORM_SRCS})
add_library(crt STATIC ${CRT_SRCS})
add_library(c SHARED ${C_SRCS})

install(TARGETS platform c LIBRARY DESTINATION lib)
install(DIRECTORY libplatform/platform DESTINATION include)

target_link_libraries(c platform)

add_executable(test_platform "libplatform/tests/test_platform.cc")
target_link_libraries(test_platform crt platform c)

# libcrt.a needs to get added before anything else for ordering of data
# in some sections
set_target_properties(test_platform PROPERTIES LINK_FLAGS "libcrt.a")
