# **********************************************************
# Copyright (c) 2013 Google, Inc.  All rights reserved.
# **********************************************************

cmake_minimum_required(VERSION 2.6)

# To match Makefiles and have just one build type per configured build
# dir, we collapse VS generator configs to a single choice.
# This must be done prior to the project() command and the var
# must be set in the cache.
if ("${CMAKE_GENERATOR}" MATCHES "Visual Studio")
  if (DEBUG)
    set(CMAKE_CONFIGURATION_TYPES "Debug" CACHE STRING "" FORCE)
  else (DEBUG)
    set(CMAKE_CONFIGURATION_TYPES "Release" CACHE STRING "" FORCE)
  endif (DEBUG)
  # we want to use the _LOCATION_<config> property
  string(TOUPPER "${CMAKE_CONFIGURATION_TYPES}" upper)
  set(location_suffix "_${upper}")
else ("${CMAKE_GENERATOR}" MATCHES "Visual Studio")
  set(location_suffix "")
endif ("${CMAKE_GENERATOR}" MATCHES "Visual Studio")

project(DyTaintCheck)

# To run out of build dir we put libs and scripts in dirs that match install layout
# except minus the toolname prefix dir.
# The CPack NSIS interface requires a bin/ dir, so for the Windows package
# we prefix bin/
# XXX: should clean all this up and normalize across platforms now
# that we have drsyms on Linux and once we're sure we don't need to
# support the old layout.
if (WIN32 AND USE_DRSYMS)
  set(INSTALL_BIN_PREFIX ".")
  set(BUILD_BIN_PREFIX ".")
elseif (PERL_TO_EXE)
  # We are only releasing Dr. Memory so no toolnames: would need to create
  # shortcut or .bat file to run from right dir
  if (X64)
    set(INSTALL_BIN_PREFIX "bin64")
    set(BUILD_BIN_PREFIX "bin64")
  else (X64)
    set(INSTALL_BIN_PREFIX "bin")
    set(BUILD_BIN_PREFIX "bin")
  endif (X64)
else (PERL_TO_EXE)
  # When installed we now use a bin dir for scripts
  if (X64)
    set(INSTALL_BIN_PREFIX "${toolname}/bin64")
    set(BUILD_BIN_PREFIX "bin64")
  else (X64)
    set(INSTALL_BIN_PREFIX "${toolname}/bin")
    set(BUILD_BIN_PREFIX "bin")
  endif (X64)
endif (WIN32 AND USE_DRSYMS)
if (WIN32 AND USE_DRSYMS)
  # For NSIS we have everything in top-level bin/
  # Once we have x64 we'll need to address: fix CPack?
  if (X64)
    set(INSTALL_BIN "${INSTALL_BIN_PREFIX}/bin64")
    set(BUILD_BIN "${BUILD_BIN_PREFIX}/bin64")
  else (X64)
    set(INSTALL_BIN "${INSTALL_BIN_PREFIX}/bin")
    set(BUILD_BIN "${BUILD_BIN_PREFIX}/bin")
  endif (X64)
else (WIN32 AND USE_DRSYMS)
  set(INSTALL_BIN "${INSTALL_BIN_PREFIX}/${BIN_ARCH}")
  set(BUILD_BIN "${BUILD_BIN_PREFIX}/${BIN_ARCH}")
endif (WIN32 AND USE_DRSYMS)
if (DEBUG_BUILD)
  set(build_type "debug")
else (DEBUG_BUILD)
  set(build_type "release")
endif (DEBUG_BUILD)
set(INSTALL_LIB "${INSTALL_BIN}/${build_type}")
set(BUILD_LIB "${BUILD_BIN}/${build_type}")

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/${BUILD_LIB}")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/${BUILD_BIN}")
if ("${CMAKE_GENERATOR}" MATCHES "Visual Studio")
  # we don't support the Debug and Release subdirs
  foreach (config ${CMAKE_CONFIGURATION_TYPES})
    string(TOUPPER "${config}" config_upper)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${config_upper}
      "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${config_upper}
      "${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}")
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${config_upper}
      "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
  endforeach ()
endif ()

if (BUILD_TESTS)
  # For automated sanity tests we can't have msgboxes or output
  set(SHOW_RESULTS_DEFAULT OFF)
else (BUILD_TESTS)
  set(SHOW_RESULTS_DEFAULT ON)
endif (BUILD_TESTS)

option(SHOW_RESULTS
  "Display client results in pop-up (Windows) or console message (Linux)"
  ${SHOW_RESULTS_DEFAULT})
if (SHOW_RESULTS)
  add_definitions(-DSHOW_RESULTS)
endif (SHOW_RESULTS)

option(SHOW_SYMBOLS "Use symbol lookup in clients that support it" ON)
if (SHOW_SYMBOLS)
  add_definitions(-DSHOW_SYMBOLS)
endif (SHOW_SYMBOLS)
if (NOT DEFINED GENERATE_PDBS)
  # support running tests over ssh where pdb building is problematic
  set(GENERATE_PDBS ON)
endif (NOT DEFINED GENERATE_PDBS)

if (STATIC_LIBRARY)
  set(libtype STATIC)
else()
  set(libtype SHARED)
endif ()

# i#379: We usually want to build the samples with optimizations to improve the
# chances of inlining, but it's nice to be able to turn that off easily.  A
# release build should already have optimizations, so this should only really
# affect debug builds.
option(OPTIMIZE_SAMPLES
  "Build samples with optimizations to increase the chances of clean call inlining (overrides debug flags)"
  ON)
if (WIN32)
  set(OPT_CFLAGS "/O2")
else (WIN32)
  set(OPT_CFLAGS "-O2")
endif (WIN32)

if (DEBUG)
  set(OPT_CFLAGS "-DDEBUG")
endif (DEBUG)

if (NOT DEFINED DynamoRIO_DIR)
  set(DynamoRIO_DIR "${PROJECT_SOURCE_DIR}/../cmake" CACHE PATH
    "DynamoRIO installation's cmake directory")
endif (NOT DEFINED DynamoRIO_DIR)

find_package(DynamoRIO 4.1)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)

if (WIN32)
  # disable stack protection: "unresolved external symbol ___security_cookie"
  # disable the warning "unreferenced formal parameter" #4100
  # disable the warning "conditional expression is constant" #4127
  # disable the warning "cast from function pointer to data pointer" #4054
  set(CL_CFLAGS "/GS- /wd4100 /wd4127 /wd4054")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CL_CFLAGS}")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CL_CFLAGS}")
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif (WIN32)

if (OPTIMIZE_SAMPLES)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OPT_CFLAGS}")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OPT_CFLAGS}")
endif ()

##################################################
# taintchecklib

add_library(taintchecklib SHARED taintcheck.cpp)

set_property(TARGET taintchecklib PROPERTY COMPILE_DEFINITIONS ${DEFINES_NO_D})

set_target_properties(taintchecklib PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY${location_suffix} "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")

# We rely on i#955's "rpath file" to locate the extension on Windows, for
# the build dir at least.
set(DynamoRIO_RPATH ON)
configure_DynamoRIO_client(taintchecklib)

# We could link with the internal static lib but it's a good exercise
# to test the shared, public version:
#use_DynamoRIO_extension(taintchecklib drmf_drsyscall)
use_DynamoRIO_extension(taintchecklib drmgr)
use_DynamoRIO_extension(taintchecklib drsyms)
#add_dependencies(taintchecklib drsyscall)

install(TARGETS taintchecklib
  RUNTIME DESTINATION "${INSTALL_LIB}" # dll
  LIBRARY DESTINATION "${INSTALL_LIB}" # .so
  PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
  WORLD_READ WORLD_EXECUTE)

# XXX DRi#1078: we should add the relative dir .drpath support!
# For now we copy drsyscall.dll.  CMake won't let us install it as a
# target from this dir so we copy it as a file.
get_target_property(drsys_path drsyscall LOCATION${location_suffix})
install(FILES ${drsys_path} DESTINATION "${INSTALL_LIB}"
  PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
  WORLD_READ WORLD_EXECUTE)

##################################################
# drtaintcheck frontend

# Restore global flags
foreach (config "" ${CMAKE_BUILD_TYPE} ${CMAKE_CONFIGURATION_TYPES})
  if ("${config}" STREQUAL "")
    set(config_upper "")
  else ("${config}" STREQUAL "")
    string(TOUPPER "_${config}" config_upper)
  endif ("${config}" STREQUAL "")
  foreach (var CMAKE_C_FLAGS${config_upper};CMAKE_CXX_FLAGS${config_upper})
    set(${var} "${SAVE_${var}}")
  endforeach (var)
endforeach (config)

add_executable(drtaintcheck drtaintcheck_frontend.c)
configure_DynamoRIO_standalone(drtaintcheck)
target_link_libraries(drtaintcheck drinjectlib drconfiglib)
#set_target_properties(drtaintcheck PROPERTIES VERSION ${DRMF_VERSION})
set_property(TARGET drtaintcheck PROPERTY COMPILE_DEFINITIONS ${DEFINES_NO_D})

install(TARGETS drtaintcheck DESTINATION "${INSTALL_BIN}"
  PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
  WORLD_READ WORLD_EXECUTE)
