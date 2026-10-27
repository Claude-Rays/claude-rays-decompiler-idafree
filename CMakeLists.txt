cmake_minimum_required(VERSION 3.25)

# Load the IDA SDK bootstrap (requires the IDASDK environment variable)
include("$ENV{IDASDK}/src/cmake/idasdk_init.cmake")

project(claude-rays-decompiler-idafree CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(idasdk REQUIRED)

# static CRT (/MT). Not IDA_USE_STATIC_RUNTIME: the SDK's x64_win_64_s libs
# ship no ida.lib. ida.lib is only an import library, so it works with /MT.
# Must come after find_package (which sets /MD) and before ida_add_plugin.
option(CR_STATIC_CRT "Link the MSVC runtime statically (/MT)" OFF)
if(MSVC AND CR_STATIC_CRT)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# installed as clauderays-decompiler.dll: Diaphora-ng looks for it by that name
ida_add_plugin(claude-rays-decompiler-idafree
    OUTPUT_NAME clauderays-decompiler
    SOURCES
        src/common.hpp
        src/logo.hpp
        src/util.cpp
        src/models.hpp
        src/models.cpp
        src/json.hpp
        src/json.cpp
        src/process.hpp
        src/process.cpp
        src/backend.hpp
        src/backend.cpp
        src/insn_table.hpp
        src/insn_table.cpp
        src/insn_facts.hpp
        src/insn_facts.cpp
        src/collector.hpp
        src/collector.cpp
        src/validate.hpp
        src/validate.cpp
        src/fixes.hpp
        src/fixes.cpp
        src/cache.hpp
        src/cache.cpp
        src/view.hpp
        src/view.cpp
        src/pair.hpp
        src/pair.cpp
        src/api.cpp
        src/clauderays.cpp
)

# build into <project>/bin instead of the SDK's bin/plugins, next to the sources
set_target_properties(claude-rays-decompiler-idafree PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")

if(MSVC)
    target_compile_options(claude-rays-decompiler-idafree PRIVATE /utf-8)
endif()
