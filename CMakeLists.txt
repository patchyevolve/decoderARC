cmake_minimum_required(VERSION 3.16)
project(ids_system CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Build type defaults ───────────────────────────────────────
# FIX: don't hardcode -O2 globally — it breaks Debug builds.
# Release gets -O2 via the standard CMake mechanism; Debug gets -O0 -g.
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "No build type set — defaulting to Release")
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

add_compile_options(-Wall -Wextra)

# ── Threads (required by ids_sharded.hpp) ─────────────────────
# FIX: std::thread / std::mutex / std::atomic need -lpthread on Linux.
# Without this, ids_sharded targets link fine but crash at runtime.
find_package(Threads REQUIRED)

# ── Header-only IDS library ───────────────────────────────────
# FIX: headers live in include/, not in CMAKE_SOURCE_DIR directly.
add_library(ids INTERFACE)
target_include_directories(ids INTERFACE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(ids INTERFACE Threads::Threads)

# ── Main demo ─────────────────────────────────────────────────
add_executable(ids_demo ids_example.cpp)
target_link_libraries(ids_demo PRIVATE ids)

# ── Tests ─────────────────────────────────────────────────────
enable_testing()

if(EXISTS ${CMAKE_SOURCE_DIR}/ids_model_test.cpp)
    add_executable(ids_model_test ids_model_test.cpp)
    target_link_libraries(ids_model_test PRIVATE ids)
    add_test(NAME model_pipeline COMMAND ids_model_test)
endif()

if(EXISTS ${CMAKE_SOURCE_DIR}/ids_sharded_test.cpp)
    add_executable(ids_sharded_test ids_sharded_test.cpp)
    target_link_libraries(ids_sharded_test PRIVATE ids)
    add_test(NAME sharded_pipeline COMMAND ids_sharded_test)
endif()

# ── Live visualizer (optional — needs libpcap + ncurses) ──────
# FIX 1: find_library only locates the .so/.a, not pcap.h.
#         find_path separately ensures the header is locatable too.
# FIX 2: independent if() checks so BOTH missing warnings always fire.
# FIX 3: find_package(Curses) handles the -ltinfo dependency on some platforms.

find_library(PCAP_LIB   NAMES pcap
    HINTS /usr/lib /usr/local/lib /opt/homebrew/lib)
find_path(PCAP_INCLUDE  NAMES pcap.h
    HINTS /usr/include /usr/local/include /opt/homebrew/include)

find_package(Curses QUIET)   # provides CURSES_LIBRARIES + CURSES_INCLUDE_DIRS

if(NOT PCAP_LIB OR NOT PCAP_INCLUDE)
    message(WARNING
        "libpcap not found — ids_visualizer will not be built.\n"
        "  Ubuntu/Debian : sudo apt install libpcap-dev\n"
        "  RHEL/Fedora   : sudo dnf install libpcap-devel\n"
        "  macOS         : brew install libpcap")
endif()

if(NOT CURSES_FOUND)
    message(WARNING
        "libncurses not found — ids_visualizer will not be built.\n"
        "  Ubuntu/Debian : sudo apt install libncurses-dev\n"
        "  RHEL/Fedora   : sudo dnf install ncurses-devel\n"
        "  macOS         : brew install ncurses")
endif()

if(PCAP_LIB AND PCAP_INCLUDE AND CURSES_FOUND)
    add_executable(ids_visualizer ids_visualizer.cpp)
    target_include_directories(ids_visualizer PRIVATE
        ${PCAP_INCLUDE}
        ${CURSES_INCLUDE_DIRS})
    target_link_libraries(ids_visualizer PRIVATE
        ids
        ${PCAP_LIB}
        ${CURSES_LIBRARIES})   # includes -ltinfo automatically when needed
    message(STATUS
        "ids_visualizer enabled\n"
        "  pcap    : ${PCAP_LIB}\n"
        "  ncurses : ${CURSES_LIBRARIES}")
endif()
