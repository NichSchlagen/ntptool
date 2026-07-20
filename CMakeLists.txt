cmake_minimum_required(VERSION 3.15)

project(ntptool
    VERSION 1.0.0
    DESCRIPTION "A comprehensive NTP server testing toolkit"
    LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(NTPTOOL_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)
option(NTPTOOL_BUILD_TESTS        "Build the self-test suite"         ON)

# ---------------------------------------------------------------------------
# Global settings
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------
set(NTPTOOL_SOURCES
    src/util.cpp
    src/ntp_time.cpp
    src/ntp_packet.cpp
    src/udp_socket.cpp
    src/md5.cpp
    src/sha1.cpp
    src/ntp_client.cpp
    src/statistics.cpp
    src/ntp_control.cpp
    src/output.cpp
    src/cli.cpp
    src/commands/cmd_query.cpp
    src/commands/cmd_monitor.cpp
    src/commands/cmd_compare.cpp
    src/commands/cmd_scan.cpp
    src/commands/cmd_control.cpp
    src/commands/cmd_security.cpp
    src/commands/cmd_trace.cpp
    src/commands/cmd_selftest.cpp
    src/main.cpp
)

add_executable(ntptool ${NTPTOOL_SOURCES})

target_include_directories(ntptool PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")

# ---------------------------------------------------------------------------
# Threads
# ---------------------------------------------------------------------------
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(ntptool PRIVATE Threads::Threads)

# ---------------------------------------------------------------------------
# Platform specifics
# ---------------------------------------------------------------------------
if(WIN32)
    target_link_libraries(ntptool PRIVATE ws2_32 iphlpapi)
    target_compile_definitions(ntptool PRIVATE
        _WIN32_WINNT=0x0601        # Windows 7+
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _CRT_SECURE_NO_WARNINGS)
endif()

# ---------------------------------------------------------------------------
# Warnings
# ---------------------------------------------------------------------------
if(MSVC)
    target_compile_options(ntptool PRIVATE /W4 /permissive-)
    if(NTPTOOL_WARNINGS_AS_ERRORS)
        target_compile_options(ntptool PRIVATE /WX)
    endif()
else()
    target_compile_options(ntptool PRIVATE
        -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion)
    if(NTPTOOL_WARNINGS_AS_ERRORS)
        target_compile_options(ntptool PRIVATE -Werror)
    endif()
endif()

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
include(GNUInstallDirs)
install(TARGETS ntptool RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

message(STATUS "ntptool ${PROJECT_VERSION} configured (${CMAKE_BUILD_TYPE})")
