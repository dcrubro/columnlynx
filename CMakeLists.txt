cmake_minimum_required(VERSION 3.16)

# Version structure:
# MAJOR.MINOR.PATCH
# If MAJOR is 0, and MINOR is 0, Version is ALPHA
# If MAJOR is 0, and MINOR > 0, Version is BETA

project(ColumnLynx
    VERSION 0.2.0
    LANGUAGES CXX
)

# ---------------------------------------------------------
# General C++ setup
# ---------------------------------------------------------
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
#set(CMAKE_CXX_FLAGS_DEBUG "-g")
#add_compile_options(${CMAKE_CXX_FLAGS_DEBUG})

if(DEBUG)
    add_compile_definitions(DEBUG=1) # TODO: Forcing for now, add dymanic based on compile flags later
endif()

include(FetchContent)

# ---------------------------------------------------------
# macOS: Force architecture before fetching dependencies
# ---------------------------------------------------------
if(APPLE)
    # Build universal (arm64 + x86_64), or limit to one arch if you prefer
    # e.g., set(CMAKE_OSX_ARCHITECTURES "arm64" CACHE STRING "" FORCE)
    set(CMAKE_OSX_ARCHITECTURES "arm64" CACHE STRING "Build architectures" FORCE)
endif()

# ---------------------------------------------------------
# Platform-specific options
# ---------------------------------------------------------
if(WIN32)
    add_compile_definitions(_WIN32_WINNT=0x0A00 NOMINMAX WIN32_LEAN_AND_MEAN)
elseif(UNIX)
    add_compile_options(-Wall -Wextra -Wpedantic -O3)
    add_link_options(-pthread)
endif()

# ---------------------------------------------------------
# Fetch libsodium (after arch and platform settings)
# ---------------------------------------------------------
FetchContent_Declare(
    Sodium
    GIT_REPOSITORY https://github.com/robinlinden/libsodium-cmake.git
    GIT_TAG e5b985ad0dd235d8c4307ea3a385b45e76c74c6a  # Last updated at 2025-04-13
)

set(SODIUM_DISABLE_TESTS ON CACHE BOOL "" FORCE)
set(SODIUM_STATIC ON CACHE BOOL "" FORCE)

# Fetch asio
FetchContent_Declare(
    asio
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
    GIT_TAG asio-1-36-0
)

# Fetch cxxopts
FetchContent_Declare(
    cxxopts
    GIT_REPOSITORY https://github.com/jarro2783/cxxopts.git
    GIT_TAG v3.3.1
)

# Forward architecture and build type to subproject
set(SODIUM_CMAKE_ARGS
    -DCMAKE_OSX_ARCHITECTURES=${CMAKE_OSX_ARCHITECTURES}
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
)

FetchContent_MakeAvailable(Sodium)
FetchContent_MakeAvailable(asio)
FetchContent_MakeAvailable(cxxopts)

# ---------------------------------------------------------
# Output directories
# ---------------------------------------------------------
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

foreach(OUTPUTCONFIG DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
    string(TOUPPER ${OUTPUTCONFIG} OUTPUTCONFIG_UPPER)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${OUTPUTCONFIG_UPPER} ${CMAKE_BINARY_DIR}/bin)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${OUTPUTCONFIG_UPPER} ${CMAKE_BINARY_DIR}/lib)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${OUTPUTCONFIG_UPPER} ${CMAKE_BINARY_DIR}/lib)
endforeach()

# ---------------------------------------------------------
# Common static library (shared code)
# ---------------------------------------------------------
file(GLOB_RECURSE COMMON_SRC CONFIGURE_DEPENDS src/common/*.cpp)
add_library(common STATIC ${COMMON_SRC})
target_link_libraries(common PUBLIC sodium cxxopts::cxxopts)

if (WIN32)
    target_link_libraries(common PUBLIC
        ws2_32
        iphlpapi
        advapi32
        mswsock
    )
endif()

target_include_directories(common PUBLIC 
    ${PROJECT_SOURCE_DIR}/include 
    ${sodium_SOURCE_DIR}/src/libsodium/include
    ${sodium_BINARY_DIR}/src/libsodium/include
    ${asio_SOURCE_DIR}/asio/include
)
target_compile_definitions(common PUBLIC ASIO_STANDALONE)

# ---------------------------------------------------------
# Client executable
# ---------------------------------------------------------
file(GLOB_RECURSE CLIENT_SRC CONFIGURE_DEPENDS src/client/*.cpp)
add_executable(client ${CLIENT_SRC})
target_link_libraries(client PRIVATE common sodium cxxopts::cxxopts)
if (WIN32)
    target_link_libraries(client PRIVATE
        dbghelp
    )
endif()
target_include_directories(client PRIVATE 
    ${PROJECT_SOURCE_DIR}/include 
    ${sodium_SOURCE_DIR}/src/libsodium/include
    ${sodium_BINARY_DIR}/src/libsodium/include
    ${asio_SOURCE_DIR}/asio/include
)
target_compile_definitions(client PRIVATE ASIO_STANDALONE)
set_target_properties(client PROPERTIES OUTPUT_NAME "columnlynx_client")

# ---------------------------------------------------------
# Server executable
# ---------------------------------------------------------
file(GLOB_RECURSE SERVER_SRC CONFIGURE_DEPENDS src/server/*.cpp)
add_executable(server ${SERVER_SRC})
target_link_libraries(server PRIVATE common sodium cxxopts::cxxopts)
if (WIN32)
    target_link_libraries(server PRIVATE
        dbghelp
    )
endif()
target_include_directories(server PRIVATE 
    ${PROJECT_SOURCE_DIR}/include 
    ${sodium_SOURCE_DIR}/src/libsodium/include
    ${sodium_BINARY_DIR}/src/libsodium/include
    ${asio_SOURCE_DIR}/asio/include
)
target_compile_definitions(server PRIVATE ASIO_STANDALONE)
set_target_properties(server PROPERTIES OUTPUT_NAME "columnlynx_server")