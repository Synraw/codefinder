cmake_minimum_required (VERSION 3.0.0)
project (Codefinder)

# Setup the WPP Library
link_directories("libs/WindowsPlusPlus/Release")
include_directories("libs/WindowsPlusPlus/Win32++/")

# Change the CRT link type to match the WPP libs
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")

# Output our binaries to the /bin folder
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")

# Multibyte characters pls
add_definitions(-D_MBCS -DMBCS )

# Build!
file(GLOB SOURCES "src/*.cpp")
add_executable(Codefinder ${SOURCES} "src/resource.rc")
target_link_libraries(Codefinder Shlwapi winplusplus)
