cmake_minimum_required (VERSION 3.0.0)
project (Codefinder)

link_directories("libs/WindowsPlusPlus/Release")
include_directories("libs/WindowsPlusPlus/Win32++/")

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")

file(GLOB SOURCES "src/*.cpp")

add_executable(Codefinder ${SOURCES})
target_link_libraries(Codefinder Shlwapi winplusplus)
