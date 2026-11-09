cmake_minimum_required(VERSION 3.18)
project(anisette_on_wine_helper LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "anisette-helper must be cross-compiled as a 64-bit Windows executable")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "anisette-helper must be built for 64-bit x86")
endif()

add_executable(anisette-helper src/main.cpp)
target_compile_features(anisette-helper PRIVATE cxx_std_17)
target_compile_definitions(anisette-helper PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(anisette-helper PRIVATE advapi32 crypt32 iphlpapi winhttp)

if(MINGW)
    target_compile_options(anisette-helper PRIVATE -Wall -Wextra -Wpedantic)
    target_link_options(anisette-helper PRIVATE -static -static-libgcc -static-libstdc++)
endif()
