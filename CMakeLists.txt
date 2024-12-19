set(CMAKE_TOOLCHAIN_FILE "C:/Users/BJEDev/Downloads/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")

cmake_minimum_required(VERSION 3.15)
project(scoring_decryptor)

set(CMAKE_CXX_STANDARD 17)

# Ensure proper compiler settings
if(MINGW)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libgcc -static-libstdc++")
endif()

# Add vcpkg installed path to prefix path
set(CMAKE_PREFIX_PATH "${CMAKE_PREFIX_PATH}" "C:/Users/BJEDev/Downloads/vcpkg/installed/x64-windows")

# Find Crypto++
find_package(cryptopp CONFIG REQUIRED)
find_package(pugixml CONFIG REQUIRED)

# Add executable
add_executable(${PROJECT_NAME} main.cpp
        XMLTagMapper.cpp
        XMLTagMapper.h)

# Link Crypto++ with specific configuration for MinGW
if(MINGW)
    target_link_libraries(${PROJECT_NAME} PRIVATE
            debug ${CMAKE_PREFIX_PATH}/debug/lib/libcryptopp.dll.a
            optimized ${CMAKE_PREFIX_PATH}/lib/libcryptopp.dll.a
    )
else()
    target_link_libraries(${PROJECT_NAME} PRIVATE cryptopp::cryptopp)
    target_link_libraries(${PROJECT_NAME} PRIVATE pugixml::pugixml)
endif()