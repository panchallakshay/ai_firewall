cmake_minimum_required(VERSION 3.18.1)

project("shakti_bridge")

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O2")

# Find Python (for Android, we'll link against libpython)
# Python path should be provided via CMAKE_PREFIX_PATH or PYTHON_INCLUDE_DIR
find_package(Python3 COMPONENTS Development)

if(NOT Python3_FOUND)
    message(WARNING "Python 3 not found, using custom paths")
    # Fallback to custom Python path for Android
    set(PYTHON_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/python/include/python3.9")
    set(PYTHON_LIBRARY "${CMAKE_SOURCE_DIR}/python/lib/libpython3.9.so")
endif()

# Source files
set(SHAKTI_SOURCES
    shakti_packet_bridge.cpp
    shakti_jni_wrapper.cpp
    shakti_python_bridge.cpp
)

# Create shared library
add_library(shakti_bridge SHARED ${SHAKTI_SOURCES})

# Include directories
target_include_directories(shakti_bridge PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${PYTHON_INCLUDE_DIR}
)

# Link libraries
target_link_libraries(shakti_bridge
    # Android system libraries
    log        # Android logging
    android    # Android native API
    
    # Python library (if found)
    ${PYTHON_LIBRARY}
)

# Strip symbols for release builds
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_custom_command(TARGET shakti_bridge POST_BUILD
        COMMAND ${CMAKE_STRIP} --strip-unneeded $<TARGET_FILE:shakti_bridge>
    )
endif()

# Output library info
message(STATUS "Shakti Bridge Configuration:")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Python Include: ${PYTHON_INCLUDE_DIR}")
message(STATUS "  Python Library: ${PYTHON_LIBRARY}")
message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Target ABI: ${ANDROID_ABI}")
