# (C) Copyright IBM Deutschland GmbH 2021, 2023
# (C) Copyright IBM Corp 2021, 2023
#
# non-exclusively licensed to gematik GmbH

########################################################################################################################

# prerequisite: specify a recent CMake version
#
cmake_minimum_required(VERSION 3.16)

########################################################################################################################

# define the project name and languages
#
set(PROJECT_NAME tpm-client)

project(${PROJECT_NAME} LANGUAGES CXX)

########################################################################################################################

# prerequisite: make sure the platform is either Linux or Windows
#
if (NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")
    message(FATAL_ERROR "`${PROJECT_NAME}` builds only on Linux and Windows.")
endif()

########################################################################################################################

# set several variables with the paths of
# various locations needed by the build system
#
set(ROOT_DIRECTORY ${CMAKE_SOURCE_DIR})
set(CMAKE_DIRECTORY ${ROOT_DIRECTORY}/cmake)
set(SOURCE_DIRECTORY ${ROOT_DIRECTORY}/src)
set(TEST_DIRECTORY ${ROOT_DIRECTORY}/test)
set(BUILD_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${BUILD_DIRECTORY}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${BUILD_DIRECTORY}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BUILD_DIRECTORY}/bin)

########################################################################################################################

# include the relevant helper CMake scripts
#
include(${CMAKE_DIRECTORY}/BuildOptions.cmake)
include(${CMAKE_DIRECTORY}/Conan.cmake)
include(${CMAKE_DIRECTORY}/Dependencies.cmake)
include(${CMAKE_DIRECTORY}/Installation.cmake)
include(${CMAKE_DIRECTORY}/TargetConfiguration.cmake)

########################################################################################################################

# continue processing other CMakeLists files
#
add_subdirectory(${SOURCE_DIRECTORY})
add_subdirectory(${TEST_DIRECTORY})

########################################################################################################################
