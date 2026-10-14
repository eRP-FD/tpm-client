# (C) Copyright IBM Deutschland GmbH 2021, 2023
# (C) Copyright IBM Corp 2021, 2023
#
# non-exclusively licensed to gematik GmbH

########################################################################################################################

# function that calls the Conan setup routines
# initializing all third party dependencies variables
#
macro(conan_setup)

    set(CONAN_BUILD_INFO_SCRIPT ${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
    if (NOT EXISTS ${CONAN_BUILD_INFO_SCRIPT})
        find_program(CONAN conan)
        if (NOT CONAN)
            message(FATAL_ERROR "Cannot find conan. Is it installed?")
        endif()
        if (BUILD_TESTS)
            set(OPTIONS -o with_tests=True)
        endif()

        execute_process(COMMAND ${CONAN} install .
                                         ${OPTIONS}
                                         --build=missing
                                         --install-folder=${BUILD_DIRECTORY}
                                         --output-folder=${BUILD_DIRECTORY}
                        WORKING_DIRECTORY ${ROOT_DIRECTORY}
                        RESULT_VARIABLE RESULT)

        if (NOT RESULT STREQUAL "0")
            message(FATAL_ERROR "Unable to fetch dependencies: `conan install` failed. See errors above.")
        endif()
    endif()

    include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
    conan_basic_setup(TARGETS)
endmacro()

########################################################################################################################
