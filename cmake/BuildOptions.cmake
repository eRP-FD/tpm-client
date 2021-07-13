# private function that returns the compilation options specific for Linux
#
function (_private_get_linux_compile_options RESULT)
    set(${RESULT} "-fPIC"
                  "-Werror"
                  "-Wall"
                  "-Wextra"
                  "-Wpedantic"
                  "-Wundef"
                  "-Wfloat-equal"
                  "-Winit-self"
                  "-Wshadow"
                  "-Wswitch-default"
                  "$<$<CONFIG:Debug>:-g>"
                  "$<$<CONFIG:Debug>:-ggdb>"
                  "$<$<CONFIG:Debug>:-O0>"
                  "$<$<CONFIG:Release>:-O2>"
        PARENT_SCOPE)
endfunction()

########################################################################################################################

# private function that returns
# the compilation options specific for Windows
#
function (_private_get_windows_compile_options RESULT)
    set(${RESULT} "/nologo"
                  "/W4"
                  "$<$<CONFIG:Debug>:/MDd>"
                  "$<$<CONFIG:Debug>:/RTC1>"
                  "$<$<CONFIG:Debug>:/Zi>"
                  "$<$<CONFIG:Debug>:/Od>"
                  "$<$<CONFIG:Debug>:/FS>"
                  "$<$<CONFIG:Release>:/MD>"
                  "$<$<CONFIG:Release>:/O2>"
        PARENT_SCOPE)
endfunction()

########################################################################################################################

# function that returns the list of general compile features to be used when configuring a target
#
function (get_compile_features RESULT)
    set(${RESULT} "cxx_std_17" PARENT_SCOPE)
endfunction()

########################################################################################################################

# function that returns the list of defines to be injected at compile time
#
function (get_compile_definitions RESULT)
    if (HARDWARE_TPM)
        set(${RESULT} "HARDWARE_TPM" PARENT_SCOPE)
    endif()
endfunction()

########################################################################################################################

# function that returns the list of specific compilation options to be used when configuring a target
#
function (get_compile_options RESULT)
    if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
        _private_get_linux_compile_options(COMPILE_OPTIONS)
    elseif (${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
        _private_get_windows_compile_options(COMPILE_OPTIONS)
    endif()

    set(${RESULT} ${COMPILE_OPTIONS} PARENT_SCOPE)
endfunction()

########################################################################################################################

# function that returns the list of additional include directories to be provided when configuring a target
#
function (get_include_directories RESULT)
    set(${RESULT} ${SOURCE_DIRECTORY} PARENT_SCOPE)
endfunction()

########################################################################################################################

# function that returns the list of linking options to be used when configuring a target
#
function (get_link_options RESULT)
    if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
        set(${RESULT} -fPIC PARENT_SCOPE)
    endif()
endfunction()

########################################################################################################################
