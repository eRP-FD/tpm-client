# (C) Copyright IBM Deutschland GmbH 2021
# (C) Copyright IBM Corp. 2021
# SPDX-License-Identifier: CC BY-NC-ND 3.0 DE

########################################################################################################################

# private function that sets the install runpath of a target to $ORIGIN so that its dependencies can be found at runtime
#
function (_private_set_runpath TARGET_NAME)
    _private_check_target_exists(${TARGET_NAME})

    get_target_property(TARGET_TYPE ${TARGET_NAME} TYPE)
    if (${TARGET_TYPE} STREQUAL "SHARED_LIBRARY")
        set(RUNPATH "$ORIGIN")
    elseif (${TARGET_TYPE} STREQUAL "EXECUTABLE")
        set(RUNPATH "$ORIGIN/../lib")
    endif()

    if (RUNPATH)
        set_target_properties(${TARGET_NAME} PROPERTIES INSTALL_RPATH ${RUNPATH})
    endif()
endfunction()

########################################################################################################################

# function that given a target name (and optionally a list of its public API headers),
# it instructs the generated build system to install its artefacts (in system wide locations)
#
function (install_target TARGET_NAME PUBLIC_HEADERS)
    _private_check_target_exists(${TARGET_NAME})

    set_target_properties(${TARGET_NAME} PROPERTIES PUBLIC_HEADER "${PUBLIC_HEADERS}")
    install(TARGETS ${TARGET_NAME} PUBLIC_HEADER DESTINATION include/${TARGET_NAME})

    _private_set_runpath(${TARGET_NAME})
endfunction()

########################################################################################################################
