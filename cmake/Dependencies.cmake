# fetch the dependencies' build infos via Conan
#
conan_setup()

########################################################################################################################

# function that returns the list of third party
# libraries (dependencies) that a target needs to link against
#
function (get_libraries_to_link_against RESULT)
    set(${RESULT} CONAN_PKG::tss
                  CONAN_PKG::openssl
        PARENT_SCOPE)
endfunction()

########################################################################################################################

# function that returns the list of third party
# libraries that (only) test targets needs to link against
#
function (get_test_libraries_to_link_against RESULT)
    set(${RESULT} CONAN_PKG::gtest PARENT_SCOPE)
endfunction()

########################################################################################################################
