# (C) Copyright IBM Deutschland GmbH 2021, 2023
# (C) Copyright IBM Corp 2021, 2023
#
# non-exclusively licensed to gematik GmbH

########################################################################################################################

# fetch the dependencies' build infos via Conan
#

########################################################################################################################

# function that returns the list of third party
# libraries (dependencies) that a target needs to link against
#
find_package(OpenSSL REQUIRED)
find_package(tss REQUIRED)

function (get_libraries_to_link_against RESULT)
    set(${RESULT} tss::tss OpenSSL::SSL OpenSSL::Crypto
        PARENT_SCOPE)
endfunction()

########################################################################################################################

# function that returns the list of third party
# libraries that (only) test targets needs to link against
#
function (get_test_libraries_to_link_against RESULT)
    find_package(GTest REQUIRED)
    set(${RESULT} GTest::gtest GTest::gtest_main PARENT_SCOPE)
endfunction()

########################################################################################################################
