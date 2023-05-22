# (C) Copyright IBM Deutschland GmbH 2021, 2023
# (C) Copyright IBM Corp 2021, 2023
#
# non-exclusively licensed to gematik GmbH

########################################################################################################################

# define the name of a new test target
#
set(TARGET_NAME "tpmclient-test")

# list its source files
#
set(SOURCE_FILES "ExceptionTests.cpp"
                 "ClientTests.cpp"
                 "SessionTests.cpp"
                 "UtilsTests.cpp")

# also list the targets under test (that the test target depends on)
#
set(TARGETS_UNDER_TEST "tpmclient")

########################################################################################################################

# define and configure the test target by specifying its name,
# list of targets that it tests and list of its own source files
#
configure_test_target(${TARGET_NAME} "${TARGETS_UNDER_TEST}" "${SOURCE_FILES}")

########################################################################################################################
